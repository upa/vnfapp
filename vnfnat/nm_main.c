#include <stdio.h>
#include <unistd.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <syslog.h>
#include <stdarg.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "nm_main.h"
#include "nm_nat.h"
#include "nm_session.h"

struct mapping **inner_table;
struct mapping **outer_table;
struct mapping *mapping_table;
pthread_mutex_t mapping_mutex;
int syslog_facility = SYSLOG_FACILITY;

static void syslog_open();
static void syslog_close();

void nm_receive(struct vnfapp *va)
{
	unsigned int budget, rx_cur, tx_cur;
	struct netmap_slot *rx_slot, *tx_slot;
	void *src_buf, *dst_buf, *buf_ip;
	struct ether_header *eth;
	int len_ip, ret;

	rx_cur = va->rx_ring->cur;
	tx_cur = va->tx_ring->cur;
	budget = min(BUDGET_MAX, min(nm_ring_space(va->rx_ring), nm_ring_space (va->tx_ring)));

	while(budget--){
		rx_slot = &va->rx_ring->slot[rx_cur];
		tx_slot = &va->tx_ring->slot[tx_cur];

		if(tx_slot->buf_idx < 2 || rx_slot->buf_idx < 2){
			printf("wrong index rx[%d] = %d -> tx[%d] = %d\n",
				rx_cur, rx_slot->buf_idx, tx_cur, tx_slot->buf_idx);
		}

		src_buf = NETMAP_BUF(va->rx_ring, rx_slot->buf_idx);
		dst_buf = NETMAP_BUF(va->tx_ring, tx_slot->buf_idx);
		nm_pkt_copy(src_buf, dst_buf, rx_slot->len);
		eth = (struct ether_header *)dst_buf;
		if(eth->ether_type != htons(ETHERTYPE_IP))
			goto packet_drop;

		/* NAT related process */
		buf_ip = (struct ip *)(dst_buf + sizeof(struct ether_header));
		len_ip = rx_slot->len - sizeof(struct ether_header);
		
		switch(va->direction){
		case NM_THREAD_R2L:
			ret = process_right_to_left(buf_ip, len_ip);
			break;
		case NM_THREAD_L2R:
			ret = process_left_to_right(buf_ip, len_ip);
			break;
		default:
			break;
		}

		/* maybe NATed session is not found */
		if(ret)
			goto packet_drop;

		/* swap the buffers */
		/*
		temp_idx = tx_slot->buf_idx;
		tx_slot->buf_idx = rx_slot->buf_idx;
		rx_slot->buf_idx = temp_idx;
		*/

		/* update length */
		tx_slot->len = rx_slot->len;
		//rx_slot->len = 0;

		/* update flags */
		tx_slot->flags |= NS_BUF_CHANGED;
		//rx_slot->flags |= NS_BUF_CHANGED;

packet_drop:
		rx_cur = nm_ring_next(va->rx_ring, rx_cur);
		tx_cur = nm_ring_next(va->tx_ring, tx_cur);
	}

	/* tell the kernel to update addresses in the NIC rings */
	va->rx_ring->head = va->rx_ring->cur = rx_cur;
	va->tx_ring->head = va->tx_ring->cur = tx_cur;
}

void *process_netmap(void * param)
{
	struct vnfapp *va = (struct vnfapp *)param;
	struct pollfd x[1];

	x[0].fd = va->rx_fd;
	x[0].events = POLLIN;

	while(1){
		poll(x, 1, -1);
		nm_receive(va);
		ioctl (va->tx_fd, NIOCTXSYNC, va->tx_q);
		//ioctl (va->rx_fd, NIOCRXSYNC, va->rx_q);
	}

	printf("rxfd=%d, txfd=%d, rxq=%d, txq=%d, rxif=%s, txif=%s\n",
	   va->rx_fd, va->tx_fd, va->rx_q, va->tx_q, va->rx_if, va->tx_if);

	return NULL;
}

int
nm_get_ring_num (char * ifname, int direct)
{
	int fd;
	struct nmreq nmr;

	fd = open ("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D ("Unable to open /dev/netmap");
		perror ("open");
		return -1;
	}

	memset (&nmr, 0, sizeof (nmr));
	nmr.nr_version = NETMAP_API;
	strncpy (nmr.nr_name, ifname, IFNAMSIZ - 1);
	if (ioctl (fd, NIOCGINFO, &nmr)) {
		printf("unable to get interface info for %s\n", ifname);
		return -1;
	}

	close (fd);

	if (direct == NM_DIR_TX) 
		return nmr.nr_tx_rings;

	if (direct == NM_DIR_RX)
		return nmr.nr_rx_rings;

	return -1;
}

int
nm_ring (char * ifname, int q, struct netmap_ring ** ring,  int x, int w)
{
	int fd;
	char * mem;
	struct nmreq nmr;
	struct netmap_if * nifp;

	/* open netmap for  ring */

	fd = open ("/dev/netmap", O_RDWR);
	if (fd < 0) {
		printf("unable to open /dev/netmap\n");
		return -1;
	}

	memset (&nmr, 0, sizeof (nmr));
	strcpy (nmr.nr_name, ifname);
	nmr.nr_version = NETMAP_API;
	nmr.nr_ringid = q | (NETMAP_NO_TX_POLL | NETMAP_DO_RX_POLL);

	if (w)
		nmr.nr_flags |= NR_REG_ONE_NIC;
	else
		nmr.nr_flags |= NR_REG_ALL_NIC;

	if (ioctl (fd, NIOCREGIF, &nmr) < 0) {
		printf("unable to register interface %s\n", ifname);
		return -1;
	}

	mem = mmap (NULL, nmr.nr_memsize,
		    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		printf("unable to mmap\n");
		return -1;
	}

	nifp = NETMAP_IF (mem, nmr.nr_offset);

	if (x > 0)
		*ring = NETMAP_TXRING (nifp, q);
	else
		*ring = NETMAP_RXRING (nifp, q);

	return fd;
}
#define nm_hw_tx_ring(i, q, r) nm_ring (i, q, r, 1, NETMAP_HW_RING)
#define nm_hw_rx_ring(i, q, r) nm_ring (i, q, r, 0, NETMAP_HW_RING)
#define nm_sw_tx_ring(i, q, r) nm_ring (i, q, r, 1, NETMAP_SW_RING)
#define nm_sw_rx_ring(i, q, r) nm_ring (i, q, r, 0, NETMAP_SW_RING)
#define nm_vl_tx_ring(i, q, r) nm_ring (i, q, r, 1, 0)
#define nm_vl_rx_ring(i, q, r) nm_ring (i, q, r, 0, 0)

void
usage (void) {
	printf ("-l [LEFT] -r [RIGHT] -q [CPUNUM]\n");

	return;
}



int
main (int argc, char ** argv)
{
	int q, rq, lq, n, ch;
	char *rif, *lif;	/* right/left interfaces */

	q = 256;	/* all CPUs */
	rif = lif = NULL;

	while ((ch = getopt (argc, argv, "r:l:q:")) != -1) {
		switch (ch) {
		case 'r' :
			rif = optarg;
			break;
		case 'l' :
			lif = optarg;
			break;
		case 'q' :
			q = atoi (optarg);
			break;
		default :
			usage ();
			return -1;
		}
	}
	
	if (rif == NULL || lif == NULL) {
		usage ();
		return -1;
	}

	mapping_table = init_mapping_table();
	pthread_mutex_init(&mapping_mutex, NULL);

	rq = nm_get_ring_num (rif, NM_DIR_RX);
	lq = nm_get_ring_num (lif, NM_DIR_RX);

	if (rq < 0 || lq < 0) {
		printf("failed to get ring number");
		return -1;
	}
	printf("rq=%d, lq=%d\n", rq, lq);

	/* asign processing threads */

	rq = (rq < q) ? rq : q;
	lq = (lq < q) ? lq : q;
	
	/* start threads from right to left */
	for (n = 0; n < rq; n++) {
		struct vnfapp *va = (struct vnfapp *)malloc(sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		va->rx_q = n;
		va->tx_q = n % lq;
		va->rx_if = rif;
		va->tx_if = lif;
		va->rx_fd = nm_vl_rx_ring (rif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (lif, va->tx_q, &va->tx_ring);
		va->direction = NM_THREAD_R2L;

		pthread_create (&va->tid, NULL, process_netmap, va);
	}

	/* start threads from left to right */
	for (n = 0; n < lq; n++) {
		struct vnfapp *va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		va->rx_q = n;
		va->tx_q = n % rq;
		va->rx_if = lif;
		va->tx_if = rif;
		va->rx_fd = nm_vl_rx_ring (lif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (rif, va->tx_q, &va->tx_ring);
		va->direction = NM_THREAD_L2R;

		pthread_create (&va->tid, NULL, process_netmap, va);
	}

	while(1){
		sleep(SESSION_CHECK_INTERVAL);

		pthread_mutex_lock(&mapping_mutex);
		count_down_ttl();
		pthread_mutex_unlock(&mapping_mutex);
	}
	
	return 0;
}

void syslog_write(int level, char *fmt, ...){
        va_list args;
        va_start(args, fmt);

        syslog_open();
        vsyslog(level, fmt, args);
        syslog_close();

        va_end(args);
}

static void syslog_open(){
	openlog(PROCESS_NAME, LOG_CONS | LOG_PID, syslog_facility);
}

static void syslog_close(){
	closelog();
}
