#include <stdio.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <ctype.h>      // isprint()
#include <unistd.h>     // sysconf()
#include <sys/poll.h>
#include <arpa/inet.h>  /* ntohs */
#include <sys/sysctl.h> /* sysctl */
#include <ifaddrs.h>    /* getifaddrs */
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>

struct vnfapp {
	pthread_t tid;

	int rx_fd, tx_fd;
	int rx_q, tx_q;
	char *rx_if, *tx_if;
	struct netmap_ring *rx_ring, *tx_ring;
	unsigned int direction;

	void *data;
};

void nm_receive(struct vnfapp *va)
{
	unsigned int budget, rx_cur, tx_cur;
	struct netmap_slot *rx_slot, *tx_slot;
	uint32_t temp_idx;

	rx_cur = va->rx_ring->cur;
	tx_cur = va->tx_ring->cur;
	budget = min(BUDGET_MAX, min(nm_ring_space(va->rx_ring), nm_ring_space (va->tx_ring)));

	while(budget--){
		rx_slot = &va->rx_ring->slot[rx_cur];
		tx_slot = &va->tx_ring->slot[tx_cur];

		if(tx_slot->buf_idx < 2 || rx_slot->buf_idx < 2){
			printf("wrong index rx[%d] = %d -> tx[%d] = %d",
				rx_cur, rx_slot->buf_idx, tx_cur, tx_slot->buf_idx);
		}

		/* NAT related process */
		switch(va->direction){
		case NETMAP_NAT_G2P:

		case NETMAP_NAT_P2G:

		default:
		}

		/* swap the buffers */
		tmp_idx = tx_slot->buf_idx;
		tx_slot->buf_idx = rx_slot->buf_idx;
		rx_slot->buf_idx = tmp_idx;

		/* update length */
		tx_slot->len = rx_slot->len;
		rx_slot->len = 0;

		/* update flags */
		tx_slot->flags = NS_BUF_CHANGED;
		rx_slot->flags = NS_BUF_CHANGED;

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
	}

	printf("rxfd=%d, txfd=%d, rxq=%d, txq=%d, rxif=%s, txif=%s",
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
		D ("unable to get interface info for %s", ifname);
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
		D ("unable to open /dev/netmap");
		return -1;
	}

	memset (&nmr, 0, sizeof (nmr));
	strcpy (nmr.nr_name, ifname);
	nmr.nr_version = NETMAP_API;
	nmr.nr_ringid = (q | w);
	nmr.nr_flags |= NR_REG_ALL_NIC;

	if (ioctl (fd, NIOCREGIF, &nmr) < 0) {
		D ("unable to register interface %s", ifname);
		return -1;
	}

	mem = mmap (NULL, nmr.nr_memsize,
		    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		D ("unable to mmap");
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
	char * rif, * lif;	/* right/left interfaces */
	struct vnfapp *va[2];

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

	rq = nm_get_ring_num (rif, NM_DIR_RX);
	lq = nm_get_ring_num (lif, NM_DIR_RX);

	if (rq < 0 || lq < 0) {
		D ("failed to get ring number");
		return -1;
	}
	printf("rq=%d, lq=%d", rq, lq);

	/* asign processing threads */

	rq = (rq < q) ? rq : q;
	lq = (lq < q) ? lq : q;
	
	/* start threads from right to left */
	for (n = 0; n < rq; n++) {
		struct vnfapp *va = vas[0];
		va = (struct vnfapp *)malloc(sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		va->rx_q = rq;
		va->tx_q = n % lq;
		va->rx_if = rif;
		va->tx_if = lif;
		va->rx_fd = nm_vl_rx_ring (rif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (lif, va->tx_q, &va->tx_ring);
		va->direction = NETMAP_NAT_G2P;

		pthread_create (&va->tid, NULL, process_netmap, va);
	}

	/* start threads from left to right */
	for (n = 0; n < lq; n++) {
		struct vnfapp *va = vas[1];
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		va->rx_q = lq;
		va->tx_q = n % rq;
		va->rx_if = lif;
		va->tx_if = rif;
		va->rx_fd = nm_vl_rx_ring (lif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (rif, va->tx_q, &va->tx_ring);
		va->direction = NETMAP_NAT_P2G;

		pthread_create (&va->tid, NULL, process_netmap, va);
	}

	pthread_join(vas[0]->tid, NULL);
	pthread_join(vas[1]->tid, NULL);
	
	return 0;
}



