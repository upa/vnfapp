
/* Application VNF L3 Border (not router) */


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
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>

#include "list.h"


struct arppkt {
	struct arphdr hdr;

	u_int8_t smac[ETH_ALEN];
	struct in_addr saddr;
	u_int8_t dmac[ETH_ALEN];
	struct in_addr daddr;
} __attribute__ ((__packed__));




#define NM_DIR_TX	0
#define NM_DIR_RX	1

#define POLL_TIMEOUT	10
#define BURST_MAX	1024


#define MACCMP(a, b) \
	(a[0] != b[0]) ? 0 : (a[1] != b[1]) ? 0 : (a[2] != b[2]) ? 0 : \
	(a[3] != b[3]) ? 0 : (a[4] != b[4]) ? 0 : (a[5] != b[5]) ? 0 : 1

#define MACCOPY(s, d)					\
	do {						\
		d[0] = s[0]; d[1] = s[1]; d[2] = s[2];	\
		d[3] = s[3]; d[4] = s[4]; d[5] = s[5];	\
	} while (0)

#define BMAC(m)						\
	do {						\
		m[0] = 0xFF; m[1] = 0xFF; m[2] = 0xFF;	\
		m[3] = 0xFF; m[4] = 0xFF; m[5] = 0xFF;	\
	} while (0)


#define ADDRCMP(a, b) (*((u_int32_t *)(a)) == *((u_int32_t *)(b)))

#define ADDRCOPY(s, d) (*((u_int32_t *)(s)) = *((u_int32_t *)(d)))


int verbose = 0;

struct list_head arplist;
struct netmap_ring * ltxring, * rtxring; /* ringid 0 */
int ltx_fd, rtx_fd;

struct vnfapp {
	pthread_t tid;

	int rx_fd, tx_fd;
	int rx_q, tx_q;
	char * rx_if, * tx_if;
	struct netmap_ring * rx_ring, * tx_ring;

	void * data;
};

/* arp entrty. It is contained in struct list_head arplist */
struct arp {
	struct list_head list;	/* private */

	u_int8_t mac[ETH_ALEN];
	struct in_addr addr;
};


struct vnfl3 {

	int dir;			/* left -> right or reverse */

	u_int8_t rmac[ETH_ALEN];	/* mac addr of Right Port */
	u_int8_t lmac[ETH_ALEN];	/* mac addr of Left Port */

	struct in_addr raddr;		/* ip addr of Right Port */
	struct in_addr laddr;		/* ip addr of Left Port */
	
	u_int8_t rdmac[ETH_ALEN];
	u_int8_t ldmac[ETH_ALEN];
};

#define SET_R2L(v) ((v)->dir = 0)
#define SET_L2R(v) ((v)->dir = 1)
#define IS_R2L(v) ((v)->dir == 0)
#define IS_L2R(v) ((v)->dir == 1)

#define INMAC(v) (((v)->dir == 0) ? (v)->rmac : (v)->lmac)
#define INADDR(v) (((v)->dir == 0) ? &((v)->raddr) : &((v)->laddr))

#define OUTDSTMAC(v) (((v)->dir == 1) ? (v)->rdmac : (v)->ldmac)
#define OUTSRCMAC(v) (((v)->dir == 1) ? (v)->rmac : (v)->lmac)

#define OUTSRCADDR(v) (((v)->dir == 1) ? (v)->raddr : (v)->laddr)



inline struct arp *
find_arp_by_ip (struct list_head * arplist, struct in_addr addr)
{
	struct arp * arp;

	list_for_each_entry (arp, arplist, list) {
		if (ADDRCMP (&arp->addr, &addr)) {
			return arp;
		}
	}

	return NULL;
}

inline struct arp * 
add_arp (struct list_head * arplist, struct in_addr addr, u_int8_t * mac)
{
	struct arp * arp;

	arp = (struct arp *) malloc (sizeof (struct arp));
	memset (arp, 0, sizeof (struct arp));

	MACCOPY (mac, arp->mac);
	arp->addr = addr;

	return arp;
}

void
send_arp_req (struct netmap_ring * txring,
	      struct in_addr saddr, u_int8_t * smac,
	      struct in_addr daddr)
{
	char pkt[64];
	struct ether_header * eth;
	struct arppkt * arp;

	/* building arp request packet */
	memset (pkt, 0, sizeof (pkt));
	
	eth = (struct ether_header *) pkt;
	BMAC (eth->ether_dhost);
	MACCOPY (smac, eth->ether_shost);
	eth->ether_type = htons (ETHERTYPE_ARP);

	arp = (struct arppkt *) (eth + 1);
	arp->hdr.ar_hrd = htons (ARPHRD_ETHER);
	arp->hdr.ar_pro = htons (0x0800);
	arp->hdr.ar_hln = 6;
	arp->hdr.ar_pln = 4;
	arp->hdr.ar_op = htons (ARPOP_REQUEST);

	MACCOPY (smac, arp->smac);
	arp->saddr = saddr;
	arp->daddr = daddr;

	/* send arp req */
	u_int idx;
	struct netmap_slot * slot;

	idx = txring->cur;
	slot = &txring->slot[idx];
	
	memcpy (NETMAP_BUF (txring, slot->buf_idx), pkt, 
		sizeof (struct ether_header) + sizeof (struct arppkt));
	slot->len = sizeof (struct ether_header) + sizeof (struct arppkt);

	return;
}

void
send_arp_rep (struct netmap_ring * txring,
	      struct in_addr saddr, u_int8_t * smac,
	      struct in_addr daddr, u_int8_t * dmac)
{

	char pkt[128];
	struct ether_header * eth;
	struct arppkt * arp;

	/* building arp request packet */
	memset (pkt, 0, sizeof (pkt));
	
	eth = (struct ether_header *) pkt;
	MACCOPY (smac, eth->ether_shost);
	MACCOPY (dmac, eth->ether_dhost);
	eth->ether_type = htons (ETHERTYPE_ARP);

	arp = (struct arppkt *) (eth + 1);
	arp->hdr.ar_hrd = htons (ARPHRD_ETHER);
	arp->hdr.ar_pro = htons (0x0800);
	arp->hdr.ar_hln = 6;
	arp->hdr.ar_pln = 4;
	arp->hdr.ar_op = htons (ARPOP_REPLY);

	MACCOPY (smac, arp->smac);
	MACCOPY (dmac, arp->dmac);
	arp->saddr = saddr;
	arp->daddr = daddr;


	D ("arp saddr %s", inet_ntoa (arp->saddr));
	D ("arp daddr %s", inet_ntoa (arp->daddr));
	D ("arp shost %02x:%02x:%02x:%02x:%02x:%02x",
	   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], 
	   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	D ("arp dhost %02x:%02x:%02x:%02x:%02x:%02x",
	   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], 
	   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

	/* send arp rep */
	u_int idx;
	struct netmap_slot * slot;

	idx = txring->cur;
	slot = &txring->slot[idx];
	
	char * p = NETMAP_BUF (txring, slot->buf_idx);
	memcpy (p, pkt, 
		sizeof (struct ether_header) + sizeof (struct arppkt));
	slot->len = sizeof (struct ether_header) + sizeof (struct arppkt);
	
	ioctl (ltx_fd, NIOCTXSYNC, 0);
	ioctl (rtx_fd, NIOCTXSYNC, 0);

	return;
}

inline int
process_arp (struct vnfl3 * v,
	     struct netmap_ring * txring, struct ether_header * eth)
{
	struct arppkt * arp;

	D ("process arp");

	arp = (struct arppkt *) (eth + 1);

	if (arp->hdr.ar_op == htons (ARPOP_REQUEST)) {

		if (ADDRCMP (INADDR(v), &arp->daddr)) {
			send_arp_rep (txring,
				      *INADDR(v), INMAC(v),
				      arp->saddr, arp->smac);
			return 1;
		}

	} else if (arp->hdr.ar_op == htons (ARPOP_REPLY)) {

		if (find_arp_by_ip (&arplist, arp->saddr) == NULL)
			add_arp (&arplist, arp->saddr, arp->smac);

		return 1;
	}

	return 0;
}

u_int
move (struct vnfapp * va)
{
	int arp_done = 0;
	u_int burst, m, idx, j, k;
	struct ether_header * eth;
	struct netmap_slot * rx_slot, * tx_slot;
	struct vnfl3 * v = va->data;
	struct arp * arp;
	struct ip * ip;
	struct netmap_ring * arp_txring;

	if (IS_L2R(v)) {
		arp_txring = ltxring;
	} else {
		arp_txring = rtxring;
	}

	j = va->rx_ring->cur;
	k = va->tx_ring->cur;

	burst = BURST_MAX;

	m = nm_ring_space (va->rx_ring);
	if (m < BURST_MAX)
		burst = m;

	m = nm_ring_space (va->tx_ring);
	if (m < burst)
		burst = m;

	m = burst;

	while (burst-- > 0) {
		/* netmap zero copy switching */

		rx_slot = &va->rx_ring->slot[j];
		tx_slot = &va->tx_ring->slot[k];

                if (tx_slot->buf_idx < 2 || rx_slot->buf_idx < 2) {
                        D("wrong index rx[%d] = %d  -> tx[%d] = %d",
			  j, rx_slot->buf_idx, k, tx_slot->buf_idx);
                        sleep(2);
                }
		
		eth = (struct ether_header *)
			NETMAP_BUF (va->rx_ring, rx_slot->buf_idx);

		if (eth->ether_type == htons (ETHERTYPE_ARP)) {
			if (process_arp (v, arp_txring, eth)) {
				goto next_burst;
			}
		}

		/* change mac address for L3 Boundry */
		if (IS_R2L (v)) {
			/* to normal network. resolve arp */
			if (eth->ether_type == htons (ETHERTYPE_IP)) {
				ip = (struct ip *) (eth + 1);
				arp = find_arp_by_ip (&arplist, ip->ip_dst);
				if (arp == NULL && arp_done == 0) {
					send_arp_req (va->tx_ring,
						      OUTSRCADDR(v),
						      OUTSRCMAC(v),
						      ip->ip_dst);
					arp_done = 1;
					goto next_burst;
				}
				MACCOPY (OUTSRCMAC(v), eth->ether_shost);
				MACCOPY (arp->mac, eth->ether_dhost);
			}
		} else {
			/* to nfv chain (mac is no cair )*/
			MACCOPY (OUTDSTMAC(v), eth->ether_dhost);
			MACCOPY (OUTSRCMAC(v), eth->ether_shost);
		}

		/* swap slot */
		idx = tx_slot->buf_idx;
		tx_slot->buf_idx = rx_slot->buf_idx;
		rx_slot->buf_idx = idx;
		tx_slot->flags |= NS_BUF_CHANGED;
		rx_slot->flags |= NS_BUF_CHANGED;
		tx_slot->len = rx_slot->len;

	next_burst:
		j = nm_ring_next (va->rx_ring, j);
		k = nm_ring_next (va->tx_ring, k);
	}

	va->rx_ring->head = va->rx_ring->cur = j;
	va->tx_ring->head = va->tx_ring->cur = k;
	
	if (verbose)
		D ("rx queue %d send %u packets", va->rx_q, m);

	return m;
}

void
processing_hub (struct vnfapp * va)
{
	struct pollfd x[1];

	x[0].fd = va->rx_fd;
	x[0].events = POLLIN;

	while (1) {
		if (poll (x, 1, -1) == 0) {
			D ("poll timeout");
			continue;
		}

		move (va);
		ioctl (va->tx_fd, NIOCTXSYNC, va->tx_q);
	}

	return;
}

void * 
processing_thread (void * param)
{
	struct vnfapp * va = (struct vnfapp *) param;

	D ("rxfd=%d, txfd=%d, rxq=%d, txq=%d, rxif=%s, txif=%s, "
	   "rxring=%p, txring=%p",
	   va->rx_fd, va->tx_fd, va->rx_q, va->tx_q, va->rx_if, va->tx_if,
	   va->rx_ring, va->tx_ring);

	pthread_detach (pthread_self ());

	processing_hub (va);

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
	nmr.nr_ringid = q | (NETMAP_NO_TX_POLL | NETMAP_DO_RX_POLL);

	if (w) 
		nmr.nr_flags |= NR_REG_ONE_NIC;
	else 
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

	printf ("-l [LEFT] -r [RIGHT] -q [CPUNUM] (-v)\n"
		"-a [LMAC] -A [RMAC] -b [LADDR] -B [RADDR]\n"
		"\n"
		"LEFT interface is connected to Normal network.\n"
		"RIGHT interface is connected to NFV network\n"
		"It means, when packet is transmitted to LEFT, "
		"ARP will be resolved\n\n");

	return;
}



int
main (int argc, char ** argv)
{
	int q, rq, lq, n, ch, mac[ETH_ALEN];
	char * rif, * lif;	/* right/left interfaces */

	q = 256;	/* all CPUs */
	rif = lif = NULL;

	struct vnfl3 v3;
	memset (&v3, 0, sizeof (v3));

 	while ((ch = getopt (argc, argv, "r:l:q:va:A:b:B:")) != -1) {
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
		case 'v' :
			verbose = 1;
			break;
		case 'a' :
			sscanf (optarg, "%02x:%02x:%02x:%02x:%02x:%02x", 
				&mac[0], &mac[1], &mac[2],
				&mac[3], &mac[4], &mac[5]);
			MACCOPY (mac, v3.lmac);
			break;
		case 'A' :
			sscanf (optarg, "%02x:%02x:%02x:%02x:%02x:%02x", 
				&mac[0], &mac[1], &mac[2],
				&mac[3], &mac[4], &mac[5]);
			MACCOPY (mac, v3.rmac);
			break;
		case 'b' :
			inet_pton (AF_INET, optarg, &v3.laddr);
			break;
		case 'B' :
			inet_pton (AF_INET, optarg, &v3.raddr);
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
	D ("rq=%d, lq=%d", rq, lq);

	D ("Left Interface %02d:%02d:%02d:%02d:%02d:%02d and %s", 
	   v3.lmac[0], v3.lmac[1], v3.lmac[3],
	   v3.lmac[3], v3.lmac[4], v3.lmac[5], inet_ntoa (v3.laddr));

	D ("Right Interface %02d:%02d:%02d:%02d:%02d:%02d and %s", 
	   v3.rmac[0], v3.rmac[1], v3.rmac[3],
	   v3.rmac[3], v3.rmac[4], v3.rmac[5], inet_ntoa (v3.raddr));

	/* asign processing threads */

	rq = (rq < q) ? rq : q;
	lq = (lq < q) ? lq : q;
	
	/* start threads from right to left */
	for (n = 0; n < rq; n++) {
		struct vnfapp * va;
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		struct vnfl3 * v;
		v = (struct vnfl3 *) malloc (sizeof (struct vnfl3));
		memcpy (v, &v3, sizeof (struct vnfl3));

		SET_R2L (v);

		va->data = v;
		va->rx_q = n;
		va->tx_q = n % lq;
		va->rx_if = rif;
		va->tx_if = lif;
		va->rx_fd = nm_vl_rx_ring (rif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (lif, va->tx_q, &va->tx_ring);

		if (n == 0) {
			ltxring = va->tx_ring;
			ltx_fd = va->tx_fd;
		}

		pthread_create (&va->tid, NULL, processing_thread, va);
	}

	/* start threads from left to right */
	for (n = 0; n < lq; n++) {
		struct vnfapp * va;
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		struct vnfl3 * v;
		v = (struct vnfl3 *) malloc (sizeof (struct vnfl3));
		memcpy (v, &v3, sizeof (struct vnfl3));

		SET_L2R (v);

		va->data = v;
		va->rx_q = n;
		va->tx_q = n % rq;
		va->rx_if = lif;
		va->tx_if = rif;
		va->rx_fd = nm_vl_rx_ring (lif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (rif, va->tx_q, &va->tx_ring);

		if (n == 0) {
			rtxring = va->tx_ring;
			rtx_fd = va->tx_fd;
		}

		pthread_create (&va->tid, NULL, processing_thread, va);
	}


	while (1)
		sleep (100);

	
	return 0;
}



