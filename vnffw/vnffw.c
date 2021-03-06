
/* Application VNF Access Controll */


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
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "patricia.h"

#define ACLPORT_MAX	16

#define NM_DIR_TX	0
#define NM_DIR_RX	1

#define POLL_TIMEOUT	10
#define BURST_MAX	1024

int vale_rings = 0;
int verbose;
patricia_tree_t * udp_tree;
patricia_tree_t * tcp_tree;

struct vnfin {
        int dir;
        u_int8_t lmac[ETH_ALEN];
        u_int8_t rmac[ETH_ALEN];
};


#define SET_R2L(v) ((v)->dir = 0)
#define SET_L2R(v) ((v)->dir = 1)
#define IS_R2L(v) ((v)->dir == 0)
#define IS_L2R(v) ((v)->dir == 1)

#define INMAC(v) (((v)->dir == 0) ? (v)->rmac : (v)->lmac)

#define OUTDSTMAC(v) (((v)->dir == 1) ? (v)->rmac : (v)->lmac)


#define MACCOPY(s, d)                                   \
        do {                                            \
		d[0] = s[0]; d[1] = s[1]; d[2] = s[2];  \
		d[3] = s[3]; d[4] = s[4]; d[5] = s[5];  \
        } while (0)


#define ADDR4COPY(s, d) *(((u_int32_t *)(d))) = *(((u_int32_t *)(s)))
#define ADDRCMP(s, d) (*(((u_int32_t *)(d))) == *(((u_int32_t *)(s))))



struct vnfapp {
	pthread_t tid;

	int rx_fd, tx_fd;
	int rx_q, tx_q;
	char * rx_if, * tx_if;
	struct netmap_ring * rx_ring, * tx_ring;

	void * data;
};


struct aclentry {
	int port[ACLPORT_MAX];
	int num;

	patricia_tree_t * dtree;
};


int
split_prefixlenport (char * str, int * proto,
		     void * sprefix, int * slen, int * sport,
		     void * dprefix, int * dlen, int * dport)
{
	int len, n, c = 0;
	char * p, * args[7];

	/* PROTO_PREFIX/LEN:PORT-PREFIX/LEN:PORT*/
	
	p = str;
	args[c++] = str;
	len = strlen (str);
	for (n = 0; n < len; n++) {
		if (*(p + n) == '_' || *(p + n) == '/' ||
		    *(p + n) == ':' || *(p + n) == '-') {
			*(p + n) = '\0';
			args[c++] = (p + n + 1);
		}
	}

	*slen = atoi (args[2]);
	*dlen = atoi (args[5]);
	*sport = atoi (args[3]);
	*dport = atoi (args[6]);

	inet_pton (AF_INET, args[1], sprefix);
	inet_pton (AF_INET, args[4], dprefix);
	
	if (!strncmp (args[0], "tcp", 3)) {
		*proto = IPPROTO_TCP;
	} else if (!strncmp (args[0], "udp", 3)) {
		*proto = IPPROTO_UDP;
	}

	return 1;
}



static inline void
dst2prefix (void * addr, u_int16_t len, prefix_t * prefix)
{
        prefix->family = AF_INET;
        prefix->bitlen = len;
        prefix->ref_count = 1;

	ADDR4COPY (addr, &prefix->add);

        return;
}

static inline void *
find_patricia_entry (patricia_tree_t * tree, void * addr, u_int16_t len)
{
	prefix_t prefix;
	patricia_node_t * pn;

	dst2prefix (addr, len, &prefix);

	pn = patricia_search_best (tree, &prefix);

	if (pn)
		return pn->data;

	return NULL;
}

static inline void
add_patricia_entry (patricia_tree_t * tree, void * addr, u_int16_t len,
		    void * data)
{
	prefix_t * prefix;
	patricia_node_t * pn;

	prefix = (prefix_t *) malloc (sizeof (prefix_t));

	dst2prefix (addr, len, prefix);

	pn = patricia_lookup (tree, prefix);
	
	pn->data = data;

	return;
}




u_int
move (struct vnfapp * va)
{
	int n;
	u_int burst, m, j, k;
	struct vnfin * v = va->data;
	struct netmap_slot * rx_slot, * tx_slot;
	struct ether_header * eth;
	struct ip * ip;
	struct aclentry * acl;
	struct udphdr * udp;
	struct tcphdr * tcp;
	patricia_tree_t * stree, * dtree;
	u_int16_t dp, sp;

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

		stree = NULL;
		dtree = NULL;

		rx_slot = &va->rx_ring->slot[j];
		tx_slot = &va->tx_ring->slot[k];

                if (tx_slot->buf_idx < 2 || rx_slot->buf_idx < 2) {
                        D("wrong index rx[%d] = %d  -> tx[%d] = %d",
			  j, rx_slot->buf_idx, k, tx_slot->buf_idx);
                        sleep(2);
                }

		eth = (struct ether_header *)
			NETMAP_BUF (va->rx_ring, rx_slot->buf_idx);
		ip = (struct ip *) (eth + 1);

		/* drop acl check */
		if (ip->ip_p == IPPROTO_UDP) {
			stree = udp_tree;
			udp = (struct udphdr *) (ip + 1);
			sp = udp->source;
			dp = udp->dest;
		} else if (ip->ip_p == IPPROTO_TCP) {
			stree = tcp_tree;
			tcp = (struct tcphdr *) (ip + 1);
			sp = tcp->source;
			dp = tcp->dest;
		}

		/* source prefix and port check */
		acl = find_patricia_entry (stree, &ip->ip_src, 32);
		if (acl) {
			for (n = 0; n < acl->num; n++) {
				if (acl->port[n] == sp ||
				    acl->port[n] == 0) {
					dtree = acl->dtree;
					break;
				}
			}
		}

		/* destination prefix and port check */
		if (dtree) {
			acl = find_patricia_entry (dtree, &ip->ip_dst, 32);
			if (acl) {
				for (n = 0; n < acl->num; n++) {
					if (acl->port[n] == dp ||
					    acl->port[n] == 0) {
						goto drop;
					}
				}
			}
		}

		
		/* change destination mac */
#ifdef ZEROCPY
		u_int idx;
		eth = (struct ether_header *)
			NETMAP_BUF (va->rx_ring, rx_slot->buf_idx);

		MACCOPY (OUTDSTMAC(v), eth->ether_dhost);

		idx = tx_slot->buf_idx;
		tx_slot->buf_idx = rx_slot->buf_idx;
		rx_slot->buf_idx = idx;
		tx_slot->flags |= NS_BUF_CHANGED;
		rx_slot->flags |= NS_BUF_CHANGED;
		tx_slot->len = rx_slot->len;

#else
                char * spkt = NETMAP_BUF (va->rx_ring, rx_slot->buf_idx);
                char * dpkt = NETMAP_BUF (va->tx_ring, tx_slot->buf_idx);
                nm_pkt_copy (spkt, dpkt, rx_slot->len);

                /* change destination mac */
                eth = (struct ether_header *) dpkt;
                MACCOPY (OUTDSTMAC(v), eth->ether_dhost);
                tx_slot->len = rx_slot->len;
#endif


	drop:
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

        if (vale_rings && strncmp (ifname, "vale", 4) == 0) {
                nmr.nr_rx_rings = vale_rings;
                nmr.nr_tx_rings = vale_rings;
        }

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

        if (vale_rings && strncmp (ifname, "vale", 4) == 0) {
                nmr.nr_rx_rings = vale_rings;
                nmr.nr_tx_rings = vale_rings;
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
		"-L [LEFTOUTMAC] -R[RIGHTOUTMAC]\n"
		"-a [PROTO_PREFIX/LEN:PORT-PREFIX/LEN:PORT] -a ... -a ...\n"
		"-e [VALERINGNUM]\n"
		"\n"
		"port number 0 means all\n"
		);

	return;
}



int
main (int argc, char ** argv)
{
	int ret, q, rq, lq, n, ch, mac[ETH_ALEN];
	char * rif, * lif;	/* right/left interfaces */
	patricia_tree_t * stree, * dtree;
	struct vnfin vi;
	struct aclentry * acl;

	int proto, slen, sport, dlen, dport;
	struct in_addr sprefix, dprefix;


	q = 256;	/* all CPUs */
	rif = lif = NULL;
	verbose = 0;

	udp_tree = New_Patricia (32);
	tcp_tree = New_Patricia (32);

	memset (&vi, 0, sizeof (vi));

	while ((ch = getopt (argc, argv, "r:l:q:R:L:a:e:")) != -1) {
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
		case 'L' :
			sscanf (optarg, "%02x:%02x:%02x:%02x:%02x:%02x", 
				&mac[0], &mac[1], &mac[2],
				&mac[3], &mac[4], &mac[5]);
			MACCOPY (mac, vi.lmac);
			break;
		case 'R' :
			sscanf (optarg, "%02x:%02x:%02x:%02x:%02x:%02x", 
				&mac[0], &mac[1], &mac[2],
				&mac[3], &mac[4], &mac[5]);
			MACCOPY (mac, vi.rmac);
			break;
		case 'a' :

			D ("install ACL Entry %s", optarg);

			ret = split_prefixlenport (optarg, &proto,
						   &sprefix, &slen, &sport,
						   &dprefix, &dlen, &dport);

			if (!ret) {
				D ("invalid prefix %s\n", optarg);
				return -1;
			}

			switch (proto) {
			case IPPROTO_UDP :
				stree = udp_tree;
				break;
			case IPPROTO_TCP :
				stree = tcp_tree;
				break;
			default :
				D ("invalid protocol");
				return -1;
			}

			/* install source prefix */
			D ("%s/%d port %d", inet_ntoa (sprefix), slen, sport);
			acl = find_patricia_entry (stree, &sprefix, slen);
			if (!acl) {
				acl = (struct aclentry *)
					malloc (sizeof (struct aclentry));
				memset (acl, 0, sizeof (struct aclentry));
				acl->dtree = New_Patricia (32);
			}
			acl->port[acl->num++] = htons (sport);
			add_patricia_entry (stree, &sprefix, slen, acl);

			/* install destination prefix */
			D ("%s/%d port %d", inet_ntoa (dprefix), dlen, dport);
			dtree = acl->dtree;
			acl = find_patricia_entry (dtree, &dprefix, slen);
			if (!acl) {
				acl = (struct aclentry *)
					malloc (sizeof (struct aclentry));
				memset (acl, 0, sizeof (struct aclentry));
			}
			acl->port[acl->num++] = htons (dport);
			add_patricia_entry (dtree, &dprefix, dlen, acl);

			break;
			
		case 'e' :
			vale_rings = atoi (optarg);
			if (vale_rings > 4) {
				D ("vale ring should be smaller than 4");
				return -1;
			}
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
	D ("Change Mac Left %02x:%02x:%02x:%02x:%02x:%02x <-> "
	   "%02x:%02x:%02x:%02x:%02x:%02x",
	   vi.lmac[0], vi.lmac[1], vi.lmac[2], 
	   vi.lmac[3], vi.lmac[4], vi.lmac[5],
	   vi.rmac[0], vi.rmac[1], vi.rmac[2], 
	   vi.rmac[3], vi.rmac[4], vi.rmac[5]);

	/* asign processing threads */

	rq = (rq < q) ? rq : q;
	lq = (lq < q) ? lq : q;
	
	/* start threads from right to left */
	for (n = 0; n < rq; n++) {
		struct vnfapp * va;
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		struct vnfin * v;
		v = (struct vnfin *) malloc (sizeof (struct vnfin));
		memcpy (v, &vi, sizeof (struct vnfin));

		SET_R2L (v);
		va->data = v;
		va->rx_q = n;
		va->tx_q = n % lq;
		va->rx_if = rif;
		va->tx_if = lif;
		va->rx_fd = nm_vl_rx_ring (rif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (lif, va->tx_q, &va->tx_ring);

		pthread_create (&va->tid, NULL, processing_thread, va);
	}

	/* start threads from left to right */
	for (n = 0; n < lq; n++) {
		struct vnfapp * va;
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		struct vnfin * v;
		v = (struct vnfin *) malloc (sizeof (struct vnfin));
		memcpy (v, &vi, sizeof (struct vnfin));

		SET_L2R (v);
		va->data = v;
		va->rx_q = n;
		va->tx_q = n % rq;
		va->rx_if = lif;
		va->tx_if = rif;
		va->rx_fd = nm_vl_rx_ring (lif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (rif, va->tx_q, &va->tx_ring);

		pthread_create (&va->tid, NULL, processing_thread, va);
	}


	while (1)
		sleep (100);

	
	return 0;
}



