#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_tun.h>
#include <syslog.h>
#include <pthread.h>

#include "nm_main.h"
#include "nm_nat.h"
#include "nm_session.h"

static void process_nat_p2g(struct mapping *result, char *buf, int len);
static void process_nat_g2p(struct mapping *result, char *buf, int len);
static unsigned short ip4_transport_checksum(struct ip *ip,
			unsigned short *payload, int payloadsize);
static unsigned short ip_checksum(unsigned short *buf, int size);

int process_right_to_left(void *buf, unsigned int len){
	struct mapping *result;
	struct ip *ip = (struct ip *)buf;
	struct icmp *icmp;
	struct tcphdr *tcp;
	struct udphdr *udp;
	uint16_t dest_port = 0;

	if((ip->ip_off & htons(IP_MF)) || (ip->ip_off & htons(IP_OFFMASK))){
		return -1;
	}

	switch(ip->ip_p){
	case IPPROTO_ICMP:
		icmp = (struct icmp *)(buf + sizeof(struct ip));
                dest_port = icmp->icmp_id;
		break;
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)(buf + sizeof(struct ip));
		dest_port = tcp->dest;
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr *)(buf + sizeof(struct ip));
                dest_port = udp->dest;
		break;
	default:
		return -1;
		break;
	}

	pthread_mutex_lock(&mapping_mutex);

	result = search_mapping_table_outer(ip->ip_dst, dest_port);
	if(result == NULL)
		return -1;

	reset_ttl(result);
	process_nat_g2p(result, buf, len);

	pthread_mutex_unlock(&mapping_mutex);

	return 0;
}

int process_left_to_right(void *buf, unsigned int len){
	struct mapping *result;
	struct ip *ip = (struct ip *)buf;
	struct icmp *icmp;
	struct tcphdr *tcp;
	struct udphdr *udp;
	uint16_t source_port = 0;

	if((ip->ip_off & htons(IP_MF)) || (ip->ip_off & htons(IP_OFFMASK))){
		return -1;
	}

	switch(ip->ip_p){
	case IPPROTO_ICMP:
		icmp = (struct icmp *)(buf + sizeof(struct ip));
		source_port = icmp->icmp_id;
		break;
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)(buf + sizeof(struct ip));
		source_port = tcp->source;
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr *)(buf + sizeof(struct ip));
		source_port = udp->source;
		break;
	default:
		return -1;
		break;
	}

	pthread_mutex_lock(&mapping_mutex);
	
	result = search_mapping_table_inner(ip->ip_src, source_port);
	if(result == NULL){
		result = (struct mapping *)malloc(sizeof(struct mapping));
		memset(result, 0, sizeof(struct mapping));

		reset_ttl(result);
		result->source_addr = ip->ip_src;
		result->source_port = source_port;
		if(insert_new_mapping(result) < 0){
			return -1;
		}

		process_nat_p2g(result, buf, len);
	}else{
		reset_ttl(result);
		process_nat_p2g(result, buf, len);
	}

	pthread_mutex_unlock(&mapping_mutex);

	return 0;
}

static void process_nat_p2g(struct mapping *result, char *buf, int len){
	struct ip *ip = (struct ip *)buf;
        struct icmp *icmp;
        struct tcphdr *tcp;
        struct udphdr *udp;

	ip->ip_src = result->mapped_addr;

	switch(ip->ip_p){
	case IPPROTO_ICMP:
                icmp = (struct icmp *)(buf + sizeof(struct ip));
                icmp->icmp_id = result->mapped_port;
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = ip_checksum((unsigned short *)icmp,
				len - sizeof(struct ip));
		break;
	case IPPROTO_TCP:
                tcp = (struct tcphdr *)(buf + sizeof(struct ip));
                tcp->source = result->mapped_port;
		tcp->check = 0;
		tcp->check = ip4_transport_checksum(ip,
				(unsigned short *)tcp, len - sizeof(struct ip));
		break;
	case IPPROTO_UDP:
                udp = (struct udphdr *)(buf + sizeof(struct ip));
                udp->source = result->mapped_port;
		udp->check = 0;
		udp->check = ip4_transport_checksum(ip,
				(unsigned short *)udp, len - sizeof(struct ip));
		break;
	default:
                return;
		break;
        }

	ip->ip_sum = 0;
	ip->ip_sum = ip_checksum((unsigned short *)ip, sizeof(struct ip));

	return;
}

static void process_nat_g2p(struct mapping *result, char *buf, int len){
	struct ip *ip = (struct ip *)buf;
        struct icmp *icmp;
        struct tcphdr *tcp;
        struct udphdr *udp;

	ip->ip_dst = result->source_addr;

	switch(ip->ip_p){
	case IPPROTO_ICMP:
                icmp = (struct icmp *)(buf + sizeof(struct ip));
                icmp->icmp_id = result->source_port;
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = ip_checksum((unsigned short *)icmp,
				len - sizeof(struct ip));
		break;
	case IPPROTO_TCP:
                tcp = (struct tcphdr *)(buf + sizeof(struct ip));
                tcp->dest = result->source_port;
		tcp->check = 0;
		tcp->check = ip4_transport_checksum(ip,
				(unsigned short *)tcp, len - sizeof(struct ip));
		break;
	case IPPROTO_UDP:
                udp = (struct udphdr *)(buf + sizeof(struct ip));
                udp->dest = result->source_port;
		udp->check = 0;
		udp->check = ip4_transport_checksum(ip,
				(unsigned short *)udp, len - sizeof(struct ip));
		break;
	default:
                return;
		break;
	}

	ip->ip_sum = 0;
	ip->ip_sum = ip_checksum((unsigned short *)ip, sizeof(struct ip));

	return;
}

static unsigned short ip4_transport_checksum(struct ip *ip,
	unsigned short *payload, int payloadsize)
{
        unsigned long sum = 0;

        struct pseudo_ipv4_header p;
        unsigned short *f = (unsigned short *)&p;
        int pseudo_size = sizeof(p);

        memset(&p, 0, sizeof(struct pseudo_ipv4_header));
        p.src_address = ip->ip_src;
        p.dst_address = ip->ip_dst;
        p.ip_p_nxt = ip->ip_p;
	p.ip_p_len = htons(payloadsize);

        while (pseudo_size > 1) {
                sum += *f;
                f++;
                pseudo_size -= 2;
        }

        while (payloadsize > 1) {
                sum += *payload;
                payload++;
                payloadsize -= 2;
        }

        if (payloadsize == 1) {
		sum += htons(*(unsigned char *)payload << 8);
        }

        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

static unsigned short ip_checksum(unsigned short *buf, int size){
        unsigned long sum = 0;

        while (size > 1) {
                sum += *buf++;
                size -= 2;
        }
        if(size){
		sum += htons(*(unsigned char *)buf << 8);
	}

        sum  = (sum & 0xffff) + (sum >> 16);    /* add overflow counts */
        sum  = (sum & 0xffff) + (sum >> 16);    /* once again */

        return ~sum;
}

