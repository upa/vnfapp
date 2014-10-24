#define NAT_ADDRESS	"192.0.2.0"
#define NAT_PREFIX	24
#define NAT_PORT_MAX	65535
#define NAT_PORT_MIN	1024

struct pseudo_ipv4_header{
	struct in_addr	src_address,
			dst_address;
	uint8_t		ip_p_pad;
	uint8_t		ip_p_nxt;
	uint16_t	ip_p_len;
};

int process_right_to_left(void *buf, unsigned int len);
int process_left_to_right(void *buf, unsigned int len);
