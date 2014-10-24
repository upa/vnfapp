#define NM_DIR_TX	0
#define NM_DIR_RX	1
#define NM_THREAD_R2L	0
#define NM_THREAD_L2R	1
#define SYSLOG_FACILITY LOG_DAEMON
#define BUDGET_MAX	1024
#define PROCESS_NAME	"vnf-nat"
#define min(a, b) ((a) < (b) ? (a) : (b))

extern struct mapping **inner_table;
extern struct mapping **outer_table;
extern struct mapping *mapping_table;
extern pthread_mutex_t mapping_mutex;

struct vnfapp {
	pthread_t tid;

	int rx_fd, tx_fd;
	int rx_q, tx_q;
	char *rx_if, *tx_if;
	struct netmap_ring *rx_ring, *tx_ring;
	unsigned int direction;

	void *data;
};

void syslog_write(int level, char *fmt, ...);
