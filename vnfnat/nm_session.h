struct mapping {
	struct in_addr	mapped_addr;
	struct in_addr	source_addr;
	uint16_t	mapped_port;
	uint16_t	source_port;
	uint32_t	ttl;
	struct mapping 	*next;
};

struct mapping *init_mapping_table();
struct mapping *search_mapping_table_outer(struct in_addr mapped_addr, uint16_t mapped_port);
struct mapping *search_mapping_table_inner(struct in_addr source_addr, uint16_t source_port);
int insert_new_mapping(struct mapping *result);
void *reset_ttl(struct mapping *target);
void count_down_ttl(void);
