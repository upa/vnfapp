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
#include <syslog.h>

#include "main.h"
#include "session.h"


static uint32_t create_table_key(void *address, uint16_t port);
static int add_mapping_to_hash(struct mapping *result);
static void delete_mapping_from_hash(struct mapping *result);
static struct in_addr select_mapped_addr(void *source_addr, uint16_t source_port);
static uint16_t select_restricted_port(struct in_addr mapped_addr, void *source_addr, uint16_t source_port);


static uint32_t create_table_key(void *address, uint16_t port){
	struct in_addr *ip = (struct in_addr *)address;
	uint32_t sum = ip->s_addr + port;

	return sum % MAX_SESSION;
}

struct mapping *init_mapping_table(){
	struct mapping *ptr = (struct mapping *)malloc(sizeof(struct mapping));
	memset(ptr, 0, sizeof(struct mapping));

	inner_table = (struct mapping **)malloc(sizeof(struct mapping *) * MAX_SESSION);
	memset(inner_table, 0, sizeof(struct mapping *) * MAX_SESSION);
	outer_table = (struct mapping **)malloc(sizeof(struct mapping *) * MAX_SESSION);
	memset(outer_table, 0, sizeof(struct mapping *) * MAX_SESSION);

	return ptr;
}

static int add_mapping_to_hash(struct mapping *result){
	uint32_t outer_key = create_table_key(&(result->mapped_addr), result->mapped_port);
	uint32_t inner_key = create_table_key(&(result->source_addr), result->source_port);
	int count;

	count = 0;
	while(outer_table[outer_key] != NULL){
		outer_key++;
                if(outer_key == MAX_SESSION){
                        outer_key = 0;
                }

		count++;
		if(count == MAX_SESSION){
			return -1;
		}
	}

	outer_table[outer_key] = result;

	count = 0;
	while(inner_table[inner_key] != NULL){
		inner_key++;
                if(inner_key == MAX_SESSION){
                        inner_key = 0;
                }

		count++;
		if(count == MAX_SESSION){
			return -1;
		}
	}

	inner_table[inner_key] = result;

	return 0;
}

static void delete_mapping_from_hash(struct mapping *result){
        uint32_t outer_key = create_table_key(&(result->mapped_addr), result->mapped_port);
        uint32_t inner_key = create_table_key(&(result->source_addr), result->source_port);

	while(1){
		if(outer_table[outer_key] != NULL){
			if(!memcmp(&(outer_table[outer_key]->mapped_addr), &(result->mapped_addr), 4)
				&& outer_table[outer_key]->mapped_port == result->mapped_port){
				break;
			}
		}

                outer_key++;
		if(outer_key == MAX_SESSION){
			outer_key = 0;
		}
        }

        outer_table[outer_key] = NULL;

        while(1){
                if(inner_table[inner_key] != NULL){
                        if(!memcmp(&(inner_table[inner_key]->source_addr), &(result->source_addr), 16)
				&& inner_table[inner_key]->source_port == result->source_port){
                                break;
                        }       
		}

                inner_key++;
                if(inner_key == MAX_SESSION){
                        inner_key = 0;
                }
        }

        inner_table[inner_key] = NULL;

        return;
}

struct mapping *search_mapping_table_outer(struct in_addr mapped_addr, uint16_t mapped_port){
        uint32_t key = create_table_key(&mapped_addr, mapped_port);
        int count = 0;

        while(++count <= MAX_SESSION){
		if(outer_table[key] != NULL){
                	if(!memcmp(&(outer_table[key]->mapped_addr), &mapped_addr, 4)
				&& outer_table[key]->mapped_port == mapped_port){

                        	return outer_table[key];
                	}
		}

		key++;
                if(key == MAX_SESSION){
                        key = 0;
                }
        }

        return NULL;

}

struct mapping *search_mapping_table_inner(struct in_addr source_addr, uint16_t source_port){
        uint32_t key = create_table_key(&source_addr, source_port);
        int count = 0;

        while(++count <= MAX_SESSION){
		if(inner_table[key] != NULL){
                	if(!memcmp(&(inner_table[key]->source_addr), &source_addr, 4)
				&& inner_table[key]->source_port == source_port){

                        	return inner_table[key];
                	}
		}

		key++;
                if(key == MAX_SESSION){
                        key = 0;
                }
        }

        return NULL;

}

static struct in_addr select_mapped_addr(void *source_addr, uint16_t source_port){
        struct in_addr *ip = (struct in_addr *)source_addr;
	struct in_addr result = config.v4_rule_addr;
	uint32_t v4_suffix = config.ea;
        uint32_t sum = ip->s_addr + source_port;
	int range;
	int i;

	v4_suffix = v4_suffix >> config.psid_len;
	v4_suffix = v4_suffix << 32 - (config.v4_rule_prefix + config.v4_suffix_len);

	for(i = 0, range = 1; i < 32 - (config.v4_rule_prefix + config.v4_suffix_len); i++){
		range *= 2;
	}

	*(uint32_t *)&result.s_addr |= htonl(v4_suffix);
	*(uint32_t *)&result.s_addr |= htonl(sum % range);
	
        return result;
}

static uint16_t select_restricted_port(struct in_addr mapped_addr, void *source_addr, uint16_t source_port){
	struct mapping *ptr = (struct mapping *)mapping_table;
	struct in_addr *ip = (struct in_addr *)source_addr;
	uint16_t psid = (uint16_t)(config.ea);
	uint16_t result;
	uint32_t sum = ip->s_addr + source_port;
	int range;
	int count = 0;
	int i;

	psid = psid << (16 - config.psid_len);
	psid = psid >> (config.a_bits);
	psid |= 1 << (16 - config.a_bits);

        for(i = 0, range = 1; i < 16 - (config.a_bits + config.psid_len); i++){
                range *= 2;
        }

	while(1){
		result = htons(psid | (sum + count) % range);
		if(search_mapping_table_outer(mapped_addr, result) == NULL){
			return result;
		}
	
		count++;
		if(count == range){
			/* failed to assign port */
			return 0;
		}
	}
	
}

int insert_new_mapping(struct mapping *result){
	struct mapping *ptr = (struct mapping *)mapping_table;
	struct in_addr mapped_addr;
	uint16_t mapped_port;
        char log_source[256];
        char log_mapped[256];

	mapped_addr = select_mapped_addr(&(result->source_addr), result->source_port);
	mapped_port = select_restricted_port(mapped_addr, &(result->source_addr), result->source_port);

	if(mapped_port != 0){
		result->mapped_addr = mapped_addr;
		result->mapped_port = mapped_port;

		if(add_mapping_to_hash(result) < 0){
			/* session over flow */
			free(result);
			return -1;
		}

		result->next = ptr->next;
		ptr->next = result;

                inet_ntop(AF_INET, &(result->source_addr), log_source, sizeof(log_source));
                inet_ntop(AF_INET, &(result->mapped_addr), log_mapped, sizeof(log_mapped));
                syslog_write(LOG_INFO, "session created: %s:%d <-> %s:%d",
			log_source, ntohs(result->source_port), log_mapped, ntohs(result->mapped_port));

		return 0;
	}else{
		free(result);
		return -1;
	}

}

void *reset_ttl(struct mapping *target){
	target->ttl = SESSION_TTL;
}

void count_down_ttl(){
	struct mapping *ptr;
	struct mapping *prev;
	struct mapping *tmp;
	char log_source[256];
	char log_mapped[256];

	prev = (struct mapping *)mapping_table;
	ptr = prev->next;

	while(ptr != NULL){
		ptr->ttl--;
		if(ptr->ttl == 0){
			tmp = ptr;
			prev->next = ptr->next;
			ptr = ptr->next;
			delete_mapping_from_hash(tmp);
			inet_ntop(AF_INET, &(tmp->source_addr), log_source, sizeof(log_source));
			inet_ntop(AF_INET, &(tmp->mapped_addr), log_mapped, sizeof(log_mapped));
			syslog_write(LOG_INFO, "session deleted: %s:%d <-> %s:%d",
				log_source, ntohs(tmp->source_port), log_mapped, ntohs(tmp->mapped_port));
			free(tmp);
			continue;
		}

		prev = ptr;
		ptr = ptr->next;
	}
}

