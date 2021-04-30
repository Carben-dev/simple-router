
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"

#define NAT_INTERNAL_IF_NAME "eth1"
#define NAT_EXTERNAL_IF_NAME "eth2"

typedef enum {
    nat_mapping_icmp,
    nat_mapping_tcp
 /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
    nat_conn_listen,
    nat_conn_syn_sent,
    nat_conn_syn_received,
    nat_conn_established,
    nat_conn_fin_wait_1,
    nat_conn_fin_wait_2,
    nat_conn_close_wait,
    nat_conn_closing,
    nat_conn_closed,
    nat_conn_last_ack,
    nat_conn_time_wait
    
} sr_nat_conn_state;

struct sr_nat_connection {
    /* add TCP connection state data members here */
    sr_nat_conn_state state;
    struct sr_nat_connection *next;
};



struct sr_nat_mapping {
    sr_nat_mapping_type type;
    uint32_t ip_int;                  /* internal ip addr */
    uint32_t ip_ext;                  /* external ip addr */
    uint16_t aux_int;                 /* internal port or icmp id */
    uint16_t aux_ext;                 /* external port or icmp id */
    time_t last_updated;              /* use to timeout mappings */
    struct sr_nat_connection *conns;  /* list of connections. null for ICMP */
    struct sr_nat_mapping *next;
};

struct sr_nat {
    /* add any fields here */
    struct sr_nat_mapping *mappings;

    /* threading */
    pthread_mutex_t       lock;
    pthread_mutexattr_t   attr;
    pthread_attr_t        thread_attr;
    pthread_t             thread;
};


int   sr_nat_init(struct sr_nat *nat);      /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);   /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);        /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext,
                                              sr_nat_mapping_type type);

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                              uint32_t ip_int,
                                              uint16_t aux_int,
                                              sr_nat_mapping_type type);

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                             uint32_t ip_int,
                                             uint16_t aux_int,
                                             sr_nat_mapping_type type);

/* helper function */
void rewrite_tcp_outbound(struct sr_instance *,
                          uint8_t *,
                          unsigned int,
                          struct sr_nat_mapping *,
                          struct sr_if *);


#endif
