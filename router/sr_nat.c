#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "sr_nat.h"


unsigned short icmp_id_counter;
unsigned short tcp_port_counter;

/* Initializes the nat */
int sr_nat_init(struct sr_nat *nat) {

    assert(nat);

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

    /* Initialize timeout thread */

    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

    nat->mappings = NULL;
    /* Initialize any variables here */
    icmp_id_counter = 0;
    tcp_port_counter = 1024;

    return success;
}

/* Destroys the nat (free memory) */
int sr_nat_destroy(struct sr_nat *nat) {

    pthread_mutex_lock(&(nat->lock));

    /* free all mapping in nat */
    struct sr_nat_mapping *curr_mapping = nat->mappings;
    while (curr_mapping != NULL) {
        /* free all connection in this mapping */
        struct sr_nat_connection *curr_conn = curr_mapping->conns;
        while (curr_conn != NULL) {
            /* save next conn ptr and free this conn */
            struct sr_nat_connection *next_conn = curr_conn->next;
            free(curr_conn);
            curr_conn = next_conn;
        }
        /* save next mapping ptr and free this mapping */
        struct sr_nat_mapping *next_mapping = curr_mapping->next;
        free(curr_mapping);
        curr_mapping = next_mapping;
    }
    
    /* free the nat */
    free(nat);
    
    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
        pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
    struct sr_nat *nat = (struct sr_nat *)nat_ptr;
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        time_t curtime = time(NULL);

        /* handle periodic tasks here */

        pthread_mutex_unlock(&(nat->lock));
    }
    return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
                                              uint16_t aux_ext,
                                              sr_nat_mapping_type type)
{
    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;
    
    /* walk through mapping in nat to find match */
    struct sr_nat_mapping *curr_mapping = nat->mappings;
    while (curr_mapping != NULL) {
        if ((curr_mapping->aux_ext == aux_ext) && (curr_mapping->type == type)) {
            copy = malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, curr_mapping, sizeof(struct sr_nat_mapping));
            break;
        }
        curr_mapping = curr_mapping->next;
    }
    
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
                                              uint32_t ip_int,
                                              uint16_t aux_int,
                                              sr_nat_mapping_type type)
{

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = NULL;
    
    /* walk through mapping in nat to find match */
    struct sr_nat_mapping *curr_mapping = nat->mappings;
    while (curr_mapping != NULL) {
        if (       (curr_mapping->aux_int == aux_int)
                && (curr_mapping->type    == type   )
                && (curr_mapping->ip_int  == ip_int )
            )
        {
            copy = malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, curr_mapping, sizeof(struct sr_nat_mapping));
            break;
        }
        curr_mapping = curr_mapping->next;
    }
    
    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
                                             uint32_t ip_int,
                                             uint16_t aux_int,
                                             sr_nat_mapping_type type)
{

    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = calloc(1, sizeof(struct sr_nat_mapping));
    struct sr_nat_mapping *cpy = malloc(sizeof(struct sr_nat_mapping));
    
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->type = type;
    
    mapping->next = nat->mappings;
    nat->mappings = mapping;
    
    /* Insert ICMP */
    if (type == nat_mapping_icmp) {
        mapping->conns = NULL;
        mapping->last_updated = time(NULL);
        mapping->aux_ext = htons(icmp_id_counter);
        icmp_id_counter++;
    }
    
    /* Insert TCP */
    if (type == nat_mapping_tcp) {
        mapping->conns = calloc(1, sizeof(struct sr_nat_connection));
        mapping->conns->state = nat_conn_syn_sent;
        mapping->last_updated = time(NULL);
        mapping->aux_ext = htons(tcp_port_counter);
        tcp_port_counter++;
        if (tcp_port_counter == 0xFFFF) {
            tcp_port_counter = 1024;
        }
        
    }
    
    memcpy(cpy, mapping, sizeof(struct sr_nat_mapping));
    pthread_mutex_unlock(&(nat->lock));
    return cpy;
}

/* helper function */
void rewrite_tcp_outbound(struct sr_instance *sr,
                          uint8_t *packet,
                          unsigned int len,
                          struct sr_nat_mapping *mapping,
                          struct sr_if *out_if)
{
    sr_ip_hdr_t *this_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_tcp_hdr_t *this_tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    
    /* rewrite IP hdr */
    this_ip_hdr->ip_src = out_if->ip;
    /* recompute checksum */
    this_ip_hdr->ip_sum = 0;
    this_ip_hdr->ip_sum = cksum(this_ip_hdr, sizeof(sr_ip_hdr_t));
    
    /* rewrite TCP hdr */
    this_tcp_hdr->port_src = mapping->aux_ext;
    this_tcp_hdr->sum = 0;
    this_tcp_hdr->sum = cksum(this_tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    
    return;
    
}


