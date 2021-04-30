/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

extern int nat_enable;

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    
    /* Init nat */
    if (nat_enable) {
        sr->nat = malloc(sizeof(struct sr_nat));
        sr_nat_init(sr->nat);
    }
    
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    /* to check whether those values are not 0? */
    assert(sr);
    assert(packet);
    assert(interface);
    
    /* print out content of this packet */
    printf("*** -> Received packet of length %d \n",len);
    print_hdrs(packet, len);

    /* fill in code here */
    
    /* If packet size less than the minimun required, drop */
    if (len < sizeof(sr_ethernet_hdr_t)){
        printf("packet size < ethernet header size. Drop!\n");
        return;
    }
    
    /* Handle ARP or IP packet differently */
    
    uint16_t this_type = ethertype(packet);
    
    /* This packet is arp packet */
    if (this_type == ethertype_arp){
        printf("ARP packet recevied. Hand packet to handle_arp_pkt.\n");
        handle_arp_pkt(sr, packet, len, interface);
        return;
    }
    
    /* This packet is IP packet */
    if (this_type == ethertype_ip) {
        printf("IP packet recevied.\n");
        if (nat_enable){
            printf("NAT enabled, Hand packet to handle_nat.\n");
            handle_nat(sr, packet, len, interface);
            printf("returned from handle_nat, Hand packet to handle_ip_pkt.\n");
        }
        
        /* check for drop mark */
        if (*packet == 0) {
            printf("DROP mark set, drop pkt\n");
            return;
        }
        
        handle_ip_pkt(sr, packet, len);
        return;
    }
    
    /* If reach here not type matched. */
    printf("Unidentified packet type. Drop!\n");
    return;

}

void handle_nat(struct sr_instance *sr,
                uint8_t            *packet,
                unsigned int        len,
                char               *interface)
{
    int is_icmp;    /* if packet is an ICMP packet */
    sr_tcp_hdr_t *this_tcp_hdr;
    sr_icmp_hdr_t *this_icmp_hdr;
    int destined_ext_if = 0; /* if pkt destined to router external interface */
    int destined_int_if = 0; /* if pkt destined to router internal interface */
    struct sr_if *external_if = sr_get_interface(sr, NAT_EXTERNAL_IF_NAME); /* external Interface */
    struct sr_if *internal_if = sr_get_interface(sr, NAT_INTERNAL_IF_NAME); /* internal Interface */
    
    /* Prepare IP header */
    sr_ip_hdr_t *this_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* check ip pkt type */
    if (this_ip_hdr->ip_p == ip_protocol_icmp) {
        printf("handle_nat: this is an ICMP pkt.\n");
        is_icmp = 1;
        this_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));    /* Prepare general ICMP hdr */
    } else { /* not need to consider udp */
        printf("handle_nat: this is an TCP pkt.\n");
        is_icmp = 0;
        this_tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
    
    /* check where pkt from and go where */
    
    /* check if pkt destined to router external interface */
    if (this_ip_hdr->ip_dst == external_if->ip) {
        destined_ext_if = 1;
    }
    
    /* check if pkt destined to router internal interface */
    if (this_ip_hdr->ip_dst == internal_if->ip) {
        destined_int_if = 1;
    }
    
    /* handle pkt outbound (internal -> external) */
    if (strstr(NAT_INTERNAL_IF_NAME, interface) != NULL && !destined_int_if && !destined_ext_if) {
        printf("handle_nat: pkt outbound(internal -> external)\n");
        
        if (is_icmp) { /* handle ICMP outbound */
            
            /* only allow ICMP echo request to go through NAT (outbound) */
            if (this_icmp_hdr->icmp_type != 8) {
                /* drop packet */
                /* set the first 8bits of pkt to 0 to mark this pkt should be drop */
                memset(packet, 1, 1);
                return;
            }
            
            /* if pass test, this pkt is ICMP echo request */
            sr_icmp_t8_hdr_t *this_icmp_type8_hdr = (sr_icmp_t8_hdr_t *)this_icmp_hdr;
            
            /* Find mapping */
            struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat, this_ip_hdr->ip_src, this_icmp_type8_hdr->icmp_id, nat_mapping_icmp);
            if (mapping == NULL) { /* no mapping found */
                mapping = sr_nat_insert_mapping(sr->nat, this_ip_hdr->ip_src, this_icmp_type8_hdr->icmp_id, nat_mapping_icmp);
            }
            
            /* rewrite IP hdr */
            this_ip_hdr->ip_src = external_if->ip;
            /* recompute checksum */
            this_ip_hdr->ip_sum = 0;
            this_ip_hdr->ip_sum = cksum(this_ip_hdr, sizeof(sr_ip_hdr_t));
            
            /* rewrite ICMP hdr */
            this_icmp_type8_hdr->icmp_id = mapping->aux_ext;
            this_icmp_type8_hdr->icmp_sum = 0;
            this_icmp_type8_hdr->icmp_sum = cksum(this_icmp_type8_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            
            
            free(mapping);
            return;
            
            
        } /* -- handle ICMP outbound -- */
        else { /* handle TCP outbound */
            
            struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat, this_ip_hdr->ip_src, this_tcp_hdr->port_src, nat_mapping_tcp);
            if (mapping == NULL) { /* no mapping found */
                if (this_tcp_hdr->syn) {
                    mapping = sr_nat_insert_mapping(sr->nat, this_ip_hdr->ip_src, this_tcp_hdr->port_src, nat_mapping_tcp);
                    rewrite_tcp_outbound(sr, packet, len, mapping, external_if);
                    free(mapping);
                    return;
                } else { /* new connection but not SYN */
                    /* drop packet */
                    /* set the first 8bits of pkt to 0 to mark this pkt should be drop */
                    printf("TCP outbound: mapping not found and not SYN\n");
                    memset(packet, 1, 1);
                    return;
                }
            } /* -- no mapping found -- */
            else {
                /* mapping found, rewrite header */
                rewrite_tcp_outbound(sr, packet, len, mapping, external_if);
                free(mapping);
                return;
            }
        } /* -- handle TCP outbound -- */
        
    }/* -- handle pkt outbound (internal -> external) -- */
    
    /* handle pkt is inbound (external -> internal) */
    if (strstr(NAT_EXTERNAL_IF_NAME, interface) != NULL && destined_ext_if)
    {
        printf("handle_nat: pkt inbound(external -> internal)\n");
        if (is_icmp) { /* handle ICMP inbound */
            
            /* only allow ICMP echo to go through NAT (inbound) */
            if (this_icmp_hdr->icmp_type != 0) {
                /* drop packet */
                /* set the first 8bits of pkt to 0 to mark this pkt should be drop */
                memset(packet, 1, 1);
                return;
            }
            
            /* if pass test, this pkt is ICMP echo */\
            /* Since type0 and type8 share the same hdr, reuse type8 hdr */
            sr_icmp_t8_hdr_t *this_icmp_echo_hdr = (sr_icmp_t8_hdr_t *)this_icmp_hdr;
            
            /* finding mapping */
            struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, this_icmp_echo_hdr->icmp_id, nat_mapping_icmp);
            if (mapping == NULL) {
                printf("ICMP inbound: not mapping found, drop packet.\n");
                /* drop packet */
                /* set the first 8bits of pkt to 0 to mark this pkt should be drop */
                memset(packet, 1, 1);
                return;
            }
            
            /* rewrite IP hdr */
            this_ip_hdr->ip_dst = mapping->ip_int;
            /* recompute checksum */
            this_ip_hdr->ip_sum = 0;
            this_ip_hdr->ip_sum = cksum(this_ip_hdr, sizeof(sr_ip_hdr_t));
            
            /* rewrite ICMP hdr */
            this_icmp_echo_hdr->icmp_id = mapping->aux_int;
            this_icmp_echo_hdr->icmp_sum = 0;
            this_icmp_echo_hdr->icmp_sum = cksum(this_icmp_echo_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            
            
            free(mapping);
            return;
            
            
        } /* -- handle ICMP inbound -- */
        else { /* handle TCP inbound */
            struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, this_tcp_hdr->port_dst, nat_mapping_tcp);
            if (mapping == NULL) {
                if (this_tcp_hdr->syn) { /* Unsolicited inbound SYN packet */
                    printf("Unsolicited inbound SYN packet.\n");
                    if (ntohs(this_tcp_hdr->port_dst) == 22) {
                        return;
                    }
                    sleep(6);
                    return;
                } else { /* Unsolicited inbound packet */
                    
                    return;
                }
            } else { /* mapping found, rewrite packet */
                
                /* rewrite IP hdr */
                this_ip_hdr->ip_dst = mapping->ip_int;
                /* recompute checksum */
                this_ip_hdr->ip_sum = 0;
                this_ip_hdr->ip_sum = cksum(this_ip_hdr, sizeof(sr_ip_hdr_t));
                
                /* rewrite TCP hdr */
                this_tcp_hdr->port_dst = mapping->aux_int;
                this_tcp_hdr->sum = 0;
                this_tcp_hdr->sum = cksum(this_tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                return;
            }
        }/* -- handle TCP inbound -- */
        
    } /* -- handle pkt is inbound (external -> internal) -- */
    
    /* If reach here, pkt doesn't go through NAT */
    printf("handle_nat: this pkt doesn't go through NAT.\n");
    return;
}


/* handle arp pkt */
void handle_arp_pkt(struct sr_instance *sr,
                    uint8_t *packet,
                    unsigned int len,
                    char *interface)
{
    /* Check if len req meet */
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
        printf("handle_arp_pkt: ARP packet len too short. Drop!\n");
        return;
    }
    
    /* Prepare header */
    sr_ethernet_hdr_t *this_eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *this_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    unsigned short this_arp_op = ntohs(this_arp_hdr->ar_op);
    
    switch (this_arp_op)
    
    {
        
        /* reply arp request */
        case arp_op_request:
            {
                /* Allocate memory for new reply packet */
                int reply_len = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
                uint8_t *reply = (uint8_t *)calloc(1, reply_len);
                
                /* Prepare reply pkt header */
                sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply;
                sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
                
                /* Prepare interface */
                struct sr_if *this_if = sr_get_interface(sr, interface);
                
                /* build reply's arp header */
                reply_arp_hdr->ar_hrd = this_arp_hdr->ar_hrd;
                reply_arp_hdr->ar_pro = this_arp_hdr->ar_pro;
                reply_arp_hdr->ar_hln = this_arp_hdr->ar_hln;
                reply_arp_hdr->ar_pln = this_arp_hdr->ar_pln;
                reply_arp_hdr->ar_op = htons(arp_op_reply);
                memcpy(reply_arp_hdr->ar_sha, this_if->addr, ETHER_ADDR_LEN);
                reply_arp_hdr->ar_sip = this_if->ip;
                memcpy(reply_arp_hdr->ar_tha, this_arp_hdr->ar_sha, ETHER_ADDR_LEN);
                reply_arp_hdr->ar_tip = this_arp_hdr->ar_sip;
                
                /* build reply's ethernet header */
                memcpy(reply_eth_hdr->ether_dhost, this_eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(reply_eth_hdr->ether_shost, this_if->addr, ETHER_ADDR_LEN);
                reply_eth_hdr->ether_type = htons(ethertype_arp);
                
                /* Send reply packet */
                sr_send_packet(sr, reply, reply_len, interface);
                free(reply);
                
                break;
            }
            
        /* Record the reply in arpentry, send out the packet waiting on the reply */
        case arp_op_reply:
            {
                printf("handle_arp_pkt: this is an arp reply.\n");
                /* Insert reply to arp cache */
                struct sr_arpreq *this_req = sr_arpcache_insert(&sr->cache, this_arp_hdr->ar_sha, this_arp_hdr->ar_sip);
                
                /* If queue not null, try to send the packets are waiting */
                if (this_req != NULL && this_req->packets != NULL) {
                    struct sr_packet *curr = this_req->packets;
                    
                    printf("handle_arp_pkt: this arp reply queue not empty.\n");
                    
                    while (curr != NULL) {
                        
                        /* Interface coresponding to current packet */
                        struct sr_if *curr_if = sr_get_interface(sr, curr->iface);
                        
                        /* Construct ethernet header for current packet */
                        struct sr_ethernet_hdr *curr_eth_hdr = (struct sr_ethernet_hdr *)curr->buf;
                        memcpy(curr_eth_hdr->ether_dhost, this_arp_hdr->ar_sha, ETHER_ADDR_LEN);
                        memcpy(curr_eth_hdr->ether_shost, curr_if->addr, ETHER_ADDR_LEN);
                        
                        printf("handle_arp_pkt: sending packets(%d byte(s)) in req queue:\n", curr->len);
                        print_hdrs(curr->buf, curr->len);
                        sr_send_packet(sr, curr->buf, curr->len, curr->iface);
                        
                        /* Go to next packet */
                        curr = curr->next;
                    }
                    
                    
                    /* After the while loop all waiting packets should be sent, clean up arpreq */
                    printf("handle_arp_pkt: All packet in req queue sent, destroy.\n");
                    sr_arpreq_destroy(&sr->cache, this_req);
                    
                }
                
                break;
            }
            
        default:
            printf("handle_arp_pkt: No matched arp_op.\n");
            break;
    }
    
};

void handle_ip_pkt(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len)
{
    uint16_t this_cksum; /* cksum result */
    
    /* Check size */
    if (len < (sizeof(sr_ethernet_hdr_t) + MIN_IP_HDR_SIZE)) {
        printf("handle_ip_pkt: IP packet size too short.\n");
        return;
    }
    
    /* Prepare IP header */
    sr_ip_hdr_t *this_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /*
     * Verify checksum
     * Drop if fail
     */
    this_cksum = cksum(this_ip_hdr, this_ip_hdr->ip_hl * 4);
    if (this_cksum != 0xFFFF) {
        printf("handle_ip_pkt: cksum: verification fail.\n");
        return;
    }
    
    /* Check if packet is coming for router. */
    /* destined_router will be true, if match found */
    int destined_router = 0; /* default false */
    struct sr_if *if_walker = sr->if_list;
    
    /* walker through interface of router */
    while (if_walker != NULL && !destined_router) {
        if (this_ip_hdr->ip_dst == if_walker->ip) {
            destined_router = 1;
        }
        if_walker = if_walker->next;
    }
    
    /* IP packet coming for router? */
    printf("handle_ip_pkt: destined router? %d\n", destined_router);
    
    /* This IP packet is destined router */
    if (destined_router) {
        
        /* Check if it is a ICMP echo pkt, if not drop? */
        if (this_ip_hdr->ip_p == ip_protocol_icmp) {
            printf("handle_ip_pkt: this is an ICMP pkt.\n");
            /* Prepare ICMP header */
            sr_icmp_hdr_t *this_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + this_ip_hdr->ip_hl * 4);
            
            /* Print out this ICMP packet */
            print_hdr_icmp((uint8_t *)this_icmp_hdr);
            
            /* check ICMP checksum, if fail drop! */
            this_cksum = cksum(this_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - (this_ip_hdr->ip_hl * 4));
            this_cksum = this_cksum; /* test purpose just skip cksum check */
            if (this_cksum != 0xFFFF) { /* cksum fail, drop */
                printf("PING pkt to router checksum fail, drop!\n");
                return;
            }
            printf("handle_ip_pkt: ICMP checksum OK.\n");
            
            /* Check ICMP header, if not a ping request, drop */
            if (this_icmp_hdr->icmp_type != 8) {
                printf("ICMP pkt to router, but not ping.\n");
                return;
            }
            
            /* Reply echo reply */
            printf("handle_ip_pkt: send icmp echo.\n");
            send_echo(sr, packet, len);
            return;
            
            
        /* Destined router but not a ICMP pkt. */
        } else {
            
            /* Send port unreachable */
            printf("Destined router but not a ICMP pkt.\n");
            printf("handle_ip_pkt: send icmp unreachable to ");
            print_addr_ip_int(ntohl(this_ip_hdr->ip_src));
            printf("\n");
            send_icmp_t3(sr, packet, this_ip_hdr->ip_src, 3);
            return;
        }
        
        
    /* Destined elsewhere. Then forward it. */
    } else {
        /* test purpose */
        if (this_ip_hdr->ip_p == ip_protocol_icmp) {
            printf("fowarding ICMP pkt.\n");
            print_hdrs(packet, len);
        }
        
        /* Decrement TTL */
        this_ip_hdr->ip_ttl--;
        
        /* TTL equal 0 */
        if (this_ip_hdr->ip_ttl == 0) {
            printf("TTL equal 0.\n");
            /* Should send ICMP timeout */
            send_icmp_t11(sr, packet, this_ip_hdr->ip_src, 0);
            return;
        }
        
        /* Recompute checksum */
        this_ip_hdr->ip_sum = 0x0000;
        uint16_t new_cksum = cksum(this_ip_hdr, sizeof(sr_ip_hdr_t));
        this_ip_hdr->ip_sum = new_cksum;
        
        /* Find out which interface to sent out the packet */
        struct sr_rt *this_route = longest_prefix_match(sr, this_ip_hdr->ip_dst);
        if (this_route == NULL) {
            /* Means not entry found for dest IP, send ICMP NET UNREACHABLE */
            printf("handle_ip_pkt: longest_prefix_match: No route to dest IP, sending ICMP NET UNREACHABLE.\n");
            send_icmp_t3(sr, packet, this_ip_hdr->ip_src, 0);
            return;
        }
        
        /* If route found */
        struct sr_if *out_if = sr_get_interface(sr, this_route->interface); /* get out interface */
        
        send_ip_pkt(sr, packet, len, out_if); /* send */
        
        return;
    }
    
}

void send_icmp_t11(struct sr_instance *sr,
                   uint8_t *orig_packet,
                   uint32_t dest, /* In net order */
                   uint8_t code)
{
    /*Allocate memory for new icmp packet */
    unsigned int ICMP_type11_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t *ICMP_type11_pkt = calloc(1, ICMP_type11_size);
    
    /* Prepare header. */
    sr_ip_hdr_t *ICMP_type11_ip_hdr = (sr_ip_hdr_t *)(ICMP_type11_pkt + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t11_hdr_t *ICMP_type11_ICMP_hdr = (sr_icmp_t11_hdr_t *)(ICMP_type11_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* Prepare source info */
    struct sr_rt *this_route = longest_prefix_match(sr, dest);
    if (this_route == NULL) {
        printf("send_icmp_t11: Can't reach destined IP.\n");
        free(ICMP_type11_pkt);
        return;
    }
    struct sr_if *out_if = sr_get_interface(sr, this_route->interface);
    
    /* Building IP header, need fix */
    ICMP_type11_ip_hdr->ip_v = 4;
    ICMP_type11_ip_hdr->ip_hl = 5;
    ICMP_type11_ip_hdr->ip_tos = 0;
    ICMP_type11_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    ICMP_type11_ip_hdr->ip_id = 0;
    ICMP_type11_ip_hdr->ip_off = 0 | 0b01000000;
    ICMP_type11_ip_hdr->ip_ttl = INIT_TTL;
    ICMP_type11_ip_hdr->ip_p = ip_protocol_icmp;
    ICMP_type11_ip_hdr->ip_sum = 0;
    ICMP_type11_ip_hdr->ip_src = out_if->ip;
    ICMP_type11_ip_hdr->ip_dst = dest;
    
    /* Compute cksum */
    uint16_t new_cksum = cksum(ICMP_type11_ip_hdr, sizeof(sr_ip_hdr_t));
    ICMP_type11_ip_hdr->ip_sum = new_cksum;
    
    /* Building ICMP header */
    ICMP_type11_ICMP_hdr->icmp_type = 11;
    ICMP_type11_ICMP_hdr->icmp_code = code;
    ICMP_type11_ICMP_hdr->icmp_sum = 0;
    ICMP_type11_ICMP_hdr->unused = 0;
    memcpy(ICMP_type11_ICMP_hdr->data, orig_packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
    
    
    /*Compute cksum */
    new_cksum = cksum(ICMP_type11_ICMP_hdr, sizeof(sr_icmp_t3_hdr_t));
    ICMP_type11_ICMP_hdr->icmp_sum = new_cksum;
    
    /* Send out */
    send_ip_pkt(sr, ICMP_type11_pkt, ICMP_type11_size, out_if);
    free(ICMP_type11_pkt);
    return;
}

void send_icmp_t3(struct sr_instance *sr,
                  uint8_t *orig_packet,
                  uint32_t dest, /* In net order */
                  uint8_t code)
{
    /*Allocate memory for new icmp packet */
    unsigned int ICMP_type3_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *ICMP_type3_pkt = calloc(1, ICMP_type3_size);
    
    /* Prepare header. */
    sr_ip_hdr_t *orig_pkt_ip_hdr = (sr_ip_hdr_t *)(orig_packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ICMP_type3_ip_hdr = (sr_ip_hdr_t *)(ICMP_type3_pkt + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *ICMP_type3_ICMP_hdr = (sr_icmp_t3_hdr_t *)(ICMP_type3_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* Prepare source info */
    struct sr_rt *this_route = longest_prefix_match(sr, dest);
    if (this_route == NULL) {
        printf("send_icmp_t3: Can't reach destined IP.\n");
        free(ICMP_type3_pkt);
        return;
    }
    struct sr_if *out_if = sr_get_interface(sr, this_route->interface);
    
    /* Building IP header, need fix */
    ICMP_type3_ip_hdr->ip_v = 4;
    ICMP_type3_ip_hdr->ip_hl = 5;
    ICMP_type3_ip_hdr->ip_tos = 0;
    ICMP_type3_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ICMP_type3_ip_hdr->ip_id = 0;
    ICMP_type3_ip_hdr->ip_off = 0 | 0b01000000;
    ICMP_type3_ip_hdr->ip_ttl = INIT_TTL;
    ICMP_type3_ip_hdr->ip_p = ip_protocol_icmp;
    ICMP_type3_ip_hdr->ip_sum = 0;
    /* sources ip address are handle differely for different Code */
    switch (code) {
        case 0:
            ICMP_type3_ip_hdr->ip_src = out_if->ip;
            break;
        case 1:
            ICMP_type3_ip_hdr->ip_src = out_if->ip;
            break;
        case 3:
            ICMP_type3_ip_hdr->ip_src = orig_pkt_ip_hdr->ip_dst;
            break;
        default:
            printf("send_icmp_t3: code: %d, can't be handle.\n", code);
            free(ICMP_type3_pkt);
            return;
    }
    /* Set dest */
    ICMP_type3_ip_hdr->ip_dst = dest;
    
    /* Compute cksum */
    uint16_t new_cksum = cksum(ICMP_type3_ip_hdr, sizeof(sr_ip_hdr_t));
    ICMP_type3_ip_hdr->ip_sum = new_cksum;
    
    /* Building ICMP header */
    ICMP_type3_ICMP_hdr->icmp_type = 3;
    ICMP_type3_ICMP_hdr->icmp_code = code;
    ICMP_type3_ICMP_hdr->icmp_sum = 0;
    ICMP_type3_ICMP_hdr->unused = 0;
    ICMP_type3_ICMP_hdr->next_mtu = 0;
    memcpy(ICMP_type3_ICMP_hdr->data, orig_packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
    
    
    /*Compute cksum */
    new_cksum = cksum(ICMP_type3_ICMP_hdr, sizeof(sr_icmp_t3_hdr_t));
    ICMP_type3_ICMP_hdr->icmp_sum = new_cksum;
    
    /* Send out */
    send_ip_pkt(sr, ICMP_type3_pkt, ICMP_type3_size, out_if);
    free(ICMP_type3_pkt);
    return;
    
}

void send_echo(struct sr_instance *sr,
               uint8_t *request,
               unsigned int len)
{
    uint8_t *echo = malloc(len);
    memcpy(echo, request, len);
    
    /* Prepare header */
    sr_ip_hdr_t *request_ip_hdr = (sr_ip_hdr_t *)(request + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *echo_ip_hdr = (sr_ip_hdr_t *)(echo + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *echo_icmp_hdr = (sr_icmp_hdr_t *)(echo + sizeof(sr_ethernet_hdr_t)
                                                     + (echo_ip_hdr->ip_hl * 4));
    
    /* Prepare source info */
    struct sr_rt *this_route = longest_prefix_match(sr, request_ip_hdr->ip_src);
    if (this_route == NULL) {
        printf("send_icmp: Can't reach destined IP.\n");
        free(echo);
        return;
    }
    struct sr_if *out_if = sr_get_interface(sr, this_route->interface);
    
    /* Building IP header */
    echo_ip_hdr->ip_ttl = INIT_TTL;
    echo_ip_hdr->ip_sum = 0;
    echo_ip_hdr->ip_dst = request_ip_hdr->ip_src;
    echo_ip_hdr->ip_src = request_ip_hdr->ip_dst;
    
    /* Compute cksum */
    uint16_t new_cksum = cksum(echo_ip_hdr, echo_ip_hdr->ip_hl * 4);
    echo_ip_hdr->ip_sum = new_cksum;
    
    /* Building ICMP header */
    echo_icmp_hdr->icmp_type = 0;
    echo_icmp_hdr->icmp_sum = 0;
    
    /* Compute cksum */
    new_cksum = cksum(echo_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - (echo_ip_hdr->ip_hl * 4));
    echo_icmp_hdr->icmp_sum = new_cksum;
    
    printf("ECHO Packet: \n");
    print_hdr_icmp(echo_icmp_hdr);
    print_hdr_ip(echo_ip_hdr);
    
    /* Send out */
    send_ip_pkt(sr, echo, len, out_if);
    free(echo);
    return;
    
}

void send_icmp(struct sr_instance *sr,
               uint32_t dest, /* In net order */
               uint8_t type,
               uint8_t code)
{
    /* Can't process type 3 */
    if (type == 3) {
        printf("send_icmp: can't process type 3 request.\n");
        return;
    }
    
    /* Allocate memory */
    unsigned int ICMP_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t *ICMP_pkt = malloc(ICMP_size);
    
    /* Prepare header. */
    sr_ip_hdr_t *ICMP_ip_hdr = (sr_ip_hdr_t *)(ICMP_pkt + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *ICMP_ICMP_hdr = (sr_icmp_hdr_t *)(ICMP_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* Prepare source info */
    struct sr_rt *this_route = longest_prefix_match(sr, dest);
    if (this_route == NULL) {
        printf("send_icmp: Can't reach destined IP.\n");
        free(ICMP_pkt);
        return;
    }
    struct sr_if *out_if = sr_get_interface(sr, this_route->interface);

    /* Building IP header */
    ICMP_ip_hdr->ip_v = 4;
    ICMP_ip_hdr->ip_hl = 5;
    ICMP_ip_hdr->ip_tos = 0;
    ICMP_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    ICMP_ip_hdr->ip_id = 0;
    ICMP_ip_hdr->ip_off = 0 | 0b01000000;
    ICMP_ip_hdr->ip_ttl = INIT_TTL;
    ICMP_ip_hdr->ip_p = ip_protocol_icmp;
    ICMP_ip_hdr->ip_sum = 0;
    ICMP_ip_hdr->ip_src = out_if->ip;
    ICMP_ip_hdr->ip_dst = dest;
    
    /* Compute cksum */
    uint16_t new_cksum = cksum(ICMP_ip_hdr, ICMP_ip_hdr->ip_hl * 4);
    ICMP_ip_hdr->ip_sum = new_cksum;
    
    /* Building ICMP header */
    ICMP_ICMP_hdr->icmp_type = type;
    ICMP_ICMP_hdr->icmp_code = code;
    ICMP_ICMP_hdr->icmp_sum = 0;
    
    /* Compute cksum */
    new_cksum = cksum(ICMP_ICMP_hdr, sizeof(sr_icmp_hdr_t));
    ICMP_ICMP_hdr->icmp_sum = new_cksum;
    
    printf("ICMP Packet: \n");
    print_hdr_icmp(ICMP_ICMP_hdr);
    print_hdr_ip(ICMP_ip_hdr);
    
    /* Send out */
    send_ip_pkt(sr, ICMP_pkt, ICMP_size, out_if);
    free(ICMP_pkt);
    return;
}

struct sr_rt *longest_prefix_match (struct sr_instance *sr,
                                    uint32_t ip)
{
    /* Longest prefix match */
    struct sr_rt *walker = sr->routing_table;
    struct sr_rt *result = NULL;
    
    /* walk though rt to find longest match prefix */
    while (walker != NULL) {
        if ((walker->dest.s_addr & walker->mask.s_addr) == (ip & walker->mask.s_addr)) {
            if (result == NULL) {
                result = walker;
            }
            if (walker->mask.s_addr > result->mask.s_addr) {
                result = walker;
            }
        }
        
        walker = walker->next; /*update */
    }
    
    return result;
}

void send_ip_pkt(struct sr_instance *sr,
                uint8_t *packet, /* Will not free */
                unsigned int len,
                struct sr_if *out_if)
{
    /* Prepare header */
    sr_ip_hdr_t *this_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *this_eth_hdr = (sr_ethernet_hdr_t *)packet;
    
    /* Find out coresponding MAC address and interface with this IP */
    struct sr_arpentry *this_arpentry = sr_arpcache_lookup(&sr->cache, this_ip_hdr->ip_dst);
    
    if (this_arpentry == NULL || this_arpentry->valid == 0) {
        /* No arpentry found */
        printf("send_ip_pkt: No arpentry found, add IP packet to req queue.\n");
        this_eth_hdr->ether_type = htons(ethertype_ip);
        sr_arpcache_queuereq(&sr->cache, this_ip_hdr->ip_dst, packet, len, out_if->name);
        return;
        
    } else {
        /* MAC addr in cache, directly send */
        /* Build ether header */
        memcpy(this_eth_hdr->ether_dhost, this_arpentry->mac, ETHER_ADDR_LEN);
        memcpy(this_eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
        this_eth_hdr->ether_type = htons(ethertype_ip);
        /* Send */
        sr_send_packet(sr, packet, len, out_if->name);
        return;
    }
    
    
}


