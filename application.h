#ifndef __APPLICATION_H
#define __APPLICATION_H

#include <stdint.h>

//structures dns et bootp
struct dnshdr
{
    uint16_t query_id;
    uint16_t flags;
    uint16_t quest_count;
    uint16_t answ_count;
    uint16_t auth_count;
    uint16_t add_count;
};

struct bootphdr
{
    uint8_t msg_type;
    uint8_t hrdwr_type;
    uint8_t hrdwr_addr_length;
    uint8_t hops;
    uint32_t trans_id;
    uint16_t num_sec;
    uint16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    __u_char hrdwr_caddr[16];
    __u_char srv_name[64];
    __u_char bpfile_name[128];
    uint32_t magic_cookie;
};

//affiche (dump) le contenu de divers paquets applicatifs (d'autres peuvent être implémentés)
void bootp_view(const __u_char*, int);
void dns_view(const __u_char*, int);
void http_view(const __u_char*, int);
void ftp_view(const __u_char*, int);
void smtp_view(const __u_char*, int);
void pop_view(const __u_char*, int);
void imap_view(const __u_char*, int);
void telnet_view(const __u_char*, int);

#endif