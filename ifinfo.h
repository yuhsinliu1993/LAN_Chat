#ifndef _IFINFO_H
#define _IFINFO_H
#include <stdlib.h>
#include <errno.h>

#define error_report(msg) \
    do { perror(msg); \
        exit (EXIT_FAILURE) \
    } while (0)


/* define a get if info struct */
struct if_infos {
    int if_idx;
    char if_name[10];
    unsigned char ip_addr[16];
    unsigned char broadcast_addr[16];
    unsigned char netmask_addr[16];
    unsigned char hd_addr_str[20];
    u_int8_t hd_addr[6];

    struct if_infos *next;
};

#endif
