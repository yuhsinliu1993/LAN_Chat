#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "mylib.h"

struct if_info *ifinfo = NULL;

void ip_print_format(char *ipaddr, char* ip_buf, char* broad_buf){
    char *ip[4];
    char *_ip = strtok(ipaddr, ".");
    int i = 0, ip_int[4];

    while(_ip != NULL){
        ip[i++] = _ip;
        _ip = strtok(NULL, ".");
    }
    for(i = 0; i < 4; i++)
        ip_int[i] = atoi(ip[i]);

    sprintf(ip_buf, "%03d.%03d.%03d.%03d", ip_int[0], ip_int[1], ip_int[2], ip_int[3]);
    // sprintf(broad_buf, "%03d.%03d.%03d.255", ip_int[0], ip_int[1], ip_int[2]);
}

static int add_to_link(struct ifaddrs *ifap, char *buf){
    struct if_info *p, *q;
    struct sockaddr_ll *s;

    if (ifinfo == NULL) {
        ifinfo = malloc (sizeof (struct if_info));
        /* init head */
        ifinfo->next = NULL;
        ifinfo->ip_addr[0] = '\0';
        ifinfo->hd_addr[0] = '\0';

        if (ifinfo == NULL) {
            fprintf (stderr, "malloc failed\n");
            exit(EXIT_FAILURE);
        }

        strcpy(ifinfo->if_name, ifap->ifa_name);
        printf("%s\n", ifap->ifa_broadaddr);
        switch (ifap->ifa_addr->sa_family) {
          case AF_INET:
                strcpy(ifinfo->ip_addr, buf);
                // printf ("head %s\n", ifinfo->ip_addr);
                break;
          case AF_PACKET:
                s = (struct sockaddr_ll *)ifap->ifa_addr;
                ifinfo->if_idx = s->sll_ifindex;
                strcpy(ifinfo->hd_addr, buf);
                // printf ("head %s\n", ifinfo->hd_addr);
                break;
          default:
                break;
        } //switch
    } else {
        for (p = ifinfo; p != NULL; p = p->next) {
            q = p;
            if (strcmp(p->if_name, ifap->ifa_name) == 0) {
                break;
            }
        }

        if (p != NULL) {
            switch (ifap->ifa_addr->sa_family) {
                case AF_INET:
                    strcpy (p->ip_addr, buf);
                    //   printf ("p %s\n", p->ip_addr);
                    break;
                case AF_PACKET:
                    s = (struct sockaddr_ll *)ifap->ifa_addr;
                    ifinfo->if_idx = s->sll_ifindex;
                    strcpy (p->hd_addr, buf);
                    //  printf ("p %s\n", p->hd_addr);
                    break;
                default:
                    break;
                } //switch
        } else {
            p = malloc (sizeof (struct if_info));
            /* init node */
            p->next = NULL;
            p->ip_addr[0] = '\0';
            p->hd_addr[0] = '\0';

            if (p == NULL) {
                fprintf(stderr, "malloc failled");
                exit(EXIT_FAILURE);
            }

            strcpy (p->if_name, ifap->ifa_name);

            switch (ifap->ifa_addr->sa_family) {
                case AF_INET:
                    strcpy (p->ip_addr, buf);
                    // printf ( "else p %s\n", p->ip_addr);
                    break;
                case AF_PACKET:
                    s = (struct sockaddr_ll *)ifap->ifa_addr;
                    ifinfo->if_idx = s->sll_ifindex;
                    strcpy (p->hd_addr, buf);
                    //printf ( "else p %s\n", p->hd_addr);
                    break;
                default:
                    break;
            }
            q->next = p;
        } //else
    }

    return 0;
}

int prt_if_info(struct sockaddr *ifa_addr, char *addrbuf, int bufsize){
    memset (addrbuf, 0, bufsize);
    struct sockaddr_ll *s;
    int i, len;
    int family = ifa_addr->sa_family;
    int ret = 0;

    switch (family) {
        case AF_INET:
            inet_ntop(ifa_addr->sa_family, &((struct sockaddr_in *)ifa_addr)->sin_addr,
                      addrbuf, sizeof (struct sockaddr_in));
            break;
        case AF_PACKET:

            for (i=0,len=0; i<6; i++) {
                len += sprintf(addrbuf+len, "%02x%s", s->sll_addr[i], i<5?":":" ");
                printf("%02x ",s->sll_addr[i]);
            }
            break;
        default:
            ret = -1;
    }

    return ret;
}

void get_if_info(){
    struct ifaddrs *ifa, *ifap;
    int family;  /* protocl family */

    if (getifaddrs(&ifa) == -1) {
        perror (" getifaddrs\n");
        exit (EXIT_FAILURE);
    }

    char buf[20];
    void * tmpAddrPtr=NULL;

    for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {

        if(strcmp(ifap->ifa_name, "lo") == 0)
            continue; /* skip the lookback card */

        if(ifap->ifa_addr == NULL)
            continue; /* if addr is NULL, this must be no ip address */


        if(prt_if_info(ifap->ifa_addr, buf, 20) == 0) {
            printf("%s: %s\n", ifap->ifa_name, buf);
            add_to_link(ifap, buf);
        }
    }

    /* printf all of them */
    printf("Enumerated network interfaces:\n");
    struct if_info *p = NULL;
    for (p = ifinfo; p != NULL; p = p->next){
        if (strlen(p->ip_addr) > 0){
            char ip_buf[16], broad_buf[16];
            ip_print_format(p->ip_addr, ip_buf, broad_buf);
            printf("%d - %-10s %s 0xffffff00 (%s) %s\n", p->if_idx, p->if_name, ip_buf, broad_buf, p->hd_addr);
        } else {
            printf("%d - %s: (No IP address) 0xffffff00 %s\n", p->if_idx, p->if_name, p->hd_addr);
        }
    }

    /* free link list */
    struct if_info *q = NULL;
    for (p = ifinfo; p != NULL; ) {
        q = p;
        p = p->next;
        free (q);
    }

    freeifaddrs (ifa);
}

int main (int argc, char *argv[]) {
    char name[20];

    get_if_info();
    // printf("Enter your name: ");
    // scanf("%s", name);
    //
    // printf("Welcome, '%s'!\n", name);

    return 0;
}
