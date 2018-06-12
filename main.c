#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <netpacket/packet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <fcntl.h>

#include "ifinfo.h"

#define DEFAULT_IF "enp0s8"
#define ETHER_TYPE 0x0801 /* custom type */
#define BUF_SIZE (ETH_FRAME_LEN)
#define MSG_SIZE 900

static char broadcast_addr[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
struct if_infos *if_info = NULL;

void ip_print_format(char *ipaddr, char* ip_buf){
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
}

void netmask_print_format(char *netmask, char *netmask_buf){
	char *ip[4];
    char *_ip = strtok(netmask, ".");
    int i = 0, ip_int[4];

    while(_ip != NULL){
        ip[i++] = _ip;
        _ip = strtok(NULL, ".");
    }
    for(i = 0; i < 4; i++)
        ip_int[i] = atoi(ip[i]);

	sprintf(netmask_buf, "0x%02x%02x%02x%02x", ip_int[0], ip_int[1], ip_int[2], ip_int[3]);
}

void add_to_ifinfo(struct ifaddrs *ifap, char *buf){
	struct sockaddr_ll *s;
	struct if_infos *p, *q;
	void *tempAddrPtr = NULL;
    int i;

	if (if_info == NULL){ // if_info is empty
		if_info = malloc(sizeof(struct if_infos));

		if (if_info == NULL) {
			fprintf (stderr, "malloc failed\n");
			exit(EXIT_FAILURE);
		}

		if_info->next = NULL;
		if_info->ip_addr[0] = '\0';
		if_info->broadcast_addr[0] = '\0';
		if_info->netmask_addr[0] = '\0';
		if_info->hd_addr[0] = '\0';

		strcpy(if_info->if_name, ifap->ifa_name);

		switch(ifap->ifa_addr->sa_family) {
          case AF_INET:
                strcpy(if_info->ip_addr, buf);
				// netmask address
				if(ifap->ifa_netmask != NULL){
               	 	inet_ntop(ifap->ifa_netmask->sa_family,
                        	  &((struct sockaddr_in *)ifap->ifa_netmask)->sin_addr,
                         	  if_info->netmask_addr,
                         	  sizeof(if_info->netmask_addr));
	      		}
				// broadcast address
				if(ifap->ifa_ifu.ifu_broadaddr != NULL){
	        		if(ifap->ifa_flags & IFF_POINTOPOINT){ /* If the ifa_flags field indicates that this is a P2P interface  do nothing */ }
					else {
		      			if(ifap->ifa_ifu.ifu_broadaddr->sa_family == AF_INET)
							inet_ntop(ifap->ifa_ifu.ifu_broadaddr->sa_family,
								   	  &((struct sockaddr_in *)ifap->ifa_ifu.ifu_broadaddr)->sin_addr,
								 	  if_info->broadcast_addr,
								 	  sizeof(if_info->broadcast_addr));
	        		}
				}
                break;
          case AF_PACKET:
                s = (struct sockaddr_ll *)ifap->ifa_addr;
                if_info->if_idx = s->sll_ifindex;
                strcpy(if_info->hd_addr_str, buf);
                for(i = 0; i<6; i++)
                    if_info->hd_addr[i] = s->sll_addr[i];
                break;
          default:
                break;
        } //switch

	} else {
		for(p = if_info; p != NULL; p = p->next){
			q = p;
			if (strcmp(p->if_name, ifap->ifa_name) == 0) break;
		}

		if (p != NULL) { // find the match interface name
            switch (ifap->ifa_addr->sa_family) {
                case AF_INET:
                    strcpy(p->ip_addr, buf);

					if(ifap->ifa_netmask != NULL){
	               	 	inet_ntop(ifap->ifa_netmask->sa_family,
	                        	  &((struct sockaddr_in *)ifap->ifa_netmask)->sin_addr,
	                         	  p->netmask_addr,
	                         	  sizeof(p->netmask_addr));
		      		}

					if(ifap->ifa_ifu.ifu_broadaddr != NULL){
		        		if(ifap->ifa_flags & IFF_POINTOPOINT){ /* If the ifa_flags field indicates that this is a P2P interface  do nothing */ }
						else {
			      			if(ifap->ifa_ifu.ifu_broadaddr->sa_family == AF_INET)
								inet_ntop(ifap->ifa_ifu.ifu_broadaddr->sa_family,
									   	  &((struct sockaddr_in *)ifap->ifa_ifu.ifu_broadaddr)->sin_addr,
									 	  p->broadcast_addr,
									 	  sizeof(p->broadcast_addr));
		        		}
					}
                    break;
                case AF_PACKET:
                    s = (struct sockaddr_ll *)ifap->ifa_addr;
                    p->if_idx = s->sll_ifindex;
                    strcpy(p->hd_addr_str, buf);
                    for(i = 0; i<6; i++)
                        p->hd_addr[i] = s->sll_addr[i];
                    break;
                default:
                    break;
                } //switch
        } else {
			p = malloc(sizeof(struct if_infos));

			if (p == NULL) {
                fprintf(stderr, "malloc failled");
                exit(EXIT_FAILURE);
            }

            /* init node */
			p->next = NULL;
			p->ip_addr[0] = '\0';
			p->broadcast_addr[0] = '\0';
			p->netmask_addr[0] = '\0';
			p->hd_addr[0] = '\0';

            strcpy(p->if_name, ifap->ifa_name);

            switch(ifap->ifa_addr->sa_family) {
                case AF_INET:
                    strcpy(p->ip_addr, buf);
					// netmask address
					if(ifap->ifa_netmask != NULL){
						// tempAddrPtr =
	               	 	inet_ntop(ifap->ifa_netmask->sa_family,
	                        	  &((struct sockaddr_in *)ifap->ifa_netmask)->sin_addr,
	                         	  p->netmask_addr,
	                         	  sizeof(p->netmask_addr));
		      		}

					if(ifap->ifa_ifu.ifu_broadaddr != NULL){
		        		if(ifap->ifa_flags & IFF_POINTOPOINT){ /* If the ifa_flags field indicates that this is a P2P interface  do nothing */ }
						else {
			      			if(ifap->ifa_ifu.ifu_broadaddr->sa_family == AF_INET)
								inet_ntop(ifap->ifa_ifu.ifu_broadaddr->sa_family,
									   	  &((struct sockaddr_in *)ifap->ifa_ifu.ifu_broadaddr)->sin_addr,
									 	  p->broadcast_addr,
									 	  sizeof(p->broadcast_addr));
		        		}
					}
                    break;
                case AF_PACKET:
                    s = (struct sockaddr_ll *)ifap->ifa_addr;
                    p->if_idx = s->sll_ifindex;
                    strcpy(p->hd_addr_str, buf);
                    for(i = 0; i<6; i++)
                        p->hd_addr[i] = s->sll_addr[i];
                    break;
                default:
                    break;
            }
            q->next = p;
        } //else
	}
}

int get_if_addr(struct sockaddr *ifa_addr, char *buf, int bufsize){
    memset(buf, 0, bufsize);
    struct sockaddr_ll *s;
    int i, len;
    int family = ifa_addr->sa_family;
    int ret = 0;

    switch (family) {
        case AF_INET:
			// get ip addr
            inet_ntop(ifa_addr->sa_family, &((struct sockaddr_in *)ifa_addr)->sin_addr,
                      buf, sizeof (struct sockaddr_in));
			// get netmask addr
            break;
        case AF_PACKET:
			// get hw addr
			s = (struct sockaddr_ll *)ifa_addr;
            for (i=0,len=0; i<6; i++)
                len += sprintf(buf+len, "%02x%s", s->sll_addr[i], i<5?":":" ");
            break;
        default:
            ret = -1;
    }

    return ret;
}

void get_if_informations(){
	struct ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;
	void *tempAddrPtr = NULL;

	int rc = 0, i;
	char buf[20];

	rc = getifaddrs(&interfaceArray);  /* retrieve the current interfaces */
	if (rc == 0){
    	for(tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next){
			if(strcmp(tempIfAddr->ifa_name, "lo") == 0) continue;
			if(tempIfAddr->ifa_addr == NULL) continue;

			if(get_if_addr(tempIfAddr->ifa_addr, buf, 20) == 0){
				add_to_ifinfo(tempIfAddr, buf);
			}

    	}

		// /* free link list */
	    // struct if_infos *q = NULL;
	    // for (p = if_info; p != NULL; ) {
	    //     q = p;
	    //     p = p->next;
	    //     free (q);
	    // }

    	freeifaddrs(interfaceArray);             /* free the dynamic memory */
    	interfaceArray = NULL;                   /* prevent use after free  */
  	} else {
     	printf("getifaddrs() failed with errno =  %d %s \n", errno, strerror(errno));
  	}
}

void show_if_informations(){
    /* printf all of them */
    struct if_infos *p = NULL;
    printf("Enumerated network interfaces:\n");
    for (p = if_info; p != NULL; p = p->next){
        if(strlen(p->ip_addr) > 0){
            char ip_buf[16], broad_buf[16], netmask_buf[10];
            ip_print_format(p->ip_addr, ip_buf);
            ip_print_format(p->broadcast_addr, broad_buf);
            netmask_print_format(p->netmask_addr, netmask_buf);
            printf("%d - %-10s %s %s (%s) %s\n", if_nametoindex(p->if_name), p->if_name, ip_buf, netmask_buf, broad_buf, p->hd_addr_str);
        }
    }
}

size_t create_raw_packet(struct if_infos *if_info, char *buf, char *start_msg, char *msg){
    /* Construct ehternet header. */
    int i;
    size_t eth_len;
    struct ether_header *eh;

    /* Ethernet header */
    eh = (struct ether_header *) buf;

    memcpy(eh->ether_shost, if_info->hd_addr, ETH_ALEN);
    memcpy(eh->ether_dhost, broadcast_addr, ETH_ALEN);
    eh->ether_type = htons(ETHER_TYPE);

    eth_len = sizeof(*eh);

    /* Fill the packet data. */
    for(i = 0; start_msg[i] != '\0'; i++)
        buf[eth_len++] = start_msg[i];
    for(i = 0; msg[i] != '\0'; i++)
        buf[eth_len++] = msg[i];

    return eth_len;
}

void read_raw_packet(int sock){
    char buf[BUF_SIZE];
    struct ether_header *eh = (struct ether_header *) buf;
    ssize_t received;
    char *p;
    int i;

    received = recvfrom(sock, buf, BUF_SIZE, 0, NULL, NULL);

    /* Receive only destination address is broadcast. */
    if(memcmp (eh->ether_dhost, broadcast_addr, ETH_ALEN) != 0)
        return;

    fprintf(stdout,
            "<%02x:%02x:%02x:%02x:%02x:%02x> ",
            eh->ether_shost[0],
            eh->ether_shost[1],
            eh->ether_shost[2],
            eh->ether_shost[3],
            eh->ether_shost[4],
            eh->ether_shost[5]
            );

    received -= sizeof (*eh);
    p = buf + sizeof (*eh);

    for(i = 0; i < received; i++)
        fputc(p[i], stdout);
}


int main(int argc, char *argv[]){
	char if_name[IFNAMSIZ];
	char name[20], name_buf[25];
    char buf[BUF_SIZE];
	char msg[MSG_SIZE];
    size_t eth_len;
    struct sockaddr_ll sll;
	int sock, i, flags;

	get_if_informations();
    show_if_informations();

	printf("Enter your name: ");
    scanf("%s", name);
    printf("Welcome, '%s'!\n", name);
    sprintf(name_buf, "[%s]: ", name);

    /* Create the AF_PACKET socket. */
    if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1)
        perror("socket()");

    // set sock to non-blocking.
    flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // set stdin to non-blocking.
    flags = fcntl(fileno(stdin), F_GETFL, 0);
    if (flags != -1) fcntl(fileno(stdin), F_SETFL, flags | O_NONBLOCK);

    // Find the interface
    int find = 0;
    struct if_infos *q = NULL;
    for (q = if_info; q != NULL; q = q->next){
        if(strcmp(q->if_name, DEFAULT_IF) == 0) { find = 1; break; }
    }

    if(!find){
        perror("Default interface not found!");
        return -1;
    }

    struct ifreq ifr;
    int s;

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, q->if_name, IFNAMSIZ - 1);

    /* Set interface to promiscuous mode. */
    if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
        perror ("SIOCGIFFLAGS");

    ifr.ifr_flags |= IFF_PROMISC;
    if(ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
        perror ("SIOCSIFFLAGS");

    /* Allow the socket to be reused. */
    s = 1;
    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &s, sizeof(s)) < 0){
        perror ("SO_REUSEADDR");
        close (sock);
        return EXIT_FAILURE;
    }

    /* Bind to device. */
    if (setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE, q->if_name, IFNAMSIZ - 1) < 0){
        perror ("SO_BINDTODEVICE");
        close (sock);
        return EXIT_FAILURE;
    }

    fd_set rfds;
    fd_set wfds;
    int nfds, ready = 0, len = 0;

    memset(buf, 0, BUF_SIZE);
    memset(msg, 0, MSG_SIZE);
    
    while(1){
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        FD_SET(sock, &rfds);
        FD_SET(sock, &wfds);

        nfds = sock;

        if(select(nfds + 1, &rfds, &wfds, NULL, NULL) < 0) {
            perror("select");
            return -1;
        }

        if(FD_ISSET(sock, &rfds))
            read_raw_packet(sock);

        if(FD_ISSET(sock, &wfds)){
            if(!ready){
                write(1, ">>> ", 4);
                ready = 1;
            } else {
                if((read(0, msg, MSG_SIZE)) > 0){
                    eth_len = create_raw_packet(q, buf, name_buf, msg);

                    sll.sll_family = AF_PACKET;
                    sll.sll_halen = ETH_ALEN;
                    sll.sll_ifindex = q->if_idx;
                    sll.sll_protocol = htons(ETHER_TYPE);
                    memcpy(sll.sll_addr, broadcast_addr, ETH_ALEN);

                    if(sendto(sock, buf, eth_len, 0, (struct sockaddr *) &sll, sizeof(sll)) < 0)
                        perror ("sendto()");

                    // Reset after sending the message
                    ready = 0;
                    memset(msg, 0, MSG_SIZE);
                    memset(buf, 0, BUF_SIZE);
                }
            }
        }
    }

    close (sock);
    return 0;
}
