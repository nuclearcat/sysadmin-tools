/**********************************************************************
* Not completed yet!
* Compile with:
* gcc -Wall -pedantic pcap_main.c -lpcap (-o foo_err_something)
*
**********************************************************************/
#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>


#define TZSP_PORT 1000

struct tzsp_header {
        uint8_t version;
        uint8_t type;
        uint16_t encapsulated_protocol;
} __attribute__ ((packed));

int open_tun(char *name)
{
        int fd, tun_fd;
        struct ifreq ifr;

        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("socket() failed");
                return 1;
        }
        if ( (tun_fd = open("/dev/net/tun",O_RDWR)) < 0)
        {
                perror("open_tun: /dev/net/tun error");
                return 1;
        }

        memset(&ifr, 0x0, sizeof(ifr));

        ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
        if (name[0] != 0)
                strncpy(ifr.ifr_name, name, IFNAMSIZ);
        else
                strncpy(ifr.ifr_name, "eoip%d", IFNAMSIZ);

        if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
                perror("ioctl-1");
                close(fd);
                return 1;
        }

        ifr.ifr_flags |= IFF_UP;
        ifr.ifr_flags |= IFF_RUNNING;

        if (ioctl(fd, SIOCSIFFLAGS, (void *)&ifr) < 0) {
                perror("ioctl-2");
                close(fd);
                return 1;
        }

        close(fd);
        return (tun_fd);
}


int main(int argc,char **argv)
{
        int sock, len, tun_fd;
        char buffer[4096];
        struct sockaddr_in si_me;
        int debug = 0;

        if (argc != 3 && argc != 4) {
                printf("%s ifname port [debug]\n", argv[0]);
                printf("Specify 1(or anything else) as debug if you want to not fork and get debug output, for example '%s ifname port 1'\n", argv[0]);
                exit(0);
        }

        if (argc == 4)  {
          debug = 1;
          printf("[DEBUG] enabled\n");
        }
        if (!debug)
          daemon(1, 1);

        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        /* Set initialize address/port */
        memset((char *) &si_me, 0, sizeof(si_me));
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(atoi(argv[2]));
        si_me.sin_addr.s_addr = htonl(INADDR_ANY);

        /* Bind to specified address/port */
        if (bind(sock, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
                perror("bind");
                close(sock);
                return 0;
        }

        tun_fd = open_tun(argv[1]);
        if (tun_fd == -1) {
                perror("tun opening");
                exit(1);
        }
        while(1) {
                len = recv(sock, buffer, 4096, 0);
                if (len > 5) {
                        if (debug)
                          printf("[DEBUG] Received %d bytes, pushing to tun\n", len);

                        write(tun_fd, buffer+5, len-5);
                } else {
                  if (debug)
                    printf("[DEBUG] Received too short packet %d bytes\n", len);
                }
        }
}
