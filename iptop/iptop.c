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
#include <math.h>
#include "uthash.h"

#define ETHERTYPE_PPPOE_SESSION 0x8864
#define PPPOE_SIZE              22
#define HASHSIZE		0xFFFFF /* Must be power of 2 */

int sortby;
int pairs_total = 0;
struct timeval tv1;
int mask_val = 0xFFFFFFFF;

struct ippairs {
    u_int32_t addr;
    struct ippairs *next;
    uint32_t bytes;
    uint32_t packets;
    UT_hash_handle hh;
};

struct ippairs *pairs = NULL;
int packets, packetstrigger;
unsigned long long packetstotal,bytes;

const int offset[2] = {offsetof(struct iphdr,daddr)/sizeof(u_int32_t), offsetof(struct iphdr,saddr)/sizeof(u_int32_t) };

static int find_ip_eth(char* buf)
{
    unsigned short ppp_proto_type; /* the protocol type field of the PPP header */
    unsigned short eth_proto_type; /* the protocol type field of the Ethernet header */
    int offset = -1;               /* the calculated offset that this function will return */

    memcpy(&eth_proto_type, buf+12, 2);
    eth_proto_type = ntohs(eth_proto_type);
    switch (eth_proto_type)
    {
    case ETHERTYPE_IPV6: /* it's pure IPv6 over ethernet */
        offset = 14;
        break;
    case ETHERTYPE_IP: /* it's pure IPv4 over ethernet */
        offset = 14;
        break;
    case ETHERTYPE_PPPOE_SESSION: /* it's a PPPoE session */
        memcpy(&ppp_proto_type, buf+20, 2);
        ppp_proto_type = ntohs(ppp_proto_type);
        if (ppp_proto_type == 0x0021) /* it's IP over PPPoE */
            offset = PPPOE_SIZE;
        break;
    default: /* well, this is not an IP packet */
        //			printf("Ethertype %0x\n",eth_proto_type);
        offset = -1;
        break;
    }
    return offset;
}

void add_ip(struct iphdr *ip,unsigned int bytes,int dir) {
    const u_int32_t ipaddr = ((u_int32_t*)ip)[offset[dir]];
    struct ippairs *found = NULL;

    HASH_FIND_INT( pairs, &ipaddr, found );

    if (found) {
        found->packets++;
        found->bytes+=bytes;
    } else {
        pairs_total++;
        found = malloc(sizeof(struct ippairs));
        memset(found,0x0,sizeof(struct ippairs));
        found->packets++;
        found->bytes+=bytes;
        //ip &= mask_val;
        found->addr = ipaddr & mask_val;
        HASH_ADD_INT( pairs, addr, found );
    }

}

int compare_bytes (const void * a, const void * b)
{
    struct ippairs *px, *py;

    px = (struct ippairs *)a;
    py = (struct ippairs *)b;

    return ( px->bytes - py->bytes );
}

int compare_packets (const void * a, const void * b)
{
    struct ippairs *px, *py;

    px = (struct ippairs *)a;
    py = (struct ippairs *)b;

    return ( px->packets - py->packets );
}

long timevaldiff(struct timeval *starttime, struct timeval *finishtime)
{
    long msec;

    msec =  (finishtime->tv_sec-starttime->tv_sec)*1000;
    msec += (finishtime->tv_usec-starttime->tv_usec)/1000;

    return msec;
}

void show_stat (void) {
    struct ippairs *found = NULL;
    long timediff;
    struct timeval tv2;
    struct in_addr s_addr;
    char ipbuf[16];
    char *ntoaptr;
    int len, i;

    gettimeofday(&tv2, NULL);

    timediff = timevaldiff(&tv1, &tv2);

    printf("\033c");

    if (sortby == 0 || sortby == 2)
        HASH_SORT(pairs, compare_bytes);
    else if (sortby == 1)
        HASH_SORT(pairs, compare_packets);

    i = 0;
    for(found=pairs; found != NULL; found=found->hh.next) {
        i++;
        memset(ipbuf,0x20,16);
        ipbuf[15] = 0x0;
        s_addr.s_addr = (in_addr_t)found->addr;
        ntoaptr = inet_ntoa(s_addr);
        if (!ntoaptr) {
            perror("inet_ntoa()");
            exit(1);
        }
        len = strlen(ntoaptr);
        strncpy(ipbuf,ntoaptr,len);
        // Show last 10
        if (i > (pairs_total - 30))
            printf("%s %db %dp avg %db %llu%%b %llu%%p %llu Kbit/s\n",ipbuf,found->bytes,found->packets,(found->bytes/found->packets),found->bytes*100/bytes,found->packets*100/packetstotal,((uint64_t)found->bytes*8/(uint64_t)timediff));
    }
    printf("Average packet size %llu (with ethernet header, max avg sz 1514)\n",bytes/packetstotal);
    printf("Time %ld, total bytes %lld, total speed %lld Kbit/s\n",timediff,bytes,bytes*8*1000/timediff/1024);
}

/*
 * workhorse function, we will be modifying this function
 */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    struct iphdr *ip; /* The IP header */
    //    struct tcphdr *tcp; /* The IP header */
    static int offset;
    //    static int iphash;
    int dir = (int) *args;

    packetstotal++;
    if (((double)(packetstotal) / (double)packets) == (double)(packetstotal/packets))
        show_stat();
    bytes += pkthdr->caplen;

    offset = find_ip_eth((char*)packet);
    if (offset == -1)
        return;

    if (pkthdr->caplen < offset+sizeof(struct iphdr))
        return;

    ip = (struct iphdr*)(packet+offset);

    add_ip(ip,pkthdr->caplen,dir);
}

int main(int argc,char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    int args = 0;
    int linktype;


    /* Options must be passed in as a string because I am lazy */
    if(argc < 5) {
        fprintf(stdout,"Usage: %s interface \"pcap filter\" packets (dst|src) [p|b|N]\n",argv[0]);
        fprintf(stdout,"p - sort by packets, b - by bytes (default)\n");
        return 0;
    }

    if (argc == 6) {
        double val_user;
        switch(argv[5][0]) {
        case 'p':
            sortby = 1;
            break;
        case 'b':
            sortby = 2;
            break;
        default:
            val_user = atof(argv[5]);
            mask_val = (int)pow(2.0, val_user);
        }
    }

    if (argc == 6 && argv[5][0] == 'b') {
        sortby = 2;
    }


    packets = atoi(argv[3]);
    packetstrigger = packets/5;
    if (!strcmp(argv[4],"src")) {
        args = 1;
    }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(argv[1],&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(argv[1],BUFSIZ,0,1000,errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    //    if (pcap_set_datalink(descr,DLT_RAW)) {
    //	dev = pcap_geterr(descr);
    //	printf("err: %s\n",dev);
    //	exit(-1);
    //    }
    linktype = pcap_datalink(descr);

    if (linktype != DLT_EN10MB) {
        printf("Ethernet only supported\n");
        exit(-1);
    }


    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
        {
            fprintf(stderr,"Error calling pcap_compile\n");
            exit(1);
        }

        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        {
            fprintf(stderr,"Error setting filter\n");
            exit(1);
        }
    }


    gettimeofday(&tv1,NULL);
    /* ... and loop */
    pcap_loop(descr, -1, my_callback, (void *)&args);


    return 0;
}
