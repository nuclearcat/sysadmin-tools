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


#define ETHERTYPE_PPPOE_SESSION 0x8864
#define PPPOE_SIZE              22                                                                                                                                                                        
#define HASHSIZE		0xFFFF /* Must be power of 2 */


struct ippairs {
    u_int32_t daddr;
    struct ippairs *next;
    int32_t refcount;
    uint32_t bytes;
    uint32_t packets;
};

struct ippairs *pairs;
int packets, packetstrigger;
unsigned long long packetstotal,bytes;

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
			printf("Ethertype %0x\n",eth_proto_type);
			offset = -1;
			break;			
	}
	return offset;
}

void add_ip(struct iphdr *ip,unsigned int bytes,int dir) {
    int iphash;// = hashlittle(&ip->daddr,4,(uint32_t)1) & HASHSIZE;
    struct ippairs *ptr;// = &pairs[iphash];
    u_int32_t ipaddr;
    if (dir == 0) {
	ipaddr = ip->daddr;
    } else {
	ipaddr = ip->saddr;
    }
    iphash = hashlittle(&ipaddr,4,(uint32_t)1) & HASHSIZE;
    ptr = &pairs[iphash];

//    printf("IP HASH %d PTR REFCOUNT %d\n",iphash,ptr->refcount);

    if (ptr->refcount == 0) {
//	printf("NEW\n");
	ptr->refcount++;
	ptr->bytes+=bytes;
	memcpy(&ptr->daddr,&ipaddr,4);
	return;
    }
//    abort();
    while(ptr->refcount) {
	if (memcmp(&ptr->daddr,&ipaddr,4)) {
	    if (ptr->next != NULL)
		ptr = ptr->next;
	    else {
//		printf("NEW COLL\n");
		/* New, but collision */
		ptr->next = malloc(sizeof(struct ippairs));
		memset(ptr->next,0x0,sizeof(struct ippairs));
		ptr = ptr->next;
		ptr->refcount++;
		ptr->bytes+=bytes;
//		ptr->packets++;
		memcpy(&ptr->daddr,&ipaddr,4);
		return;
	    }
	} else {
	    /* Existing */
//		printf("EXIST\n");
	    ptr->refcount++;
	    ptr->bytes+=bytes;
//	    ptr->packets++;

//	    if ((double)(ptr->refcount/packetstrigger) == ((double)ptr->refcount/(double)packetstrigger) ) {
//		struct in_addr s_addr;
//		s_addr.s_addr = (in_addr_t)ptr->daddr;
//		printf("Interesting %s %d\n",inet_ntoa(s_addr),ptr->refcount);
//	    }


	    return;
	}
    }
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
    bytes += pkthdr->caplen;

    offset = find_ip_eth((char*)packet);
    if (offset == -1)
	return;

    if (pkthdr->caplen < offset+sizeof(struct iphdr))
	return;

    ip = (struct iphdr*)(packet+offset);

    add_ip(ip,pkthdr->caplen,dir);
}

long timevaldiff(struct timeval *starttime, struct timeval *finishtime)
{
  long msec;

  msec =  (finishtime->tv_sec-starttime->tv_sec)*1000;
  msec += (finishtime->tv_usec-starttime->tv_usec)/1000;

  return msec;
}


int compare (const void * a, const void * b)
{
    struct ippairs *px, *py;

    px = (struct ippairs *)a;
    py = (struct ippairs *)b;
    
    return ( px->bytes - py->bytes );
}


int main(int argc,char **argv)
{ 
//    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
//    u_char* args = NULL;
    int args = 0;
    int linktype,i;
    struct ippairs *ptr;
//    FILE *fff;
//    char *buf;
    long timediff;
    struct timeval tv1, tv2;

    /* Options must be passed in as a string because I am lazy */
    if(argc < 5){ 
        fprintf(stdout,"Usage: %s interface \"pcap filter\" packets [dst|src]\n",argv[0]);
        return 0;
    }

    packets = atoi(argv[3]);
    packetstrigger = packets/5;
    if (!strcmp(argv[4],"src")) {
        args = 1;
    }

//    printf("Allocating mem %d bytes for struct %d bytes\n",(sizeof(struct ippairs) * HASHSIZE),sizeof(struct ippairs));
    pairs = malloc(sizeof(struct ippairs) * (HASHSIZE+1));
    memset(pairs,0x0,sizeof(struct ippairs) * (HASHSIZE+1));

    /* grab a device to peak into... */
//    dev = pcap_lookupdev(errbuf);
//    if(dev == NULL) { 
//	printf("%s\n",errbuf); 
//	exit(1); 
//    }


    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(argv[1],&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(argv[1],BUFSIZ,0,-1,errbuf);
    if(descr == NULL) { 
	printf("pcap_open_live(): %s\n",errbuf); exit(1); 
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
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }


    gettimeofday(&tv1,NULL);
    /* ... and loop */ 
    pcap_loop(descr,packets,my_callback,(void *)&args);
    gettimeofday(&tv2,NULL);

    timediff = timevaldiff(&tv1, &tv2);

    printf("Average packet size %llu (with ethernet header, max avg sz 1514)\n",bytes/packetstotal);
    printf("Time %ld, total bytes %lld, total speed %lld Kbit/s\n",timediff,bytes,bytes*8*1000/timediff/1024);

    qsort (pairs, HASHSIZE, sizeof(struct ippairs), compare);

    for (i=0;i<HASHSIZE;i++) {
	 ptr = &pairs[i];
	 while(ptr->refcount) {
	    struct in_addr s_addr;
	    s_addr.s_addr = (in_addr_t)ptr->daddr;
	    printf("%s bytes %d packets %d avgsz %d percbytes %llu percpkts %llu spd %llu Kbit/s\n",inet_ntoa(s_addr),ptr->bytes,ptr->refcount,(ptr->bytes/ptr->refcount),ptr->bytes*100/bytes,ptr->refcount*100/packetstotal,((uint64_t)ptr->bytes*8/(uint64_t)timediff));
	    if (!ptr->next) {
		break;
//		printf("N\n");
    	    }
	    ptr = ptr->next;
	 };
    }
//    fprintf(stdout,"Program finished\n");
    return 0;
}
