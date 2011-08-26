/*
    file:   pingwdog.c
    Authors: 
    Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#ifdef __linux__
#include <netinet/ether.h>
#include <linux/if_tun.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#ifdef __FreeBSD__
#include <net/if_tap.h>
#endif
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>

#include <curl/curl.h>
#include <sys/mman.h>

#include <getopt.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <sys/select.h>
#include <assert.h>
#include <syslog.h>

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))
#define DEFNAME "default"
#define MAXBUF	1024

int verbose = 0;

struct mondata {
    unsigned int rtt;
};

/*
struct pings {    
	struct 
};
*/

/* From Stevens, UNP2ev1 */
unsigned short
in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

long timevaldiff(struct timeval *starttime, struct timeval *finishtime)
{
  long msec;
  msec=(finishtime->tv_sec-starttime->tv_sec)*1000;
  msec+=(finishtime->tv_usec-starttime->tv_usec)/1000;
  return msec;
}


static int ping4(char *dsthost, long maxdelay, char *bindaddr,int size)
{
	int s,retval,icmp_len,rcvd,seq;
	int on = 1;
	struct hostent *hp;
	char buf[size];
        struct ip *ip = (struct ip *)buf;
        struct icmp *icmp = (struct icmp *)(ip + 1);
        struct sockaddr_in dst,src;
	fd_set rfds;
	struct timeval tv;
	struct timeval tvent, tvcur; // entrance time, current time
	long timediff = 0;
	size_t dstsize;

	static int sequence = 0;

	gettimeofday(&tvent,NULL);

        FD_ZERO(&rfds);
	memset(icmp,0x0,sizeof(struct icmp));



       if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
                perror("socket");
                exit(1);
        }
	if (bindaddr != NULL) {
	    struct sockaddr_in serv_addr;
	    serv_addr.sin_family = AF_INET;
	    if (!inet_pton(AF_INET, bindaddr, (struct in_addr *)&serv_addr.sin_addr.s_addr)) {
		perror("bind address invalid");
		exit(-1);
	    }
	    serv_addr.sin_port = 0;
	    if (bind(s, (struct sockaddr *) &serv_addr,
		    sizeof(serv_addr)) < 0)
	    {
		perror("bind error");
		exit(-1);
	    }
	}

        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
                perror("IP_HDRINCL");
                exit(1);
        }

       if ((hp = gethostbyname(dsthost)) == NULL) {
                if ((ip->ip_dst.s_addr = inet_addr(dsthost)) == -1) {
                        fprintf(stderr, "%s: unknown host\n", dsthost);
                }
        } else {
                memcpy(&ip->ip_dst.s_addr, hp->h_addr_list[0], hp->h_length);
        }

        ip->ip_v = 4;
        ip->ip_hl = sizeof *ip >> 2;
        ip->ip_tos = 0;
        ip->ip_len = htons(sizeof(buf));
        ip->ip_id = 0;
        ip->ip_off = 0;
        ip->ip_ttl = 255;
        ip->ip_p = 1;
        ip->ip_sum = 0;                 /* kernel fills in */
        ip->ip_src.s_addr = 0;          /* kernel fills in */

	dst.sin_addr = ip->ip_dst;
        dst.sin_family = AF_INET;

        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
	icmp->icmp_hun.ih_idseq.icd_id = getpid();
//	icmp->icmp_hun.ih_idseq.icd_seq = seq = htons(rand());
	sequence++;
	icmp->icmp_hun.ih_idseq.icd_seq = seq = htons(sequence);

	icmp_len = sizeof(buf) - sizeof(struct iphdr);
        icmp->icmp_cksum = in_cksum((unsigned short *)icmp, icmp_len);

	if (sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
                        perror("sendto");

        

        tv.tv_sec = maxdelay/1000;
        tv.tv_usec = (maxdelay%1000)*1000;
	
	while (1) {
	    FD_SET(s, &rfds);
	    retval = select(s+1, &rfds, NULL, NULL, &tv);
	    /* Timeout */
	    if (tv.tv_usec == 0 && tv.tv_sec == 0) {
		close(s);
		return(timediff);
	    }
	    if (retval > 0) {
		dstsize = sizeof(dst);
		rcvd = recvfrom(s,buf,sizeof(buf),0, (struct sockaddr *)&src, &dstsize);
		/* Check only if we dont have anything, otherwise just discard packet 
		   till time is expired
		*/
		if (!timediff && rcvd >= ( 8 + ip->ip_hl * 4)) {
	    	    //printf("Got something %d == %d,%d == %d,%d\n",icmp->icmp_hun.ih_idseq.icd_seq,seq,icmp->icmp_hun.ih_idseq.icd_id,getpid(),!memcmp(&src.sin_addr,&dst.sin_addr,sizeof(src.sin_addr)));
	    	    if (icmp->icmp_type == ICMP_ECHOREPLY && !memcmp(&src.sin_addr,&dst.sin_addr,sizeof(src.sin_addr)) && icmp->icmp_hun.ih_idseq.icd_id == getpid() && icmp->icmp_hun.ih_idseq.icd_seq == seq) {
			gettimeofday(&tvcur,NULL);
			timediff = timevaldiff(&tvent,&tvcur);
			/* TODO, usec resolution */
			if (timediff == 0)
			    timediff = 1;
			//close(s);
			//return(timediff);
		    }
		}
	    }
	    if (retval < 0) {
		printf("ERR\n");
		close(s);
		return(0);
	    }
	}
	

	if (retval <= 0) {
	    /* Expired */
	    close(s);
	    return(0);
	} 

	close(s);
	return(timediff);	
	
}

void exec_detached(char *program, char *attribute) {
    int tty_fd = -1;
    int devnull_fd = -1;
    int i;
    pid_t pid;

    tty_fd=open("/dev/tty", O_RDWR);
    devnull_fd=open("/dev/null", O_RDWR);
    i = fork();
    if (i<0) {
	perror("Unable to fork.\n");
	exit(1);
    }
    if (i) {
	close(devnull_fd);
	close(tty_fd);
	return;
    }

     /* change tty */
    ioctl(tty_fd, TIOCNOTTY, 0);
    close(tty_fd);
    umask(022); /* set a default for dumb programs */
    dup2(devnull_fd,0); /* stdin */
    dup2(devnull_fd,1); /* stdout */
    dup2(devnull_fd,2); /* stderr */
     /* now close all extra fds */
    for (i=getdtablesize()-1; i>=3; --i) close(i);

    execlp(program,program,attribute,NULL);
    exit(0);
}

/*
struct _trackparam {
    double 
};
*/

int main(int argc,char **argv)
{
  int interval = 500, size = 100, period = 60, span = 200, inertia = 30;

  int tlatencyhi = 200, tlatencylo = 150, tjitterlo = 0, tjitterhi = 0;
  int toutagebad = 0, toutagegood = 0;
  double tlosshi = 1.0, tlosslo = 0.5;

  char *dsthost=NULL,*bindaddr=NULL,*name=NULL,*onfail=NULL,*onrestore=NULL,*tmp;
  int len,c,prevc,i;
  int cntlatency = 0,cntloss = 0,cntjitter = 0, operational = 0;
  double sumlatency = 0.0,sumloss = 0.0,sumjitter = 0.0;

  int rpt_cntlatency = 0,rpt_cntloss = 0,rpt_cntjitter = 0;
  double rpt_sumlatency = 0.0, rpt_sumloss = 0.0, rpt_sumjitter = 0.0;

  time_t triglatency = 0, trigloss = 0, trigjitter = 0;
  struct timeval tv;
  time_t oldtime = time(NULL);
  char buffer[MAXBUF];
  struct sigaction sa;

  /* prevent zombies */
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = SA_NOCLDWAIT;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
  }


  while (1)
         {

	    static struct option long_options[] =
             {
               /* These options don't set a flag.
                  We distinguish them by their indices. */
               {"dst",  required_argument, 0, 'd'},
               {"name",  required_argument, 0, 'n'},
               {"interval",  required_argument, 0, 'i'},
               {"size",  required_argument, 0, 's'},
               {"bind",  required_argument, 0, 'b'},
               {"maxlost",  required_argument, 0, 'm'},
               {"span",  required_argument, 0, '1'},
               {"rperiod",  required_argument, 0, '2'},
               {"triggerloss",  required_argument, 0, '3'},
               {"triggerlatency",  required_argument, 0, '4'},
               {"triggerjitter",  required_argument, 0, '5'},
               {"triggeroutage",  required_argument, 0, '6'},
               {"onfail",  required_argument, 0, 'f'},
               {"onrestore",  required_argument, 0, 'r'},
               {"verbose",  no_argument, 0, 'v'},
               {"help",  no_argument, 0, 'h'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
	    int option_index = 0;
     
	    c = getopt_long (argc, argv, "d:b:p:g:f:r:h:b:n:l", long_options, &option_index);
          /* Detect the end of the options. */
           if (c == -1)
             break;
     
           switch (c)
             {
             case 'i':
		interval = atoi(optarg);
               break;

             case 's':
		size = atoi(optarg);
               break;

             case 'v':
		verbose = 1;
               break;

             case '1':
		span = atoi(optarg);
               break;

             case '2':
		period = atoi(optarg);
               break;

             case '3':
		tmp = strchr(optarg,'/');
		tlosshi = tlosslo = atof(optarg);
		if (tmp)
		    tlosshi = atof(++tmp);
               break;

             case '4':
		tmp = strchr(optarg,'/');
		tlatencylo = tlatencyhi = atoi(optarg);
		if (tmp)
		    tlatencyhi = atof(++tmp);

               break;

             case '5':
		tmp = strchr(optarg,'/');
		tjitterlo = tjitterhi = atoi(optarg);
		if (tmp)
		    tjitterhi = atof(++tmp);

               break;

             case '6':
		tmp = strchr(optarg,'/');
		toutagebad = toutagegood = atoi(optarg);
		if (tmp)
		    toutagegood = atof(++tmp);
               break;


             case 'd':
		len = strlen(optarg) + 1;
		dsthost = malloc(len);
		strncpy(dsthost,optarg,len);
               break;

             case 'b':
		len = strlen(optarg) + 1;
		bindaddr = malloc(len);
		strncpy(bindaddr,optarg,len);
               break;

             case 'n':
		len = strlen(optarg) + 1;
		name = malloc(len);
		strncpy(name,optarg,len);
               break;

             case 'f':
		len = strlen(optarg) + 1;
		onfail = malloc(len);
		strncpy(onfail,optarg,len);
               break;

             case 'r':
		len = strlen(optarg) + 1;
		onrestore = malloc(len);
		strncpy(onrestore,optarg,len);
               break;

     
             case 'h':
		printf("Available options:\n");
		printf("--dst 			- Destination host\n");
		printf("--name 			- Name of measurement\n");
		printf("--interval 		- Interval between pings (500ms)\n");
		printf("--size 			- Size of packet (100)\n");
		printf("--bind 			- Bind address\n");
		printf("--maxlost 		- Max packets lost in row to trigger alert\n");
		printf("--span	 		- Statistical span of data to analyse (200)\n");
		printf("--rperiod 		- Report period (each 60 seconds)\n");
		printf("--onfail 		- Script on failure\n");
		printf("--onrestore 		- Script on restore\n");
		printf("--verbose 		- Verbose\n");
		printf("Thresholds recovery/alert, set to 0 to off\n");
		printf("--triggerloss 		- Packetloss %% (0.5/1.0)\n");
		printf("--triggerlatency	- Latency msec (150/200)\n");
		printf("--triggerjitter		- Jitter msec (0/0)\n");
//		printf("--triggeroutage		- Detect outage, missed packets/packets ok (0/0)\n");
               /* getopt_long already printed an error message. */
		exit(1);
               break;
     
             default:
               abort ();
             }
         }                            

    if (dsthost == NULL) {
	printf("Please specify destination\n");
	exit(1);
    }

    if (!name) {
	name = malloc(sizeof(DEFNAME));
	strncpy(name,DEFNAME,sizeof(DEFNAME));
    }


    /* TODO: Alert about invalid values */
    if (tlatencyhi > interval)
	tlatencyhi = interval;

    if (tlatencylo > interval)
	tlatencylo = interval;

    if (tlatencyhi < tlatencylo)
	tlatencyhi = tlatencylo;


    if (tlosshi < tlosslo)
	tlosshi = tlosslo;

    if (tjitterhi < tjitterlo)
	tjitterhi = tjitterlo;

    
    

    daemon(0,1);

    snprintf(buffer,MAXBUF-1,"%s/SLAd starting",name);
    syslog(LOG_USER|LOG_ALERT,"%s",buffer);

    snprintf(buffer,MAXBUF-1,"%s/i%d sz%d spn%d rptper%d tloss%f/%f tlat%d/%d tjit%d/%d\n",name,interval,size,span,period,tlosslo,tlosshi,tlatencylo,tlatencyhi,tjitterlo,tjitterhi);
    syslog(LOG_USER|LOG_ALERT,"%s",buffer);

    c = 0;
    prevc = 0;
    while(1) {
	/* Store prev value for jitter calculation */
	if (c)
	    prevc = c;

	c = ping4(dsthost,interval,bindaddr,size);

	/* Handle first measurement */
	if (!prevc)
	    prevc = c;

        if (!c) {
	    if (verbose) {
		snprintf(buffer,MAXBUF-1,"%s/FAIL\n",name);
		syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
	    }
	    /* Loss */
	    sumloss++; 
	    cntloss++;
	    rpt_sumloss++; 
	    rpt_cntloss++;

	} else {
	    /* TODO: Calculate final values by just adding rpt_ */
	    /* Loss handling, no sum, there is no loss */
	    cntloss++; 
	    /* Latency */
	    sumlatency += (double)c;
	    cntlatency++;
	    /* Jitter */
	    sumjitter += abs(prevc-c);
	    cntjitter++;


	    /* Loss handling, no sum, there is no loss */
	    rpt_cntloss++; 
	    /* Latency */
	    rpt_sumlatency += (double)c;
	    rpt_cntlatency++;
	    /* Jitter */
	    rpt_sumjitter += abs(prevc-c);
	    rpt_cntjitter++;


	    if (verbose || ( (time(NULL) - oldtime > period) && operational )) {
		// int rpt_cntlatency = 0,rpt_cntloss = 0,rpt_cntjitter = 0;
		//double rpt_sumlatency = 0.0, rpt_sumloss = 0.0, rpt_sumjitter = 0.0;

		oldtime = time(NULL);
		snprintf(buffer,MAXBUF-1,"%s: loss,lat,jit cur: %f %f %f , avg: %f %f %f A:%s:%s:%s\n",name, \
		rpt_sumloss/rpt_cntloss*100.0,(rpt_sumlatency/rpt_cntlatency),rpt_sumjitter/rpt_cntjitter, \
		sumloss/cntloss*100.0,(sumlatency/cntlatency),sumjitter/cntjitter,trigloss?"bad":"ok",triglatency?"bad":"ok",trigjitter?"bad":"ok");
		syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
		rpt_cntlatency = 0;
		rpt_cntloss = 0;
		rpt_cntjitter = 0;
		rpt_sumlatency = 0.0;
		rpt_sumloss = 0.0;
		rpt_sumjitter = 0.0;

	    }
	}

	/* Here we cut exceeding data if it is more than span */
	if (cntlatency > span) {
	    sumlatency -= sumlatency / (double)cntlatency;
	    cntlatency--;
	}

	if (cntloss > span) {
	    /* We avoid if there, it is branch, just assign that we reach required amount of data */
	    operational=1;

	    sumloss -= sumloss / (double)cntloss;
	    cntloss--;
	}

	if (cntjitter > span) {
	    sumjitter -= sumjitter / (double)cntjitter;
	    cntjitter--;
	}

	if (operational) {
	    if (tlosshi > 0.0) { 
		if ((sumloss/cntloss*100.0) >= tlosshi) {
		    if (!trigloss) {
			snprintf(buffer,MAXBUF-1,"%s/ALARM: Loss exceeding trigger value\n",name);
			syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
			if (onfail) {
			    snprintf(buffer,MAXBUF-1,"%s fail loss %f dst/src %s/%s",name,(sumloss/cntloss*100.0),dsthost,bindaddr == NULL ? "N/A" : bindaddr);
			    exec_detached(onfail,buffer);
			}
			trigloss = time(NULL);
		    }
		} else if (trigloss && sumloss/cntloss*100.0 < tlosslo && (time(NULL) - trigloss) > inertia) {
		    trigloss = 0;
		    snprintf(buffer,MAXBUF-1,"%s/RECOVERED: Loss \n",name);
		    syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
		    if (onrestore) {
			snprintf(buffer,MAXBUF-1,"%s restore loss %f dst/src %s/%s",name,(sumloss/cntloss),dsthost,bindaddr == NULL ? "N/A" : bindaddr);
			exec_detached(onrestore,buffer);
		    }
		}
	    }


	    if (tlatencyhi > 0) { 
		if ((int)sumlatency/cntlatency >= tlatencyhi) {
		    if (!triglatency) {
			snprintf(buffer,MAXBUF-1,"%s/ALARM: latency exceeding trigger value\n",name);
			syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
			if (onfail) {
			    snprintf(buffer,MAXBUF-1,"%s fail latency %f dst/src %s/%s",name,(sumlatency/cntlatency),dsthost,bindaddr == NULL ? "N/A" : bindaddr);
			    exec_detached(onfail,buffer);
			}
			triglatency = time(NULL);
		    }
		} else if (triglatency && sumlatency/cntlatency < tlatencylo && (time(NULL) - triglatency) > inertia) {
		    triglatency = 0;
		    snprintf(buffer,MAXBUF-1,"%s/RECOVERED: latency \n",name);
		    syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
		    if (onrestore) {
			snprintf(buffer,MAXBUF-1,"%s restore latency %f dst/src %s/%s",name,(sumlatency/cntlatency),dsthost,bindaddr == NULL ? "N/A" : bindaddr);
			exec_detached(onfail,buffer);
		    }
		}
	    }

	    if (tjitterhi > 0) { 
		if ((int)sumjitter/cntjitter >= tjitterhi) {
		    if (!trigjitter) {
			snprintf(buffer,MAXBUF-1,"%s/ALARM: jitter exceeding trigger value\n",name);
			syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
			if (onfail) {
			    snprintf(buffer,MAXBUF-1,"%s fail jitter %f dst/src %s/%s",name,(sumjitter/cntjitter),dsthost,bindaddr == NULL ? "N/A" : bindaddr);
			    exec_detached(onfail,buffer);
			}
			trigjitter = time(NULL);
		    }
		} else if (trigjitter && sumjitter/cntjitter < tjitterlo && (time(NULL) - trigjitter) > inertia) {
		    trigjitter = 0;
		    snprintf(buffer,MAXBUF-1,"%s/RECOVERED: jitter \n",name);
		    syslog(LOG_DAEMON|LOG_NOTICE,"%s",buffer);
		    if (onrestore) {
			snprintf(buffer,MAXBUF-1,"%s restore jitter %f dst/src %s/%s",name,(sumjitter/cntjitter),dsthost,bindaddr == NULL ? "N/A" : bindaddr);
			exec_detached(onfail,buffer);
		    }
		}
	    }


	}
	/*
        tv.tv_sec = interval/1000;
        tv.tv_usec = (interval%1000)*1000;
	select(0, NULL, NULL, NULL, &tv);
	*/
    }

    return(0);
}

