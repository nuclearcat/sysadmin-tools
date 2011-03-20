/*
    file:   toom.c
    Authors: 
    Linux code: Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>

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

/*! Assert*/
#define assert(x, f) \
if  (x == NULL) \
  { warn("%s:%d %s: %m", __FILE__, __LINE__, f); exit(1);}

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

struct toom {
    int valid;
    time_t firstoccur;
    time_t lastoccur;
    int times;
    int span;
};

int main(int argc,char **argv)
{
    int timespan,maxtimes,oneshot;
    int filefd,retcode = 0,tmp;
    struct toom *ptr;
    int toom_size = sizeof(struct toom);
    struct stat mystat;

    if(argc != 4){
	printf("\"Too Many\" stateless tool v%s\n",VERSION);
	printf("(c) 2011 Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");
        fprintf(stdout,"Usage: %s /path/datafile timespan maxtimes\n",argv[0]);
        return 0;
    }
    timespan = atoi(argv[2]);
    maxtimes = atoi(argv[3]);
    if (!timespan || !maxtimes) {
	printf("Invalid arguments\n");
	exit(-1);
    }

    if (stat(argv[1],&mystat)) {
	printf("File init\n");
	filefd = open(argv[1],O_RDWR|O_CREAT|O_EXCL,S_IRWXU);
	if (filefd == -1) {
	    perror("initial open error");
	    exit(-1);
	}
	ptr = malloc(toom_size);
	memset(ptr,0x0,toom_size);
	tmp = write(filefd,ptr,toom_size);
	close(filefd);
	stat(argv[1],&mystat);
    }

    if (mystat.st_size != toom_size) {
	printf("Invalid toom data file, size %d should %d\n",mystat.st_size, toom_size);
	exit(-1);
    }

    filefd = open(argv[1],O_RDWR|O_EXCL);
    if (filefd == -1) {
	perror("open()");
	exit(0);
    }
    
    ptr = mmap(NULL,toom_size,PROT_READ|PROT_WRITE,MAP_SHARED,filefd,0);
    if (ptr == NULL) {
	perror("mmap()");
	exit(-1);
    }

    if (ptr->valid == 0) {
	printf("First run\n");
	ptr->firstoccur=time(NULL);
	ptr->lastoccur=time(NULL);
	ptr->times=1;
	ptr->span=timespan;
	ptr->valid=1;
	goto done;
    }

    if (ptr->span!=timespan) {
	printf("Span is changed, reset\n");
	ptr->firstoccur=time(NULL);
	ptr->lastoccur=time(NULL);
	ptr->times=1;
	ptr->span=timespan;
	goto done;
    }

    if (time(NULL) - ptr->lastoccur >= ptr->span) {
	printf("Total reset, last time more than spantime seconds ago\n");
	ptr->firstoccur=time(NULL);
	ptr->lastoccur=time(NULL);
	ptr->times=1;
	goto done;
    }

    oneshot = ptr->span / maxtimes;

    if (time(NULL) - ptr->firstoccur > ptr->span+oneshot) {
	int cut = (time(NULL) - ptr->firstoccur - ptr->span) * 100 / ptr->span;
	printf("Decreasing %d %%\n",cut);
	ptr->firstoccur=ptr->firstoccur + (ptr->span*cut/100);
	ptr->lastoccur=time(NULL);
	printf("CUT %d\n",(ptr->times*cut/100));
	ptr->times-=(ptr->times*cut/100);
	if (ptr->times <= 0) {
	    ptr->firstoccur=time(NULL);
	    ptr->lastoccur=time(NULL);
	    ptr->times=0;	    
	}
    }

    ptr->lastoccur=time(NULL);
    ptr->times++;
    if (ptr->times >=maxtimes) {
	//ptr->times =maxtimes;
	printf("TRIGGER\n");

	retcode = 1;
    }

done:
    printf("CTR:%d\n",ptr->times);
    munmap(ptr,toom_size);
    fsync(filefd);
    close(filefd);
    return(retcode);
}

