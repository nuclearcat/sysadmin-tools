/*
 * trafw.c V1.3
 *
 * Copyright (C) 2005-2010 Fedoryshchenko Denys <nuclearcat@nuclearcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * Or, point your browser to http://www.gnu.org/copyleft/gpl.html
 *
 * Recommended gcc flags:
 * gcc -s -Wall -o trafw trafw.c -lpcap -lpthread -lrt
 *
 * ATTENTION! Real tests discover, that this application cannot be used on
 * loaded links. Results will be not precise, cause libpcap dropping packets.
 * Information about dropped packets will appear in result and you can estimate 
 * precision error
 * TODO: 32/64 bit arches, eliminate long value?
 */

#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>

unsigned long long traf[2] = {0, 0};
unsigned int pkts[2] = {0, 0};

unsigned 
int timer;
//pthread_t motherthread;
long long overall[2] = {0, 0};
struct timeval tv;
double oldtm;
char **argv_global;
pcap_t *pd[2];
pthread_mutex_t mutex[2] = {PTHREAD_MUTEX_INITIALIZER , PTHREAD_MUTEX_INITIALIZER};
pthread_cond_t condition;


// Some silly ISP's "conform" IEC standarts
// where is 1Mbit = 1000*1000 bytes
// nice cheat :D but they win only 50Kbit on 1Mbit

#define IEC_COMPLIANT 1

#ifdef IEC_COMPLIANT
#define DIVIDER 1000
#define KBITNAME "KBit"
#else
#define DIVIDER 1024
#define KBITNAME "KiBit"
#endif

#define BILLION 1000000000L;


void
my_callback (u_char * useless, const struct pcap_pkthdr *pkthdr,
	       const u_char * packet)
{
  int cindex = (int) useless;
  register int caplen;
  caplen = (pkthdr->caplen + 4); /* 4 bytes is FCS */
  if (caplen < 64) /* Ethernet specific stuffing */
    caplen = 64;

  pthread_mutex_lock (&mutex[cindex]);
  pkts[cindex]++;
  traf[cindex] += caplen;
  pthread_mutex_unlock (&mutex[cindex]);
}



/* Calculate traffic, reset alarm */
void
show_traffic (void)
{
  double tm;
  struct timespec tv;
  struct timeval ltime;
  register int s;

  unsigned long long l_traf[2] = {0,0};
  unsigned int l_pkts[2] = {0,0};

  clock_gettime (CLOCK_MONOTONIC, &tv);
  tm = tv.tv_sec + (double) tv.tv_nsec / (double) BILLION;

  if ((int) (tm - oldtm) != 0)
    {
      pthread_mutex_lock (&mutex[0]);
      pthread_mutex_lock (&mutex[1]);
      l_traf[0] = traf[0];
      l_traf[1] = traf[1];
      traf[0] = 0;
      traf[1] = 0;

      l_pkts[0] = pkts[0];
      l_pkts[1] = pkts[1];
      pkts[0] = 0;
      pkts[1] = 0;

      pthread_mutex_unlock (&mutex[0]);
      pthread_mutex_unlock (&mutex[1]);

      gettimeofday(&ltime,NULL);
      s = (ltime.tv_sec) % 86400;
                (void)printf("%02d:%02d:%02d ",
                             s / 3600, (s % 3600) / 60, s % 60);

      printf ("%llu/%llu %s/S %u/%u pps (%llu/%llu) (%llu/%llu) %f\n",
	      (unsigned long long) ((l_traf[0]/ (tm - oldtm)) * 8 / DIVIDER),
	      (unsigned long long) ((l_traf[1] / (tm - oldtm)) * 8 / DIVIDER),
	      KBITNAME,
	      (unsigned int) (l_pkts[0]/ (tm - oldtm)),
	      (unsigned int) (l_pkts[1] / (tm - oldtm)),

	      l_traf[0], l_traf[1], overall[0], overall[1], (tm - oldtm));
      oldtm = tm;
      overall[0] += l_traf[0];
      overall[1] += l_traf[1];
    }

  //alarm(timer);
}


// Show pcap statistic
// most important to find possible dropped packets
// TODO: Move to main code? And analyse on each alarm
void
sig_hup (int ifunc)
{
    struct pcap_stat ps;
    int i;
    unsigned int dropshown = 0;
    static int lastdrop[2];

    for (i=0;i<2;i++) {
	if ((pcap_stats (pd[i], &ps)) == -1)
	{
         printf ("pcap_stats iface %d error\n",i);
    	 exit (1);
	}
	if (ps.ps_drop != lastdrop[i]) {
	    dropshown = 1;
	    lastdrop[i] = ps.ps_drop;
	    printf ("if%d: rx:%d drop:%d ", i,ps.ps_recv, ps.ps_drop);
	}
    }
    if (dropshown)
	printf("\n");
}

// Prepare interface and start pcap loop
// TODO: remove lot of 'if' crap 
// TODO: better error handling
int
dump_interface (void *num)
{
  pcap_t *descr;
  struct bpf_program fp;
  bpf_u_int32 netp = 32;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *tmp;

  pthread_mutex_lock(&mutex[0]);

  pthread_detach (pthread_self ());

  if ((int) num == 0)
    tmp = argv_global[1];
  else
    tmp = argv_global[3];

  descr = pcap_open_live (tmp, BUFSIZ, 0, -1, errbuf);
  if (descr == NULL)
    {
      printf ("pcap_open_live(): %s\n", errbuf);
      exit (1);
    }

  if ((int) num == 0)
    tmp = argv_global[2];
  else
    tmp = argv_global[4];

  if (pcap_compile (descr, &fp, tmp, 0, netp) == -1)
    {
      fprintf (stderr, "%s: Error - `pcap_compile()'\n", argv_global[0]);
      return 1;
    }

  if (pcap_setfilter (descr, &fp) == -1)
    {
      fprintf (stderr, "%s: Error - `pcap_setfilter()'\n", argv_global[0]);
      return 1;
    }

  pcap_freecode (&fp);

    pd[(int)num] = descr;
    if ((int)num == 0)
	pthread_cond_signal(&condition);

  pthread_mutex_unlock(&mutex[0]);
	
    pcap_loop (descr, -1, my_callback, num);


  return (0);
}

// TODO: handle pthread_create return code
int
main (int argc, char **argv)
{
  pthread_t thread1, thread2;
  double tm;
//    struct timeval tv;
  struct timespec tv;
  struct timespec ts;

  argv_global = argv;

  //signal(SIGALRM,sig_alarm);
  signal (SIGHUP, sig_hup);

  if (argc != 6)
    {
      fprintf (stdout,
	       "Usage: %s interface1 \"interface1 pcap filter\" interface2 \"interface2 pcap filter\" timer\n",
	       argv[0]);
      return 0;
    }

  timer = atoi (argv[5]);
  if (timer == 0)
    {
      fprintf (stdout, "Wrong timer!\n");
      return (0);
    }

//    gettimeofday(&tv,NULL);
//    tm=tv.tv_sec+(double)tv.tv_usec/1000000;

  clock_gettime (CLOCK_MONOTONIC, &tv);
  tm = tv.tv_sec + (double) tv.tv_nsec / (double) BILLION;


  oldtm = tm;

  //motherthread = pthread_self ();
  pthread_mutex_lock(&mutex[0]);
  pthread_create (&thread1, NULL, (void *) dump_interface, (void *) 0);
  pthread_cond_wait(&condition, &mutex[0]);
  pthread_mutex_unlock(&mutex[0]);

  pthread_create (&thread2, NULL, (void *) dump_interface, (void *) 1);
  

  while (1)
    {
      ts.tv_sec = timer;
      ts.tv_nsec = 0;
      nanosleep (&ts, NULL);
      show_traffic ();
      sig_hup (0);
    }
  fprintf (stdout, "\nExiting!\n");
  return 0;
}
