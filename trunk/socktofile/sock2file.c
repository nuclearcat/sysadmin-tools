/*
    file:   udp2file.c
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include "lib.h"

void str2ip(const char* ip, uint32_t *retval) {
   *retval = 0;

   if (strcmp(ip, "0.0.0.0") == 0) {
      return;
   }

   if (ip[0] == 0) {
      return;
   }

   *retval = inet_addr(ip);
   if (*retval != INADDR_NONE) {
      return;
   }
}


int main(int argc,char **argv)
{
   int fd[2], fd_f = 0, proto = 0, num_fd = 0, max, sequence = 0, ret;
   struct sockaddr_in srv_addr, cli_addr;
   socklen_t len, n, n2;
   char message[65536];
   uint16_t port;
   uint32_t ipaddr;
   char *str_ptr = NULL;

   if (argc < 3) {
    printf("%s port[:proto] dir [bindip]\n", argv[0]);
    exit(0);
   }

   port = atoi(argv[1]);

   if (argc == 4)
	str2ip(argv[3], &ipaddr);

   if (!port) {
    printf("Invalid port\n");
    exit(0);
   }
   str_ptr = strchr(argv[1], ':');
   if (str_ptr && strlen(str_ptr) >= 4) {
	str_ptr++;
   }

   if (str_ptr && !strcmp(str_ptr, "tcp"))
     proto = 1;

   if (proto)
    fd[0] = socket(AF_INET, SOCK_STREAM, 0);
   else
    fd[0] = socket(AF_INET, SOCK_DGRAM, 0);

   num_fd++;
   max = fd[0];
   fd[1] = 0;

   memset(&srv_addr, 0x0, sizeof(srv_addr));
   srv_addr.sin_family = AF_INET;
   if (argc == 4)
    srv_addr.sin_addr.s_addr = ipaddr;
   else
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   srv_addr.sin_port = htons(port);
   bind(fd[0], (struct sockaddr *)&srv_addr, sizeof(srv_addr));

   if (proto) {
    ret = listen(fd[0], 1000);
    if (ret == -1) {
	perror("listen");
	exit(1);
    }
   }

   chdir(argv[2]);
   fd_new_date(&fd_f, &sequence);

   daemon(1,1);

   for (;;)
   {
	
	if (!proto) {
	    len = sizeof(cli_addr);
	    n = recvfrom(fd[0], message, sizeof(message)-1, 0, (struct sockaddr *)&cli_addr, &len);
	    n2 = write(fd_f, message, n);
	    if (n2 != n)
		perror("write()");
	} else {
	    /* Handling tcp */
	    fd_set set;
	    FD_ZERO(&set);
	    FD_SET(fd[0], &set);
	    if (fd[1])
		FD_SET(fd[1], &set);
	    select(max + 1, &set, NULL, NULL, NULL);
	    if (FD_ISSET(fd[0], &set)) {
		/* New connection */
		if (fd[1])
		    close(fd[1]);
		fd[1] = accept(fd[0], (struct sockaddr *) &cli_addr, &len);
		max = fd[1];
		num_fd = 2;
	    }
	    if (fd[1] && FD_ISSET(fd[1], &set)) {
		n = read(fd[1], message, sizeof(message)-1);
		if (n <= 0) {
			/* We close also old file, data maybe corrupted, so new will be clean */
			close(fd[1]);
			close(fd_f);
			fd_f = 0;
			num_fd = 1;
			fd[1] = 0;
			max = fd[0];
		} else {
			/* Writing data */
			n2 = write(fd_f, message, n);
			if (n2 != n)
			    perror("write()");
		}
	    }
	}
	fd_new_date(&fd_f, &sequence);
   }
}

