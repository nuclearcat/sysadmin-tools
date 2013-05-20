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



int main(int argc,char **argv)
{
   int fd, fd_f;
   struct sockaddr_in srv_addr, cli_addr;
   socklen_t len, n, n2;
   char message[65536];
   uint16_t port;

   if (argc != 3) {
    printf("%s port file\n", argv[0]);
    exit(0);
   }

   port = atoi(argv[1]);
   if (!port) {
    printf("Invalid port\n");
    exit(0);
   }



   fd = socket(AF_INET, SOCK_DGRAM, 0);

   memset(&srv_addr, 0x0, sizeof(srv_addr));
   srv_addr.sin_family = AF_INET;
   srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   srv_addr.sin_port = htons(port);
   bind(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

   fd_f = open(argv[2], O_RDWR|O_CREAT|O_APPEND, 0600);

   daemon(1,1);

   for (;;)
   {
      len = sizeof(cli_addr);
	n = recvfrom(fd, message, sizeof(message)-1, 0, (struct sockaddr *)&cli_addr, &len);
	n2 = write(fd_f, message, n);
	if (n2 != n)
	    perror("write()");
//      sendto(sockfd,mesg,n,0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
   }

}

