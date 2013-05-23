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
#include <time.h>
#include <unistd.h>
#include <string.h>

static void seq_process (int *sequence) {
   int ret;
   char buffer[64];

   ret = open("seq", O_RDWR|O_CREAT, 0600);
   if (ret != -1) {
	if (read(ret, buffer, sizeof(buffer) - 1) > 0) {
	    *sequence = atoi(buffer);
	}
	(*sequence)++;
	lseek(ret, 0, SEEK_SET);
	sprintf(buffer, "%d", *sequence);
	if (write(ret, buffer, strlen(buffer)) < strlen(buffer))
	    perror("write_seq");
	close(ret);
   } else {
     *sequence = 0;
   }
}

void fd_new_date(int *fd, int *seq) {
    int day;
    static time_t mytime;
    struct tm *tm;
    time_t current;
    char filename[64], formatted[32];

    tm = gmtime(&mytime);
    day = tm->tm_mday;
    current = time(NULL);
    tm = gmtime(&current);
    if (day != tm->tm_mday || *fd == 0) {
	if (*fd) {
	    close(*fd);
	    /* TODO: create flag that this file ok to be compressed or processed */
	}
	seq_process(seq);
	sprintf(formatted, "%%Y-%%m-%%d_%05d_%%H:%%M:%%S.log", *seq);
	strftime(filename, sizeof(filename) - 1, formatted, tm);
	*fd = open(filename, O_RDWR|O_CREAT|O_APPEND, 0600);
	if (*fd == -1) {
	    perror("open");
	    *fd = 0;
	    return;
	}
    mytime = current;
    }
}

