#include <sys/types.h>
#include <sys/signal.h>
#include <sys/wait.h>

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <sys/termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>


int launch_child(char *prog,char **argv) {
		int i;
		int tty_fd = -1;
		int devnull_fd = -1;

//		printf("P:'%s' '%s' '%s'\n",prog,argv[0],argv[1]);
		tty_fd=open("/dev/tty", O_RDWR);
		devnull_fd=open("/dev/null", O_RDWR);

		i = fork();
		if (i<0) {
			perror("Unable to fork.\n");
			exit(1);
		}
		if (i)
		    return(i);

		 /* change tty */
		ioctl(tty_fd, TIOCNOTTY, 0);
		close(tty_fd);
		umask(022); /* set a default for dumb programs */
		dup2(devnull_fd,0); /* stdin */
		dup2(devnull_fd,1); /* stdout */
		dup2(devnull_fd,2); /* stderr */
		 /* now close all extra fds */
		for (i=getdtablesize()-1; i>=3; --i) close(i);
		setsid();
		execvp(prog, argv);
		perror("execv()");
}

int
main(int argc, char **argv)
{
	char *prog = *(++argv);
	int i;

	i = launch_child(prog,argv);
	printf("%d\n",i);
	return (0);
}
