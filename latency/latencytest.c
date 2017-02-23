#include<stdio.h>

#ifdef __MINGW32__
#include <winsock2.h>
#include <stdbool.h>
//#pragma comment(lib,"ws2_32.lib")
#else
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#endif
#define BUFLEN 1500  //Max length of buffer
#define PORT 18888   //The port on which to listen for incoming data
#define EXIT_FAILURE 1
#define CLIENT 1
#define SERVER 2

#ifdef __MINGW32__
void GetHighResolutionSystemTime(SYSTEMTIME* pst)
{
    static LARGE_INTEGER    uFrequency = { 0 };
    static LARGE_INTEGER    uInitialCount;
    static LARGE_INTEGER    uInitialTime;
    static bool             bNoHighResolution = false;

    if(!bNoHighResolution && uFrequency.QuadPart == 0)
    {
        // Initialize performance counter to system time mapping
        bNoHighResolution = !QueryPerformanceFrequency(&uFrequency);
        if(!bNoHighResolution)
        {
            FILETIME ftOld, ftInitial;

            GetSystemTimeAsFileTime(&ftOld);
            do
            {
                GetSystemTimeAsFileTime(&ftInitial);
                QueryPerformanceCounter(&uInitialCount);
            } while(ftOld.dwHighDateTime == ftInitial.dwHighDateTime && ftOld.dwLowDateTime == ftInitial.dwLowDateTime);
            uInitialTime.LowPart  = ftInitial.dwLowDateTime;
            uInitialTime.HighPart = ftInitial.dwHighDateTime;
        }
    }

    if(bNoHighResolution)
    {
        GetSystemTime(pst);
    }
    else
    {
        LARGE_INTEGER   uNow, uSystemTime;
        {
            FILETIME    ftTemp;
            GetSystemTimeAsFileTime(&ftTemp);
            uSystemTime.LowPart  = ftTemp.dwLowDateTime;
            uSystemTime.HighPart = ftTemp.dwHighDateTime;
        }
        QueryPerformanceCounter(&uNow);

        LARGE_INTEGER   uCurrentTime;
        uCurrentTime.QuadPart = uInitialTime.QuadPart + (uNow.QuadPart - uInitialCount.QuadPart) * 10000000 / uFrequency.QuadPart;

        if(uCurrentTime.QuadPart < uSystemTime.QuadPart || abs(uSystemTime.QuadPart - uCurrentTime.QuadPart) > 1000000)
        {
            // The performance counter has been frozen (e. g. after standby on laptops)
            // -> Use current system time and determine the high performance time the next time we need it
            uFrequency.QuadPart = 0;
            uCurrentTime = uSystemTime;
        }

        FILETIME ftCurrent;
        ftCurrent.dwLowDateTime  = uCurrentTime.LowPart;
        ftCurrent.dwHighDateTime = uCurrentTime.HighPart;
        FileTimeToSystemTime(&ftCurrent, pst);
    }
}

unsigned long long get_ms() {
    SYSTEMTIME p1;
    FILETIME ft;

    GetHighResolutionSystemTime(&p1);
    SystemTimeToFileTime(&p1, &ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart= ft.dwHighDateTime;
    ULONGLONG uft= uli.QuadPart;
    return uft / 10000;
}
#else
unsigned long long get_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return((ts.tv_sec*1000) + (int)(ts.tv_nsec / 1000000));
}
#endif


int geterr(void) {
#ifdef __MINGW32__
    return WSAGetLastError();
#else
    return(errno);
#endif
}


int main(int argc, char **argv) {
#ifdef __MINGW32__
    SOCKET s;
    WSADATA wsa;
#else
    int s;
#endif
    fd_set read_fd_set;
    struct sockaddr_in server, si_other;
    struct sockaddr_in remote; // only for client
    int slen , recv_len, send_ret, ret;
    char buf[BUFLEN];
    unsigned long long stamp[2];
    struct timeval timeout;
    slen = sizeof(si_other);
    int mode = SERVER;

    if (argc == 3 && !strcmp(argv[1], "-c")) {
	mode = CLIENT;
	memset(&remote, 0x0, sizeof(remote));
        remote.sin_addr.s_addr = inet_addr(argv[2]);
	remote.sin_family = AF_INET;
	remote.sin_port = htons(PORT);
	printf("Client mode\n");
    } else {
	printf("Server mode\n");
    }

#ifdef __MINGW32__
    //Initialise winsock
    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("Failed. Error Code : %d",WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    printf("Initialised.\n");
#endif
    s = socket(AF_INET , SOCK_DGRAM , 0 );
    if(s < 0) {
        printf("Could not create socket : %d\n", geterr());
    }
    printf("Socket created.\n");

    memset(&server, 0x0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    if( bind(s ,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("Bind failed with error code : %d\n", geterr());
        exit(EXIT_FAILURE);
    }

    while(1)
    {
	if (mode == SERVER) {
	    recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen);
	    if (recv_len <= 0) {
        	printf("recvfrom() failed with error code : %d\n", geterr());
        	exit(EXIT_FAILURE);
    	    }
	    send_ret = sendto(s, buf, recv_len, 0, (struct sockaddr*) &si_other, slen);
	    if (send_ret != recv_len) {
        	printf("sendto() failed with error code : %d\n", geterr());
        	exit(EXIT_FAILURE);
	    }
	} else {
	    FD_ZERO (&read_fd_set);
	    FD_SET (s, &read_fd_set);
	    timeout.tv_sec = 0;
	    timeout.tv_usec = 500000;

	    recv_len = 1400;
	    send_ret = sendto(s, buf, recv_len, 0, (struct sockaddr*) &remote, slen);
	    if (send_ret != recv_len) {
        	printf("sendto() failed with error code : %d\n", geterr());
        	exit(EXIT_FAILURE);
	    }
	    stamp[0] = get_ms();
	    ret = select (FD_SETSIZE, &read_fd_set, NULL, NULL, &timeout);
	    if (ret < 0) {
        	printf("select() failed with error code : %d\n", geterr());
        	exit(EXIT_FAILURE);
	    }
	    if (ret > 0) {
		stamp[1] = get_ms();
		recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen);
		if (recv_len <= 0) {
        	    printf("recvfrom() failed with error code : %d\n", geterr());
        	    exit(EXIT_FAILURE);
		}
		printf("Latency: %llums\n", (stamp[1] - stamp[0]));
	    } else {
		printf("Packet lost!\n");
	    }
	}
    }

#ifdef __MINGW32__
    closesocket(s);
    WSACleanup();
#else
    close(s);
#endif
    return 0;
}