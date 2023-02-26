VERSION=0.2

DEBUG=-g # -pg
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -O0
LDFLAGS=$(DEBUG) -lrt -lpcap -lm

OBJS=iptop.o

all: iptop

iptop: $(OBJS)
	$(CC) -Wall -W $(OBJS) $(LDFLAGS) -o iptop

install: iptop
	cp iptop /usr/bin

clean:
	rm -f $(OBJS) iptop core test* a.out gmon.out
