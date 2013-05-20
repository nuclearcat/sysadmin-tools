VERSION=0.1

DEBUG=-s
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -Os -D_FILE_OFFSET_BITS=64
LDFLAGS=$(DEBUG)

OBJS=udp2file.o

all: udp2file

udp2file: $(OBJS)

install: udp2file
	cp udp2file /usr/sbin

clean:
	rm -f $(OBJS) udp2file core a.out gmon.out
