VERSION=0.1

DEBUG=-s
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -Os -D_FILE_OFFSET_BITS=64
LDFLAGS=$(DEBUG)

OBJS=sock2file.o lib.o

all: sock2file

sock2file: $(OBJS)

install: sock2file
	sstrip sock2file
	cp sock2file /usr/sbin

clean:
	rm -f $(OBJS) sock2file core a.out gmon.out
