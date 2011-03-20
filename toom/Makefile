VERSION=0.1

DEBUG=-g
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -O3
LDFLAGS=$(DEBUG)

OBJS=toom.o

all: toom

toom: $(OBJS)

install: toom
	cp toom /usr/sbin

clean:
	rm -f $(OBJS) toom core a.out gmon.out
