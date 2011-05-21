VERSION=0.1

DEBUG=-g
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -O3
LDFLAGS=$(DEBUG)

OBJS=ipslad.o

all: ipslad

ipslad: $(OBJS)

install: ipslad
	cp ipslad /usr/sbin

clean:
	rm -f $(OBJS) ipslad core a.out gmon.out
