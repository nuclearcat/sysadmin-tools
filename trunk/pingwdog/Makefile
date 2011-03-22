VERSION=0.1

DEBUG=-g
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -O3
LDFLAGS=$(DEBUG)

OBJS=pingwdog.o

all: pingwdog

pingwdog: $(OBJS)

install: pingwdog
	cp pingwdog /usr/sbin

clean:
	rm -f $(OBJS) pingwdog core a.out gmon.out
