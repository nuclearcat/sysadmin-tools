VERSION=0.1

DEBUG=-g # -pg
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG) -O0
LDFLAGS=$(DEBUG)

OBJS=tzsp_tap.o

all: tzsp_tap

tzsp_tap: $(OBJS)
	$(CC) -Wall -W $(OBJS) $(LDFLAGS) -o tzsp_tap

install: tzsp_tap
	cp tzsp_tap /usr/bin

clean:
	rm -f $(OBJS) tzsp_tap core test* a.out gmon.out
