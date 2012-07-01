VERSION=0.1

DEBUG=-s -Os -ffunction-sections -fdata-sections -D_FORTIFY_SOURCE=2 -Wall -Wextra
CFLAGS=-DVERSION=\"${VERSION}\" -Wall $(DEBUG)
LDFLAGS=$(DEBUG)

OBJS=ipslad.o

all: ipslad

ipslad: $(OBJS)

install: ipslad
	cp ipslad /usr/sbin

clean:
	rm -f $(OBJS) ipslad core a.out gmon.out
