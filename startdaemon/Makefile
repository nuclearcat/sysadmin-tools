CC?=		gcc
CFLAGS?=	-O -pipe
LDFLAGS?=
LFLAGS?=	${LDFLAGS}
LIBS?=

RM=		rm -f
MKDIR?=		mkdir -p

PROG=		sdaemon
OBJS=		sdaemon.o
SRCS=		sdaemon.c

# development/debugging flags, you may safely ignore them
#CFLAGS+=	-ggdb -g3

all:		${PROG} ${MAN1GZ}

clean:
		${RM} ${PROG} ${OBJS} ${MAN1GZ}

${PROG}:	${OBJS}
		${CC} ${LFLAGS} -o ${PROG} ${OBJS}

sdaemon.o:	sdaemon.c
		${CC} ${CFLAGS} -c sdaemon.c

${MAN1GZ}:	${MAN1}
		gzip -c9 ${MAN1} > ${MAN1GZ}.tmp
		mv ${MAN1GZ}.tmp ${MAN1GZ}

install:	all
		-${MKDIR} ${DESTDIR}${BINDIR}
		-${MKDIR} ${DESTDIR}${MANDIR}1
		install -c -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} ${PROG} ${DESTDIR}${BINDIR}/
		install -c -o ${MANOWN} -g ${MANGRP} -m ${MANMODE} ${MAN1GZ} ${DESTDIR}${MANDIR}1/
