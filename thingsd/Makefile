PROG =		thingsd
SRCS =		parse.y
SRCS +=		config.c control.c log.c thingsd.c proc.c
SRCS +=		sockets.c tls.c client.c

MAN =		thingsd.8 thingsd.conf.5

PREFIX=		/usr/local
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/man/man

LDADD =		-levent -ltls -lssl -lcrypto -lutil
DPADD =		${LIBEVENT} ${LIBTLS} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL}
DEBUG=		-g -DDEBUG=0 -O0
CFLAGS +=	-Wall -I${.CURDIR}
CFLAGS +=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS +=	-Wmissing-declarations
CFLAGS +=	-Wshadow -Wpointer-arith -fno-common
CFLAGS +=	-Wsign-compare
YFLAGS =

CLEANFILES+=	y.tab.h

.include <bsd.prog.mk>
