PROG=		thingsd

SRCS=		parse.y
SRCS+=		log.c serial.c sockets.c client.c events.c tls.c

SRCS+=		thingsd.c

INC_C_DIR=	/usr/local
BINDIR?=	${INC_C_DIR}/sbin
MANDIR?=	${INC_C_DIR}/man/man



LDADD=		-levent -ltls -lssl -lcrypto -lutil -pthread
DPADD=		${LIBEVENT} ${LIBTLS} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL}
DEBUG=		-g -DDEBUG=3 -O0

CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -pthread

CLEANFILES+=	y.tab.h

MAN=		thingsd.8 thingsd.conf.5

.include <bsd.prog.mk>
