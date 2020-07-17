PROG =		thingsd
SRCS =		config.c control.c things.c log.c thingsd.c parse.y proc.c \
		tls.c serial.c sockets.c events.c client.c

MAN =		thingsd.8 thingsd.conf.5

INC_C_DIR =	/usr/local
BINDIR? =	${INC_C_DIR}/sbin
MANDIR? =	${INC_C_DIR}/man/man

CFLAGS +=	-Wall -I${.CURDIR}
CFLAGS +=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS +=	-Wmissing-declarations
CFLAGS +=	-Wshadow -Wpointer-arith
CFLAGS +=	-Wsign-compare -pthread
YFLAGS =
LDADD =		-levent -ltls -lssl -lcrypto -lutil -pthread
DPADD =		${LIBEVENT} ${LIBTLS} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL}

CLEANFILES+=	y.tab.h

DEBUG=		-g -O2

.include <bsd.prog.mk>
