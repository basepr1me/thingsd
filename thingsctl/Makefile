PROG=		thingsctl

SRCS+=		thingsctl.c parser.c

INC_C_DIR=	/usr/local
BINDIR?=	${INC_C_DIR}/sbin
MANDIR?=	${INC_C_DIR}/man/man

DEBUG=		-g -DDEBUG=3 -O0

LDADD=		-lutil
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -pthread
CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/../thingsd

MAN=		thingsctl.8

.include <bsd.prog.mk>
