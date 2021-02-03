PROG=		thingsctl

SRCS+=		thingsctl.c parser.c

PREFIX=		/usr/local
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/man/man

LDADD=		-lutil
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -fno-common
CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/../thingsd

MAN=		thingsctl.8

.include <bsd.prog.mk>
