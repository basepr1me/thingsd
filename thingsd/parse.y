/*
 * Copyright (c) 2016-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2020 Matthias Pressfreund <mpfr@fn.de>
 * Copyright (c) 2007 - 2015 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2006 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

%{
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#include "proc.h"
#include "thingsd.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file;
struct file	*newfile(const char *, int);
struct file	*newbuff(u_char *);
static void	 closefile(struct file *);
static void	 closebuff(struct file *);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 getservice(char *);
int	 symset(const char *, const char *, int);
char	*symget(const char *);

void	 clear_config(struct thingsd *xconf);

static int		 errors;

int		 get_addrs(const char *, struct addresslist *,
		    struct portrange *);

static struct thingsd		*thingsd;
static struct thing		*new_thing;

const int		 baudrates[18] = {50, 75, 110, 134, 150, 200,
			    300, 600, 1200, 1800, 2400, 4800, 9600,
			    38400, 57600, 76800, 115200};
const char		*parity[4] = {"none", "odd", "even", "space"};
struct client		*pclient, *tclient;
char			 my_name[THINGSD_MAXTEXT];
int			 my_fd, pkt_len;

typedef struct {
	union {
		long long		 number;
		char			*string;
		struct portrange	 port;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	BAUD BIND CA CERTIFICATE CIPHERS CLIENT CLIENTS CONNECT CONNECTION CRL
%token	DATA DHE ECDHE ERROR HARDWARE INCLUDE INTERFACE IPADDR KEY
%token	LISTEN LOCATION MAX NAME OCSP ON OPTIONAL PARITY PASSWORD PERSISTENT
%token	PORT PREFORK PROTOCOLS RECEIVE RETRY SOFTWARE STOP SUBSCRIBE
%token	THING THINGS TCP TLS UDP VERBOSE

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.string>	string
%type	<v.number>	opttls
%type	<v.port>	port

%%

grammar		: /* empty */
		| grammar include '\n'
		| grammar '\n'
		| grammar conf_main '\n'
		| grammar dosub
		| grammar error '\n'		{ file->errors++; }
		| grammar thing '\n'
		| grammar varset '\n'
		;

conf_main	: bindopts1
		| maxclients
		| PREFORK NUMBER {
			thingsd->prefork_socks = $2;
			if ($2 <= 0 || $2 > PROC_MAX_INSTANCES) {
				yyerror("invalid number of preforked "
				    "sockets: %lld", $2);
				YYERROR;
			}
		}
		| thingretry
		;

bindopts1	: BIND TCP INTERFACE STRING {
			if (strlcpy(thingsd->tcp_iface, $4,
			    sizeof(thingsd->tcp_iface)) >=
			    sizeof(thingsd->tcp_iface)) {
				yyerror("%s: thingsd tcp_iface truncated",
				    __func__);
				free($4);
				free(thingsd);
				YYERROR;
			}
			if (strlcpy(thingsd->udp_iface, $4,
			    sizeof(thingsd->udp_iface)) >=
			    sizeof(thingsd->udp_iface)) {
				yyerror("%s: thingsd udp_iface truncated",
				    __func__);
				free($4);
				free(thingsd);
				YYERROR;
			}
			free($4);
		}
		| BIND UDP INTERFACE STRING {
			memset(&thingsd->udp_iface, 0,
			    sizeof(thingsd->udp_iface));
			if (strlcpy(thingsd->udp_iface, $4,
			    sizeof(thingsd->udp_iface)) >=
			    sizeof(thingsd->udp_iface)) {
				yyerror("%s: thingsd udp_iface truncated",
				    __func__);
				free($4);
				free(thingsd);
				YYERROR;
			}
			free($4);
		}
		;

bindopts2	: BIND TCP INTERFACE STRING {
			if (strlcpy(new_thing->conf.tcp_iface, $4,
			    sizeof(new_thing->conf.tcp_iface)) >=
			    sizeof(new_thing->conf.tcp_iface)) {
				yyerror("%s: new_thing tcp_iface truncated",
				    __func__);
				free($4);
				free(new_thing);
				YYERROR;
			}
			if (strlen(new_thing->conf.udp_iface) == 0) {
				if (strlcpy(new_thing->conf.udp_iface, $4,
				    sizeof(new_thing->conf.udp_iface)) >=
				    sizeof(new_thing->conf.udp_iface)) {
					yyerror("%s: new_thing udp_iface "
					    "truncated", __func__);
					free($4);
					free(new_thing);
					YYERROR;
				}
			}
			free($4);
		}
		| BIND UDP INTERFACE STRING {
			if (strlcpy(new_thing->conf.udp_iface, $4,
			    sizeof(new_thing->conf.udp_iface)) >=
			    sizeof(new_thing->conf.udp_iface)) {
				yyerror("%s: new_thing udp_iface truncated",
				    __func__);
				free($4);
				free(new_thing);
				YYERROR;
			}
			free($4);
		}
		;

dosub		: SUBSCRIBE '{' optnl subopts '}'
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = newfile($2, 1)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

port		: NUMBER {
			if ($1 <= 0 || $1 > (int)USHRT_MAX) {
				yyerror("invalid port: %lld", $1);
				YYERROR;
			}
			$$.val[0] = htons($1);
			$$.op = 1;
		}
		| STRING {
			int	 val;

			if ((val = getservice($1)) == -1) {
				yyerror("invalid port: %s", $1);
				free($1);
				YYERROR;
			}
			free($1);

			$$.val[0] = val;
			$$.op = 1;
		}
		;

locationopts	: /* empty */
		| '{' optnl locationopts2 '}'
		;

locationopts1	: bindopts2
		| BAUD NUMBER {
			int		 bc;
			const int	 bauds = (sizeof(baudrates) /
					    sizeof(const int));

			new_thing->conf.baud = -1;
			for (bc = 0; bc < bauds; bc++) {
				if ($2 == baudrates[bc]) {
					new_thing->conf.baud = $2;
					continue;
				}
			}
			if (new_thing->conf.baud == -1) {
				yyerror("baud rate syntax error");
				YYERROR;
			}
		}
		| DATA NUMBER {
			if ($2 > 8 || $2 < 5) {
				yyerror("data bits syntax error");
				YYERROR;
			} else
				new_thing->conf.data_bits = $2;
		}
		| HARDWARE NUMBER {
			if ($2 > 1 || $2 < 0) {
				yyerror("hardware syntax error");
				YYERROR;
			} else if ($2 > 0)
				new_thing->conf.hw_ctl = 1;
		}
		| LISTEN ON opttls PORT port {
			struct thing	*thing;

			TAILQ_FOREACH(thing, thingsd->things, entry) {
				if (thing->conf.tcp_listen_port.val[0] ==
				    $5.val[0]) {
					yyerror("tls port already assigned");
					YYERROR;
				}
			}

			new_thing->conf.tcp_listen_port.val[0] = $5.val[0];
			new_thing->conf.tcp_listen_port.op = $5.op;
		}
		| maxclientssub
		| PASSWORD STRING {
			if (strlcpy(new_thing->conf.password, $2,
			    sizeof(new_thing->conf.password)) >=
			    sizeof(new_thing->conf.password)) {
				yyerror("%s: new_thing password truncated",
				    __func__);
				free($2);
				free(new_thing);
				YYERROR;
			}
			free($2);
		}
		| PARITY STRING {
			int		 pc;
			const int	 parities = (sizeof(parity) /
					     sizeof(const char *));

			for (pc = 0; pc < parities; pc++) {
				if (strcmp($2, parity[pc]) == 0) {
					if (strlcpy(new_thing->conf.parity, $2,
					    sizeof(new_thing->conf.parity)) >=
					    sizeof(new_thing->conf.parity)) {
						yyerror("%s: new_thing parity "
						    "truncated", __func__);
						free($2);
						free(new_thing);
						YYERROR;
					}
					continue;
				}
			}
			if (strlen(new_thing->conf.parity) == 0) {
				free($2);
				yyerror("parity syntax error");
				YYERROR;
			}
			free($2);
		}
		| SOFTWARE NUMBER {
			if ($2 > 1 || $2 < 0) {
				yyerror("software syntax error");
				YYERROR;
			} else
				new_thing->conf.sw_ctl = 1;
		}
		| STOP NUMBER {
			if ($2 > 2 || $2 < 1) {
				yyerror("stop bits syntax error");
				YYERROR;
			} else if ($2 > 0)
				new_thing->conf.stop_bits = $2;
		}
		| TLS tlsopts {
			if (new_thing->conf.tls == 0) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
		;

locationopts2	: locationopts2 locationopts1 nl
		| locationopts1 optnl
		;

maxclients	: MAX CLIENTS NUMBER {
			thingsd->max_clients = $3;
		}
		;

maxclientssub	: MAX CLIENTS NUMBER {
			new_thing->conf.max_clients = $3;
		}
		;

name		: NAME optcomma STRING {
			memset(&my_name, 0, sizeof(my_name));
			memcpy(&pclient->name, $3, sizeof(pclient->name));
			memcpy(&my_name, $3, sizeof(my_name));
			free($3);
		}
		;

nl		: '\n' optnl
		;

optcomma	: ',' optcomma
		| /* empty */
		;

optnl		: '\n' optnl		/* zero or more newlines */
		| /* empty */
		;

opttls		: /* empty */ {
			$$ = 0;
			new_thing->conf.tls = 0;
		}
		| TLS {
			$$ = 1;
			new_thing->conf.tls = 1;
		}
		;

socketopts1	: CONNECT ON PORT port {
			new_thing->conf.tcp_conn_port.val[0] = $4.val[0];
			new_thing->conf.tcp_conn_port.op = $4.op;
		}
		| LISTEN ON opttls PORT port {
			struct thing	*thing;
			TAILQ_FOREACH(thing, thingsd->things, entry) {
				if (thing->conf.tcp_listen_port.val[0] ==
				    $5.val[0]) {
					yyerror("port already assigned");
					YYERROR;
				}
			}

			new_thing->conf.tcp_listen_port.val[0] = $5.val[0];
			new_thing->conf.tcp_listen_port.op = $5.op;
		}
		| RECEIVE ON PORT port {
			struct thing *thing;
			TAILQ_FOREACH(thing, thingsd_env->things, entry) {
				if (thing->conf.udp_rcv_port.val[0] == 0 ||
				    $4.val[0] == 0)
					continue;
				if (thing->conf.udp_rcv_port.val[0] ==
				    $4.val[0]) {
					yyerror("UDP thing receive ports must "
					   "be unique");
					   YYERROR;
				}
			}
			new_thing->conf.udp_rcv_port.val[0] = $4.val[0];
			new_thing->conf.udp_rcv_port.op = $4.op;

			/* if((new_thing->conf.udp_rcv_port = */
			/*     strdup($4)) == NULL) */
			/* 	fatal("%s: strdup", __func__); */
			/* free($4); */
		}
		| PASSWORD STRING {
			if (strlcpy(new_thing->conf.password, $2,
			    sizeof(new_thing->conf.password)) >=
			    sizeof(new_thing->conf.password)) {
				yyerror("%s: new_thing password truncated",
				    __func__);
				free($2);
				free(new_thing);
				YYERROR;
			}
			free($2);
		}
		| PERSISTENT NUMBER {
			if ($2)
				new_thing->conf.persist = 1;
			else
				new_thing->conf.persist = 0;
		}
		| TLS tlsopts {
			if (new_thing->conf.tls == 0) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
		| bindopts2
		| maxclientssub
		;

socketopts2	: socketopts2 socketopts1 nl
		| socketopts1 optnl
		;

string		: string STRING {
			if (asprintf(&$$, "%s %s", $1, $2) == -1) {
				free($1);
				free($2);
				yyerror("string: asprintf");
				YYERROR;
			}
			free($1);
			free($2);
		}
		| STRING
		;

subopts		: {
		} '{' name '}' optcomma '{' things '}'
		;

subthings	: THING '{' STRING optcomma STRING '}' {
			struct socket	*sock = pclient->sock, *tsock;
			struct socket	*psock = NULL, *csock = NULL;
			struct client	*clt;

			/* check thing name */
			if ((strcmp(sock->conf.thing_name, $3)) != 0)
				goto done;

			/* check we have the password */
			if (strcmp(sock->conf.password, $5) != 0)
				goto done;

			/* check that ports match */
			if (sock->conf.port.val[0] != pclient->port.val[0])
				goto done;

			/*
			 * XXX: check from here down don't actually work
			 * when prefork is > 1
			 * come back and figure this out later
			 * probably a way to loop through the processes and
			 * check all
			 */

			/* check for duplicate name on socket */
			TAILQ_FOREACH(tsock, thingsd_env->sockets, entry) {
				TAILQ_FOREACH(clt, tsock->clients, entry) {
					if (strcmp(clt->name, my_name) == 0 &&
					    clt->subscribed) {
						log_warnx("client exists");
						goto done;
					}
				}
			}

			/* check parent/child counts */
			if (sock->conf.child_id) {
				TAILQ_FOREACH(csock, thingsd_env->sockets,
				    entry)
					if (csock->conf.id ==
					    sock->conf.child_id)
						break;
			}
			if (sock->conf.parent_id) {
				TAILQ_FOREACH(psock, thingsd_env->sockets,
				    entry)
					if (psock->conf.id ==
					    sock->conf.parent_id)
						break;
			}

			/* if counts are fine, subscribe client */
			if (sock->conf.max_clients > 0 &&
			    (sock->client_cnt + 1 >
			    sock->conf.max_clients)) {
				log_debug("max clients reached for listener %d",
				    sock->conf.id);
			} else {
				pclient->subscribed = 1;

				sock->client_cnt++;
				if (csock != NULL)
					csock->client_cnt++;
				if (psock != NULL)
					psock->client_cnt++;

				log_debug("client %s subscribed to %s",
				    pclient->name, $3);
			}
done:
			free($3);
			free($5);
		}
		;

subthings2	: subthings2 subthings
		| subthings
		;

thing		: THING STRING {
       			thing_id++;
			new_thing = thingsd_conf_new_thing(thingsd_env, NULL,
			    $2, thing_id);

			if (strlcpy(new_thing->conf.name, $2,
			    sizeof(new_thing->conf.name)) >=
			    sizeof(new_thing->conf.name)) {
				yyerror("thing name truncated");
				free($2);
				free(new_thing);
				YYERROR;
			}

			if (strlcpy(new_thing->conf.name, $2,
			    sizeof(new_thing->conf.name)) >=
			    sizeof(new_thing->conf.name)) {
				yyerror("thing name truncated");
				free($2);
				free(new_thing);
				YYERROR;
			}

			new_thing->exists = 0;
			new_thing->fd = -1;
			new_thing->conf.id = thing_id;

			if (strlen(thingsd->tcp_iface) != 0) {
				if (strlcpy(new_thing->conf.tcp_iface,
				    thingsd->tcp_iface,
				    sizeof(new_thing->conf.tcp_iface)) >=
				    sizeof(new_thing->conf.tcp_iface)) {
					yyerror("%s: new_thing tcp_iface "
					    "truncated",
					    __func__);
					free(new_thing);
					YYERROR;
				}
			} else
				memset(new_thing->conf.tcp_iface, 0,
				    sizeof(new_thing->conf.tcp_iface));

			if ((new_thing->conf.tcp_al = calloc(1,
			    sizeof(*new_thing->conf.tcp_al))) == NULL)
				fatalx("%s: calloc", __func__);

			TAILQ_INIT(new_thing->conf.tcp_al);

			if ((new_thing->conf.udp_al = calloc(1,
			    sizeof(*new_thing->conf.udp_al))) == NULL)
				fatalx("%s: calloc", __func__);

			TAILQ_INIT(new_thing->conf.udp_al);

			if (strlen(thingsd->udp_iface) != 0) {
				if (strlcpy(new_thing->conf.udp_iface,
				    thingsd->udp_iface,
				    sizeof(new_thing->conf.udp_iface)) >=
				    sizeof(new_thing->conf.udp_iface)) {
					yyerror("%s: new_thing udp_iface "
					    "truncated",
					    __func__);
					free(new_thing);
					YYERROR;
				}
			} else
				memset(new_thing->conf.udp_iface, 0,
				    sizeof(new_thing->conf.udp_iface));

			memset(new_thing->conf.location, 0,
			    sizeof(new_thing->conf.location));
			memset(new_thing->conf.ipaddr, 0,
			    sizeof(new_thing->conf.ipaddr));
			memset(new_thing->conf.udp, 0,
			    sizeof(new_thing->conf.udp));
			memset(new_thing->conf.password, 0,
			    sizeof(new_thing->conf.password));
			memset(new_thing->conf.parity, 0,
			    sizeof(new_thing->conf.parity));

			new_thing->conf.max_clients = thingsd->max_clients;

			new_thing->conf.baud = DEFAULT_BAUD;
			new_thing->conf.data_bits = -1;
			new_thing->conf.stop_bits = -1;
			new_thing->conf.hw_ctl = 0;
			new_thing->conf.sw_ctl = 0;
			new_thing->conf.persist = 1;

			new_thing->conf.tls_protocols = TLS_PROTOCOLS_DEFAULT;
			new_thing->conf.tls_flags = 0;

			memset(new_thing->conf.tls_ciphers, 0,
			    sizeof(new_thing->conf.tls_ciphers));
			memset(new_thing->conf.tls_dhe_params, 0,
			    sizeof(new_thing->conf.tls_dhe_params));
			memset(new_thing->conf.tls_ecdhe_curves, 0,
			    sizeof(new_thing->conf.tls_ecdhe_curves));

			if((new_thing->conf.tls_cert_file =
			    strdup(TLS_CERT)) == NULL)
				fatal("%s: strdup", __func__);
			if((new_thing->conf.tls_key_file =
			    strdup(TLS_KEY)) == NULL)
				fatal("%s: strdup", __func__);

			strlcpy(new_thing->conf.tls_ciphers, TLS_CIPHERS,
			    sizeof(new_thing->conf.tls_ciphers));
			strlcpy(new_thing->conf.tls_dhe_params, TLS_DHE_PARAMS,
			    sizeof(new_thing->conf.tls_dhe_params));
			strlcpy(new_thing->conf.tls_ecdhe_curves,
			    TLS_ECDHE_CURVES,
			    sizeof(new_thing->conf.tls_ecdhe_curves));
			free($2);

		} '{' optnl thingopts2 '}' {
			if (new_thing->conf.tcp_listen_port.val[0] == 0) {
				yyerror("thing listen port required");
				YYERROR;
			}
			if (strlen(new_thing->conf.ipaddr) != 0 &&
			    new_thing->conf.tcp_conn_port.val[0] == 0) {
				yyerror("ipaddr connect port required");
				YYERROR;
			}
			if (strlen(new_thing->conf.ipaddr) != 0 &&
			    strlen(new_thing->conf.location) != 0) {
				yyerror("too many ipaddr device arguments");
				YYERROR;
			}
			if (strlen(new_thing->conf.udp) != 0 &&
			    strlen(new_thing->conf.udp_iface) == 0) {
				yyerror("udp bind interface required");
				YYERROR;
			}
			if (strlen(new_thing->conf.udp) != 0 &&
			    new_thing->conf.udp_rcv_port.val[0] == 0) {
				yyerror("udp receive port required");
				YYERROR;
			}
			if (strlen(new_thing->conf.udp) != 0 &&
			    strlen(new_thing->conf.location) != 0) {
				yyerror("too many udp device arguments");
				YYERROR;
			}

			if (get_addrs(new_thing->conf.tcp_iface,
			    new_thing->conf.tcp_al,
			    &new_thing->conf.tcp_listen_port) == -1) {
				yyerror("could not get tcp iface addrs");
				YYERROR;
			}

			if (get_addrs(new_thing->conf.udp_iface,
			    new_thing->conf.udp_al,
			    &new_thing->conf.udp_rcv_port) == -1) {
				yyerror("could not get udp iface addrs");
				YYERROR;
			}
		}
		;

thingopts1	: IPADDR STRING {
			if (strlen($2) == 0) {
				yyerror("ipaddr string empty");
				YYERROR;
			}
			if (strlcpy(new_thing->conf.ipaddr, $2,
			    sizeof(new_thing->conf.ipaddr)) >=
			    sizeof(new_thing->conf.ipaddr)) {
				yyerror("%s: new_thing ipaddr truncated",
				    __func__);
				free($2);
				free(new_thing);
				YYERROR;
			}
			new_thing->conf.type = S_TCP;
			free($2);
		} '{' optnl socketopts2 '}'
		| LOCATION STRING {
			if (strlcpy(new_thing->conf.location, $2,
			    sizeof(new_thing->conf.location)) >=
			    sizeof(new_thing->conf.location)) {
				yyerror("%s: new_thing location truncated",
				    __func__);
				free($2);
				free(new_thing);
				YYERROR;
			}
			new_thing->conf.type = S_DEV;
			free($2);
		} locationopts
		| UDP STRING {
			if (strlcpy(new_thing->conf.udp, $2,
			    sizeof(new_thing->conf.udp)) >=
			    sizeof(new_thing->conf.udp)) {
				yyerror("%s: new_thing udp truncated",
				    __func__);
				free($2);
				free(new_thing);
				YYERROR;
			}
			new_thing->conf.type = S_UDP;
			free($2);
		} '{' optnl socketopts2 '}'
		;

thingopts2	: thingopts2 thingopts1 nl
		| thingopts1 optnl
		;

thingretry	: CONNECTION RETRY NUMBER {
			if ($3 >= MIN_RETRY && $3 <= MAX_RETRY)
				thingsd->conn_retry = $3;
		}
		;

things		: THINGS '{' subthings2 '}'
		;

tlscltopt	: /* empty */
		| tlscltopt CRL STRING {
			new_thing->conf.tls_flags = TLSFLAG_CRL;
			free(new_thing->conf.tls_crl_file);
			if ((new_thing->conf.tls_crl_file = strdup($3)) == NULL)
				fatal("%s: strdup", __func__);
			free($3);
		}
		| tlscltopt OPTIONAL {
			new_thing->conf.tls_flags |= TLSFLAG_OPTIONAL;
		}
		;

tlsopts		: CERTIFICATE STRING {
			free(new_thing->conf.tls_cert_file);
			if ((new_thing->conf.tls_cert_file =
			    strdup($2)) == NULL)
				fatal("%s: strdup", __func__);
			free($2);
		}
		| CIPHERS STRING {
			if (strlcpy(new_thing->conf.tls_ciphers, $2,
			    sizeof(new_thing->conf.tls_ciphers)) >=
			    sizeof(new_thing->conf.tls_ciphers)) {
				yyerror("ciphers too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| CLIENT CA STRING tlscltopt {
			new_thing->conf.tls_flags |= TLSFLAG_CA;
			free(new_thing->conf.tls_ca_file);
			if ((new_thing->conf.tls_ca_file = strdup($3)) == NULL)
				fatal("%s: strdup", __func__);
			free($3);
		}
		| DHE STRING {
			if (strlcpy(new_thing->conf.tls_dhe_params, $2,
			    sizeof(new_thing->conf.tls_dhe_params)) >=
			    sizeof(new_thing->conf.tls_dhe_params)) {
				yyerror("dhe too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| ECDHE STRING {
			if (strlcpy(new_thing->conf.tls_ecdhe_curves, $2,
			    sizeof(new_thing->conf.tls_ecdhe_curves)) >=
			    sizeof(new_thing->conf.tls_ecdhe_curves)) {
				yyerror("ecdhe too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| KEY STRING {
			free(new_thing->conf.tls_key_file);
			if ((new_thing->conf.tls_key_file = strdup($2)) == NULL)
				fatal("%s: strdup", __func__);
			free($2);
		}
		| OCSP STRING {
			free(new_thing->conf.tls_ocsp_staple_file);
			if ((new_thing->conf.tls_ocsp_staple_file =
			    strdup($2)) == NULL)
				fatal("%s: strdup", __func__);
			free($2);
		}
		| PROTOCOLS STRING {
			if (tls_config_parse_protocols(
			    &new_thing->conf.tls_protocols, $2) != 0) {
				yyerror("invalid tls protocols");
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

varset		: STRING '=' string		{
			char *s = $1;
			if (thingsd->thingsd_verbose)
				printf("%s = \"%s\"\n", $1, $3);
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* This has to be sorted always. */
	static const struct keywords keywords[] = {
		{ "baud",		BAUD },
		{ "bind",		BIND },
		{ "ca",			CA },
		{ "certificate",	CERTIFICATE },
		{ "ciphers",		CIPHERS },
		{ "client",		CLIENT },
		{ "clients",		CLIENTS },
		{ "connect",		CONNECT },
		{ "connection",		CONNECTION },
		{ "crl",		CRL },
		{ "data",		DATA },
		{ "dhe",		DHE },
		{ "ecdhe",		ECDHE },
		{ "hardware",		HARDWARE },
		{ "include",		INCLUDE },
		{ "interface",		INTERFACE },
		{ "ipaddr",		IPADDR },
		{ "key",		KEY },
		{ "listen",		LISTEN },
		{ "location",		LOCATION },
		{ "max",		MAX },
		{ "name",		NAME },
		{ "ocsp",		OCSP },
		{ "on",			ON },
		{ "optional",		OPTIONAL },
		{ "parity",		PARITY },
		{ "password",		PASSWORD },
		{ "persistent",		PERSISTENT },
		{ "port",		PORT },
		{ "prefork",		PREFORK },
		{ "protocols",		PROTOCOLS },
		{ "receive",		RECEIVE },
		{ "retry",		RETRY },
		{ "software",		SOFTWARE },
		{ "stop",		STOP },
		{ "subscribe",		SUBSCRIBE },
		{ "tcp",		TCP },
		{ "thing",		THING },
		{ "things",		THINGS },
		{ "tls",		TLS },
		{ "udp",		UDP },
		{ "verbose",		VERBOSE}
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

unsigned char	*parsebuf;
int		 parseindex;
unsigned char	 pushback_buffer[MAXPUSHBACK];
int		 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c = 0, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			if (parsebuf == NULL)
				return (0);
			if (parseindex > pkt_len)
				return (0);
			if ((c = parsebuf[parseindex++]) != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if (parseindex > 0) {
			/* malformed packet */
			yyerror("reached end of packet while parsing "
			"quoted string");
			return (-1);
		}
		c = getc(file->stream);
		if (c == EOF)
			yyerror("reached end of file while parsing "
			    "quoted string");
		return (c);
	}

	if (parseindex == 0) {
		while ((c = getc(file->stream)) == '\\') {
			if ((next = getc(file->stream)) != '\n') {
				c = next;
				break;
			}
			yylval.lineno = file->lineno;
			file->lineno++;
		}
	}

	parseindex = 0;
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* Skip to either EOF or the first real EOL. */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	unsigned char	 buf[8096];
	unsigned char	*p, *val;
	int		 quotec, next, c;
	int		 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		if ((val = symget(buf)) == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		if ((yylval.v.string = strdup(buf)) == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING) {
			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL)
				err(1, "yylex: strdup");
		}
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: thing writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

struct file *
newfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("calloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("strdup");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	return (nfile);
}

struct file *
newbuff(u_char *pkt)
{
	struct file	*bfile;

	if ((bfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("calloc");
		return (NULL);
	}
	if ((bfile->name = strdup("subscribe buffer")) == NULL) {
		log_warn("strdup");
		free(bfile);
		return (NULL);
	}
	if ((parsebuf = pkt) == NULL) {
		log_warn("%s", bfile->name);
		free(bfile->name);
		free(bfile);
		return (NULL);
	}
	bfile->lineno = 1;
	return (bfile);
}

static void
closefile(struct file *xfile)
{
	fclose(xfile->stream);
	free(xfile->name);
	free(xfile);
}

static void
closebuff(struct file *xfile)
{
	free(xfile->name);
	free(xfile);
}

int
parse_config(const char *filename, struct thingsd *env)
{
	struct sym	*sym, *next;

	if ((file = newfile(filename, 0)) == NULL) {
		log_warn("failed to open %s", filename);
		return (0);
	}

	if (config_init(env) == -1)
		fatal("failed to initialize configuration");

	thingsd = env;

	thingsd->conn_retry = CONN_RETRY;
	/* thingsd->dead_things->run = 1; */
	thingsd->run = 1;

	yyparse();
	errors = file->errors;
	closefile(file);
	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if ((thingsd->thingsd_verbose > 1) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not used\n",
			    sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (errors)
		return (-1);

	/* setup our listening sockets */
	sockets_parse_sockets(env);

	return (0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);
	if ((sym->nam = strdup(nam)) == NULL) {
		free(sym);
		return (-1);
	}
	if ((sym->val = strdup(val)) == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	 ret;
	size_t	 len;

	val = strrchr(s, '=');
	if (val == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		fatal("%s: malloc", __func__);

	memcpy(&sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

int
parse_buf(struct client *client, u_char *pkt, int len)
{
	pkt_len = len;
	pclient = client;
	my_fd = client->fd;

	if ((file = newbuff(pkt)) == NULL)
		return (-1);

	yyparse();
	errors = file->errors;

	closebuff(file);

	return (errors ? -1 : 0);
}

void
clear_config(struct thingsd *xconf)
{
	struct thing	*thing;

	while ((thing = TAILQ_FIRST(xconf->things)) != NULL) {
		TAILQ_REMOVE(xconf->things, thing, entry);
		free(thing);
	}

	free(xconf);
}

int
getservice(char *n)
{
	struct servent	*s;
	const char	*errstr;
	long long	 llval;

	llval = strtonum(n, 0, UINT16_MAX, &errstr);
	if (errstr) {
		s = getservbyname(n, "tcp");
		if (s == NULL)
			s = getservbyname(n, "udp");
		if (s == NULL)
			return (-1);
		return (s->s_port);
	}

	return (htons((unsigned short)llval));
}

struct address *
host_v4(const char *s)
{
	struct in_addr		 ina;
	struct sockaddr_in	*sain;
	struct address		*h;

	memset(&ina, 0, sizeof(ina));
	if (inet_pton(AF_INET, s, &ina) != 1)
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(__func__);
	sain = (struct sockaddr_in *)&h->ss;
	sain->sin_len = sizeof(struct sockaddr_in);
	sain->sin_family = AF_INET;
	sain->sin_addr.s_addr = ina.s_addr;
	if (sain->sin_addr.s_addr == INADDR_ANY)
		h->prefixlen = 0; /* 0.0.0.0 address */
	else
		h->prefixlen = -1; /* host address */
	return (h);
}

struct address *
host_v6(const char *s)
{
	struct addrinfo		 hints, *res;
	struct sockaddr_in6	*sa_in6;
	struct address		*h = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, "0", &hints, &res) == 0) {
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(__func__);
		sa_in6 = (struct sockaddr_in6 *)&h->ss;
		sa_in6->sin6_len = sizeof(struct sockaddr_in6);
		sa_in6->sin6_family = AF_INET6;
		memcpy(&sa_in6->sin6_addr,
		    &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
		    sizeof(sa_in6->sin6_addr));
		sa_in6->sin6_scope_id =
		    ((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id;
		if (memcmp(&sa_in6->sin6_addr, &in6addr_any,
		    sizeof(sa_in6->sin6_addr)) == 0)
			h->prefixlen = 0; /* any address */
		else
			h->prefixlen = -1; /* host address */
		freeaddrinfo(res);
	}

	return (h);
}

int
host_dns(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct addrinfo		 hints, *res0, *res;
	int			 error, cnt = 0;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct address		*h;

	if ((cnt = host_if(s, al, max, port, ifname, ipproto)) != 0)
		return (cnt);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /* DUMMY */
	hints.ai_flags = AI_ADDRCONFIG;
	error = getaddrinfo(s, NULL, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		return (0);
	if (error) {
		log_warnx("%s: could not parse \"%s\": %s", __func__, s,
		    gai_strerror(error));
		return (-1);
	}

	for (res = res0; res && cnt < max; res = res->ai_next) {
		if (res->ai_family != AF_INET &&
		    res->ai_family != AF_INET6)
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(__func__);

		if (port != NULL)
			memcpy(&h->port, port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname)) {
				log_warnx("%s: interface name truncated",
				    __func__);
				freeaddrinfo(res0);
				free(h);
				return (-1);
			}
		}
		if (ipproto != -1)
			h->ipproto = ipproto;
		h->ss.ss_family = res->ai_family;
		h->prefixlen = -1; /* host address */

		if (res->ai_family == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    res->ai_addr)->sin_addr.s_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (cnt == max && res) {
		log_warnx("%s: %s resolves to more than %d hosts", __func__,
		    s, max);
	}
	freeaddrinfo(res0);
	return (cnt);
}

int
host_if(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct ifaddrs		*ifap, *p;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct address		*h;
	int			 cnt = 0, af;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	/* First search for IPv4 addresses */
	af = AF_INET;

 nextaf:
	for (p = ifap; p != NULL && cnt < max; p = p->ifa_next) {
		if (p->ifa_addr == NULL ||
		    p->ifa_addr->sa_family != af ||
		    (strcmp(s, p->ifa_name) != 0 &&
		    !is_if_in_group(p->ifa_name, s)))
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal("calloc");

		if (port != NULL)
			memcpy(&h->port, port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname)) {
				log_warnx("%s: interface name truncated",
				    __func__);
				free(h);
				freeifaddrs(ifap);
				return (-1);
			}
		}
		if (ipproto != -1)
			h->ipproto = ipproto;
		h->ss.ss_family = af;
		h->prefixlen = -1; /* host address */

		if (af == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
			sain->sin_len = sizeof(struct sockaddr_in);
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    p->ifa_addr)->sin_addr.s_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    p->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
			sin6->sin6_scope_id = ((struct sockaddr_in6 *)
			    p->ifa_addr)->sin6_scope_id;
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (af == AF_INET) {
		/* Next search for IPv6 addresses */
		af = AF_INET6;
		goto nextaf;
	}

	if (cnt > max) {
		log_warnx("%s: %s resolves to more than %d hosts", __func__,
		    s, max);
	}
	freeifaddrs(ifap);
	return (cnt);
}

int
host(const char *s, struct addresslist *al, int max,
    struct portrange *port, const char *ifname, int ipproto)
{
	struct address *h;

	h = host_v4(s);

	/* IPv6 address? */
	if (h == NULL)
		h = host_v6(s);

	if (h != NULL) {
		if (port != NULL)
			memcpy(&h->port, port, sizeof(h->port));
		if (ifname != NULL) {
			if (strlcpy(h->ifname, ifname, sizeof(h->ifname)) >=
			    sizeof(h->ifname)) {
				log_warnx("%s: interface name truncated",
				    __func__);
				free(h);
				return (-1);
			}
		}
		if (ipproto != -1)
			h->ipproto = ipproto;

		TAILQ_INSERT_HEAD(al, h, entry);
		return (1);
	}

	return (host_dns(s, al, max, port, ifname, ipproto));
}

int
is_if_in_group(const char *ifname, const char *groupname)
{
	unsigned int		 len;
	struct ifgroupreq	 ifgr;
	struct ifg_req		*ifg;
	int			 s;
	int			 ret = 0;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");

	memset(&ifgr, 0, sizeof(ifgr));
	if (strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ) >= IFNAMSIZ)
		err(1, "IFNAMSIZ");
	if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
		if (errno == EINVAL || errno == ENOTTY)
			goto end;
		err(1, "SIOCGIFGROUP");
	}

	len = ifgr.ifgr_len;
	ifgr.ifgr_groups = calloc(len / sizeof(struct ifg_req),
	    sizeof(struct ifg_req));
	if (ifgr.ifgr_groups == NULL)
		err(1, "getifgroups");
	if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1)
		err(1, "SIOCGIFGROUP");

	ifg = ifgr.ifgr_groups;
	for (; ifg && len >= sizeof(struct ifg_req); ifg++) {
		len -= sizeof(struct ifg_req);
		if (strcmp(ifg->ifgrq_group, groupname) == 0) {
			ret = 1;
			break;
		}
	}
	free(ifgr.ifgr_groups);

end:
	close(s);
	return (ret);
}

int
get_addrs(const char *addr, struct addresslist *al, struct portrange *port)
{
	if (strcmp("", addr) == 0) {
		if (host("0.0.0.0", al, 1, port, "0.0.0.0", -1) <= 0) {
			yyerror("invalid listen ip: %s",
			    "0.0.0.0");
			return (-1);
		}
		if (host("::", al, 1, port, "::", -1) <= 0) {
			yyerror("invalid listen ip: %s", "::");
			return (-1);
		}
	} else {
		if (host(addr, al, THINGSD_MAXIFACE, port, addr,
		    -1) <= 0) {
			yyerror("invalid listen ip: %s", addr);
			return (-1);
		}
	}
	return (0);
}
