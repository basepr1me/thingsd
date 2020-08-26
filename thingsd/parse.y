/*
 * Copyright (c) 2016-2019, 2020 Tracey Emery <tracey@traceyemery.net>
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
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <limits.h>
#include <stdbool.h>
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
int		 load_tls(struct thing *);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

void	 clear_config(struct thingsd *xconf);

static int		 errors;

static struct thing		*new_thing;
static struct subscription	*new_sub(char *);

const int		 baudrates[18] = {50, 75, 110, 134, 150, 200,
			    300, 600, 1200, 1800, 2400, 4800, 9600,
			    38400, 57600, 76800, 115200};
const char		*parity[4] = {"none", "odd", "even", "space"};
struct client		*client, *tclient;
char			 my_name[THINGSD_MAXTEXT];
int			 my_fd, pkt_len;
size_t			 pn;

struct thing		*conf_new_thing(char *);

typedef struct {
	union {
		int64_t		 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	BAUD BIND CA CERTIFICATE CIPHERS CLIENT CLIENTS CONNECT CONNECTION CRL
%token	DATA DEFAULT DHE ECDHE ERROR HARDWARE INCLUDE INTERFACE IPADDR KEY
%token	LISTEN LOCATION MAX NAME OCSP ON OPTIONAL PARITY PASSWORD PERSISTENT
%token	PORT PREFORK PROTOCOLS RECEIVE RETRY SOFTWARE STOP SUBSCRIBE
%token	SUBSCRIPTIONS THING THINGS TLS UDP VERBOSE

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.string>	string
%type	<v.number>	opttls

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
		| DEFAULT PORT NUMBER {
			thingsd_env->port = $3;
		}
		| maxclients
		| maxsubs
		| PREFORK NUMBER {
			thingsd_env->prefork_things = $2;
			if ($2 <= 0 || $2 > PROC_MAX_INSTANCES) {
				yyerror("invalid number of preforked "
				    "servers: %lld", $2);
				YYERROR;
			}
		}
		| thingretry
		;

bindopts1	: BIND INTERFACE STRING {
			pn = strlcpy(thingsd_env->iface, $3,
			    sizeof(thingsd_env->iface));
			if (pn >= sizeof(thingsd_env->iface))
				fatalx("%s: thingsd_env->iface too long",
				    __func__);
			free($3);
		}
		;

bindopts2	: BIND INTERFACE STRING {
			pn = strlcpy(new_thing->iface, $3,
			    sizeof(new_thing->iface));
			if (pn >= sizeof(new_thing->iface))
				fatalx("%s: new_thing->iface too long",
				    __func__);
			free($3);
		}
		;

dosub		: SUBSCRIBE '{' optnl subopts '}'
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			nfile = newfile($2, 1);
			if (nfile == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
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

			new_thing->baud = -1;
			for (bc = 0; bc < bauds; bc++) {
				if ($2 == baudrates[bc]) {
					new_thing->baud = $2;
					continue;
				}
			}
			if (new_thing->baud == -1) {
				yyerror("baud rate syntax error");
				YYERROR;
			}
		}
		| DATA NUMBER {
			if ($2 > 8 || $2 < 5) {
				yyerror("data bits syntax error");
				YYERROR;
			} else
				new_thing->data_bits = $2;
		}
		| HARDWARE NUMBER {
			if ($2 > 1 || $2 < 0) {
				yyerror("hardware syntax error");
				YYERROR;
			} else if ($2 > 0)
				new_thing->hw_ctl = true;
		}
		| LISTEN ON opttls PORT NUMBER {
			struct thing	*thing;

			TAILQ_FOREACH(thing, thingsd_env->things, entry) {
				if (thing->port == $5 && (thing->tls || $3)) {
					yyerror("tls port already used");
					YYERROR;
				}
			}
			new_thing->port = $5;
		}
		| maxclientssub
		| PASSWORD STRING {
			pn = strlcpy(new_thing->password, $2,
			    sizeof(new_thing->password));
			if (pn >= sizeof(new_thing->password))
				fatalx("%s: new_thing->password too long",
				    __func__);
			free($2);
		}
		| PARITY STRING {
			int		 pc;
			const int	 parities = (sizeof(parity) /
					     sizeof(const char *));

			for (pc = 0; pc < parities; pc++) {
				if (strcmp($2, parity[pc]) == 0) {
					pn = strlcpy(new_thing->parity, $2,
					    sizeof(new_thing->parity));
					if (pn >= sizeof(new_thing->parity))
						fatalx("%s: new_thing->parity "
						    "too long", __func__);
					continue;
				}
			}
			if (strlen(new_thing->parity) == 0) {
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
				new_thing->sw_ctl = true;
		}
		| STOP NUMBER {
			if ($2 > 2 || $2 < 1) {
				yyerror("stop bits syntax error");
				YYERROR;
			} else if ($2 > 0)
				new_thing->stop_bits = $2;
		}
		| TLS tlsopts {
			if (new_thing->tls == false) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
		;

locationopts2	: locationopts2 locationopts1 nl
		| locationopts1 optnl
		;

maxclients	: MAX CLIENTS NUMBER {
			thingsd_env->max_clients = $3;
		}
		;

maxclientssub	: MAX CLIENTS NUMBER {
			new_thing->max_clients = $3;
		}
		;

maxsubs		: MAX SUBSCRIPTIONS NUMBER {
			thingsd_env->max_subs = $3;
		}
		;

name		: NAME optcomma STRING {
			/* test we're us and set name */
			TAILQ_FOREACH(client, thingsd_env->clients, entry) {
				if (client == tclient) {
					memset(&my_name, 0, sizeof(my_name));
					pn = strlcpy(client->name, $3,
					    sizeof(client->name));
					if (pn >= sizeof(client->name))
						fatalx("%s: client->name too "
						    "long", __func__);
					pn = strlcpy(my_name, $3,
					    sizeof(my_name));
					if (pn >= sizeof(my_name))
						fatalx("%s: my_name too long ",
						    __func__);
					break;
				}
			}
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
			new_thing->tls = false;
		}
		| TLS {
			$$ = 1;
			new_thing->tls = true;
		}
		;

socketopts1	: CONNECT ON PORT NUMBER {
			new_thing->conn_port = $4;
		}
		| LISTEN ON opttls PORT NUMBER {
			struct thing	*thing;
			TAILQ_FOREACH(thing, thingsd_env->things, entry) {
				if (thing->port == $5 && (thing->tls || $3)) {
					yyerror("tls port already used");
					YYERROR;
				}
			}
			new_thing->port = $5;
		}
		| RECEIVE ON PORT NUMBER {
			new_thing->rcv_port = $4;
		}
		| PASSWORD STRING {
			pn = strlcpy(new_thing->password, $2,
			    sizeof(new_thing->password));
			if (pn >= sizeof(new_thing->password))
				fatalx("%s: new_thing->password too long",
				    __func__);
			free($2);
		}
		| PERSISTENT NUMBER {
			if ($2)
				new_thing->persist = true;
			else
				new_thing->persist = false;
		}
		| TLS tlsopts {
			if (new_thing->tls == false) {
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

subthings	: THING '{' STRING optcomma STRING '}' optcomma {
			struct thing		*thing = NULL;
			struct subscription	*sub, *nsub;
			bool			 fail = false;

			/* check for duplicate name and subscriptions */
			TAILQ_FOREACH(client, thingsd_env->clients, entry) {
				if (strlen(client->name) == 0 ||
				    strlen(my_name) == 0)
					continue;
				if (strcmp(client->name, my_name) == 0) {
					if (my_fd != client->fd) {
						fail = true;
						log_warnx("client exists");
					}
					TAILQ_FOREACH(sub,
					    client->subscriptions, entry)
						if (strcmp(sub->thing_name,
						    $3) == 0)
							fail = true;
					break;
				}
			}

			if (fail)
				goto done;

			TAILQ_FOREACH(thing, thingsd_env->things, entry) {
				if (thing->port != client->port) {
					fail = true;
					continue;
				}
				if (strcmp(thing->name, $3) == 0) {
					fail = false;
					break;
				}
			}

			if (thing == NULL || fail)
				goto done;

			if (strcmp(thing->password, $5) == 0) {
				if (client->subs++ >= thingsd_env->max_subs)
					log_warn("max subscriptions reached");
				else {
					client->subscribed = true;
					nsub = new_sub(thing->name);
					TAILQ_INSERT_TAIL(
					    client->subscriptions, nsub, entry);
					client->le++;
					thing->client_cnt++;
					log_info("client %s subscribed to %s",
					    client->name, thing->name);
				}
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
			new_thing = conf_new_thing($2);

			if (strlen(thingsd_env->iface) != 0) {
				pn = strlcpy(new_thing->iface,
				thingsd_env->iface, sizeof(new_thing->iface));
				if (pn >= sizeof(new_thing->iface))
					fatalx("%s: new_thing->iface too long",
					    __func__);
			} else
				memset(new_thing->iface, 0,
				    sizeof(new_thing->iface));

			memset(new_thing->location, 0,
			    sizeof(new_thing->location));
			memset(new_thing->ipaddr, 0, sizeof(new_thing->ipaddr));
			memset(new_thing->udp, 0, sizeof(new_thing->udp));
			memset(new_thing->password, 0,
			    sizeof(new_thing->password));
			memset(new_thing->parity, 0, sizeof(new_thing->parity));

			new_thing->max_clients = thingsd_env->max_clients;
			new_thing->port = thingsd_env->port;
			new_thing->baud = DEFAULT_BAUD;
			new_thing->conn_port = -1;
			new_thing->data_bits = -1;
			new_thing->stop_bits = -1;
			new_thing->hw_ctl = false;
			new_thing->sw_ctl = false;
			new_thing->persist = true;

			new_thing->tls_protocols = TLS_PROTOCOLS_DEFAULT;
			new_thing->tls_flags = 0;

			memset(new_thing->tls_cert_file, 0,
			    sizeof(new_thing->tls_cert_file));
			pn = strlcpy(new_thing->tls_cert_file, TLS_CERT,
			    sizeof(new_thing->tls_cert_file));
			if (pn >= sizeof(new_thing->tls_cert_file))
				fatalx("%s: new_thing->tls_cert_file too long",
				    __func__);
			memset(new_thing->tls_key_file, 0,
			    sizeof(new_thing->tls_key_file));
			pn = strlcpy(new_thing->tls_key_file, TLS_KEY,
			    sizeof(new_thing->tls_key_file));
			if (pn >= sizeof(new_thing->tls_key_file))
				fatalx("%s: new_thing->tls_key_file too long",
				    __func__);
			pn = strlcpy(new_thing->tls_ciphers, TLS_CIPHERS,
			    sizeof(new_thing->tls_ciphers));
			if (pn >= sizeof(new_thing->tls_ciphers))
				fatalx("thing strlcpy");
			pn = strlcpy(new_thing->tls_dhe_params, TLS_DHE_PARAMS,
			    sizeof(new_thing->tls_dhe_params));
			if (pn >= sizeof(new_thing->tls_dhe_params))
				fatalx("thing strlcpy");
			pn = strlcpy(new_thing->tls_ecdhe_curves,
			    TLS_ECDHE_CURVES,
			    sizeof(new_thing->tls_ecdhe_curves));
			if (pn >= sizeof(new_thing->tls_ecdhe_curves))
				fatalx("thing strlcpy");
			free($2);
		} '{' optnl thingopts2 '}' {
			if (strlen(new_thing->ipaddr) != 0 &&
			    new_thing->conn_port == -1) {
				yyerror("ipaddr connect port empty");
				YYERROR;
			}
			if (strlen(new_thing->ipaddr) != 0 &&
			    strlen(new_thing->location) != 0) {
				yyerror("too many ipaddr device arguments");
				YYERROR;
			}
			if (strlen(new_thing->udp) != 0 &&
			    new_thing->rcv_port == -1) {
				yyerror("udp receive port empty");
				YYERROR;
			}
			if (strlen(new_thing->udp) != 0 &&
			    strlen(new_thing->location) != 0) {
				yyerror("too many udp device arguments");
				YYERROR;
			}
			if (thingsd_env->port == 0) {
				yyerror("could not set default port");
				YYERROR;
			}
			if (new_thing->tls)
				if (load_tls(new_thing) == -2)
					YYABORT;
		}
		;

thingopts1	: IPADDR STRING {
			if (strlen($2) == 0) {
				yyerror("ipaddr string empty");
				YYERROR;
			}
			pn = strlcpy(new_thing->ipaddr, $2,
			    sizeof(new_thing->ipaddr));
			if (pn >= sizeof(new_thing->ipaddr))
				fatalx("%s: new_thing->ipaddr too long",
				    __func__);
			free($2);
		} '{' optnl socketopts2 '}'
		| LOCATION STRING {
			pn = strlcpy(new_thing->location, $2,
			    sizeof(new_thing->location));
			if (pn >= sizeof(new_thing->location))
				fatalx("%s: new_thing->location too long",
				    __func__);
			free($2);
		} locationopts
		| UDP STRING {
			pn = strlcpy(new_thing->udp, $2,
			    sizeof(new_thing->udp));
			if (pn >= sizeof(new_thing->udp))
				fatalx("%s: new_thing->udp too long",
				    __func__);
			free($2);
		} '{' optnl socketopts2 '}'
		;

thingopts2	: thingopts2 thingopts1 nl
		| thingopts1 optnl
		;

thingretry	: CONNECTION RETRY NUMBER {
			if ($3 >= MIN_RETRY && $3 <= MAX_RETRY)
				thingsd_env->conn_retry = $3;
		}
		;

things		: THINGS '{' subthings2 '}'
		;

tlscltopt	: /* empty */
		| tlscltopt CRL STRING {
			new_thing->tls_flags = TLSFLAG_CRL;
			pn = strlcpy(new_thing->tls_crl_file, $3,
			    sizeof(new_thing->tls_crl_file));
			if (pn >= sizeof(new_thing->tls_crl_file))
				fatalx("%s: new_thing->tls_crl_file too long",
				    __func__);
			free($3);
		}
		| tlscltopt OPTIONAL {
			new_thing->tls_flags |= TLSFLAG_OPTIONAL;
		}
		;

tlsopts		: CERTIFICATE STRING {
			pn = strlcpy(new_thing->tls_cert_file, $2,
			    sizeof(new_thing->tls_cert_file));
			if (pn >= sizeof(new_thing->tls_cert_file))
				fatalx("%s: new_thing->tls_cert_file too long",
				    __func__);
			free($2);
		}
		| CIPHERS STRING {
			if (strlcpy(new_thing->tls_ciphers, $2,
			    sizeof(new_thing->tls_ciphers)) >=
			    sizeof(new_thing->tls_ciphers)) {
				yyerror("ciphers too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| CLIENT CA STRING tlscltopt {
			new_thing->tls_flags |= TLSFLAG_CA;
			pn = strlcpy(new_thing->tls_ca_file, $3,
			    sizeof(new_thing->tls_ca_file));
			if (pn >= sizeof(new_thing->tls_ca_file))
				fatalx("%s: new_thing->tls_ca_file too long",
				    __func__);
			free($3);
		}
		| DHE STRING {
			if (strlcpy(new_thing->tls_dhe_params, $2,
			    sizeof(new_thing->tls_dhe_params)) >=
			    sizeof(new_thing->tls_dhe_params)) {
				yyerror("dhe too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| ECDHE STRING {
			if (strlcpy(new_thing->tls_ecdhe_curves, $2,
			    sizeof(new_thing->tls_ecdhe_curves)) >=
			    sizeof(new_thing->tls_ecdhe_curves)) {
				yyerror("ecdhe too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| KEY STRING {
			pn = strlcpy(new_thing->tls_key_file, $2,
			    sizeof(new_thing->tls_key_file));
			if (pn >= sizeof(new_thing->tls_key_file))
				fatalx("%s: new_thing->tls_key_file too long",
				    __func__);
			free($2);
		}
		| OCSP STRING {
			pn = strlcpy(new_thing->tls_ocsp_staple_file, $2,
			    sizeof(new_thing->tls_ocsp_staple_file));
			if (pn >= sizeof(new_thing->tls_ocsp_staple_file))
				fatalx("%s: new_thing->tls_ocsp_staple_file "
				    "too long", __func__);
			free($2);
		}
		| PROTOCOLS STRING {
			if (tls_config_parse_protocols(
			    &new_thing->tls_protocols, $2) != 0) {
				yyerror("invalid tls protocols");
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

varset		: STRING '=' string		{
			char *s = $1;
			if (thingsd_env->thingsd_verbose)
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
		{ "default",		DEFAULT },
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
		{ "subscriptions",	SUBSCRIPTIONS },
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
				return(0);
			if (parseindex > pkt_len)
				return(0);
			c = parsebuf[parseindex++];
			if (c != '\0')
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
			next = getc(file->stream);
			if (next != '\n') {
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
			c = lgetc(0);
			if (c == EOF)
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
		val = symget(buf);
		if (val == NULL) {
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
			c = lgetc(quotec);
			if (c == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				next = lgetc(quotec);
				if (next == EOF)
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
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
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
		token = lookup(buf);
		if (token == STRING) {
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

	nfile = calloc(1, sizeof(struct file));
	if (nfile == NULL) {
		log_warn("calloc");
		return (NULL);
	}
	nfile->name = strdup(name);
	if (nfile->name == NULL) {
		log_warn("strdup");
		free(nfile);
		return (NULL);
	}
	nfile->stream = fopen(nfile->name, "r");
	if (nfile->stream == NULL) {
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

	bfile = calloc(1, sizeof(struct file));
	if (bfile == NULL) {
		log_warn("calloc");
		return (NULL);
	}
	bfile->name = strdup("subscribe buffer");
	if (bfile->name == NULL) {
		log_warn("strdup");
		free(bfile);
		return (NULL);
	}
	parsebuf = pkt;
	if (parsebuf == NULL) {
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
parse_config(const char *filename)
{
	struct sym	*sym, *next;

	file = newfile(filename, 0);
	if (file == NULL) {
		log_warn("failed to open %s", filename);
		return (0);
	}

	TAILQ_INIT(thingsd_env->things);
	thingsd_env->client_fptr = client_do_chk;
	thingsd_env->conn_retry = CONN_RETRY;
	thingsd_env->dead_things->run = 1;

	yyparse();
	errors = file->errors;
	closefile(file);
	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if ((thingsd_env->thingsd_verbose > 1) && !sym->used)
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
	sym = calloc(1, sizeof(*sym));
	if (sym == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
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
	sym = malloc(len);
	if (sym == NULL)
		fatal("%s: malloc", __func__);

	strlcpy(sym, s, len);

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
parse_buf(struct client *pclient, u_char *pkt, int len)
{
	pkt_len = len;
	tclient = pclient;
	my_fd = tclient->fd;

	file = newbuff(pkt);
	if (file == NULL)
		return (-1);

	yyparse();
	errors = file->errors;

	closebuff(file);

	return (errors ? -1 : 0);
}

struct subscription *
new_sub(char *name)
{
	struct subscription	*sub;
	size_t			 n;

	sub = calloc(1, sizeof(*sub));
	if (sub == NULL)
		fatal("%s: calloc", __func__);
	memset(&sub->thing_name, 0, sizeof(sub->thing_name));
	n = strlcpy(sub->thing_name, name, sizeof(sub->thing_name));
	if (n >= sizeof(sub->thing_name))
		fatalx("%s: sub->thing_name too long", __func__);

	return (sub);
}

struct thing *
conf_new_thing(char *name)
{
	struct thing	*thing;
	size_t		 n;

	TAILQ_FOREACH(thing, thingsd_env->things, entry) {
		if (strcmp(name, thing->name) == 0)
			return (thing);
	}

	thing = calloc(1, sizeof(*thing));
	if (thing == NULL)
		fatal("%s: calloc", __func__);
	n = strlcpy(thing->name, name, sizeof(thing->name));
	if (n >= sizeof(thing->name))
		fatalx("%s: thing->name too long", __func__);

	TAILQ_INSERT_TAIL(thingsd_env->things, thing, entry);

	return (thing);
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
load_tls(struct thing *thing)
{
	if (tls_load_keypair(thing) == -1) {
		log_warnx("%s:%d: thing \"%s\": failed to load public/private"
		    " keys", file->name, yylval.lineno, thing->name);
		return -1;
	}
	if (tls_load_ca(thing) == -1) {
		yyerror("failed to load ca cert(s) for thing %s", thing->name);
		return -2;
	}
	if (tls_load_crl(thing) == -1) {
		yyerror("failed to load crl(s) for thing %s", thing->name);
		free(thing);
		return -2;
	}
	if (tls_load_ocsp(thing) == -1) {
		yyerror("failed to load ocsp staple for thing %s", thing->name);
		free(thing);
		return -2;
	}
	return 0;
}
