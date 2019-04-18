/*
 * Copyright (c) 2016-2019 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2007 - 2015 Reyk Floeter <reyk@openbsd.org>
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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <ctype.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>

#include "thingsd.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);

static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;

extern struct thgsd		*pthgsd;
extern struct dthgs		*pdthgs;

struct clt			*clt, *tclt;
struct file			*pushfile(const char *);
struct file			*pushbuff(u_char *);
struct thg			*newthg;

const int			 baudrates[18] = {50, 75, 110, 134, 150, 200,
				     300, 600, 1200, 1800, 2400, 4800, 9600,
				     38400, 57600, 76800, 115200};
const int			 cbauds = (sizeof(baudrates) /
				     sizeof(const int));
const char			*parity[4] = {"none", "odd", "even", "space"};
const int			 sparity = (sizeof(parity) /
				     sizeof(const char *));

int				 bc, pc, my_fd, pkt_len;
int				 popfile(void);
int				 popbuff(void);
int				 yyparse(void);
int				 yylex(void);
int				 yy_flush_buffer(void); /* look up */
int				 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int				 kw_cmp(const void *, const void *);
int				 lookup(char *);
int				 lgetc(int);
int				 lungetc(int);
int				 findeol(void);
int				 load_tls(struct thg *);

size_t				 n;

char				*my_name;

typedef struct {
	union {
		int		 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;
%}

%token	BAUD DATA PARITY STOP HARDWARE SOFTWARE PASSWORD NAME RETRY PERSISTENT
%token	LOG VERBOSE CONNECT THING LISTEN LOCATION IPADDR UDP THINGS CONNECTION
%token	DEFAULT PORT MAX CLIENTS SUBSCRIPTIONS BIND INTERFACE SUBSCRIBE TLS
%token	ERROR RECEIVE CERTIFICATE CIPHERS CLIENT CA CRL OPTIONAL DHE ECDHE KEY
%token	OCSP PROTOCOLS ON
%token	<v.string>		STRING
%token	<v.number>		NUMBER
%type	<v.number>		opttls

%%
grammar		: /* empty */
		| grammar '\n'
		| grammar main '\n'
		| grammar dosub
		| grammar error '\n' { file->errors++; }
		;
opttls		: /*empty*/ {
			$$ = 0;
			newthg->tls = false;
		}
		| TLS {
			$$ = 1;
			newthg->tls = true;
		}
		;
main		: DEFAULT PORT NUMBER {
			pthgsd->port = $3;
		}
		| maxclients
		| maxsubs
		| bindopts1
		| logging
		| thing
		| thgretry
		;
dosub		: SUBSCRIBE '{' subopts '}'
		;
subopts		: {
	 	/* empty */
		} '{' name '}' ',' '{' things '}'
		;
name		: NAME ',' STRING {
      			/* test we're us and set name */
      			TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
				if (clt == tclt) {
					clt->name = $3;
					my_name = $3;
					break;
				}
			}
		}
;
things		: THINGS '{' subthgs2 '}'
		;
subthgs2	: subthgs2 subthgs
		| subthgs
		;
subthgs		: THING '{' STRING ',' STRING '}' optcomma {
	 		struct thg		*thg;
			bool			 fail = false;

			/* check for duplicate name and subscriptions */
      			TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
				if (clt->name == NULL || my_name == NULL)
					continue;
				if (strcmp(clt->name, my_name) == 0) {
					if (my_fd != clt->fd) {
						fail = true;
						log_warnx("client exists");
					}
					for (n = 0; n < clt->le; n++)
						if (strcmp(clt->sub_names[n],
						    $3) == 0)
							fail = true;
					break;
				}
			}
			/*
			 * fail from previous tests
			 * check correct port
			 * test max subscriptions
			 * subscribe
			 */
			TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
				if (fail)
					continue;
				if (thg->port != clt->port)
					continue;
				if (strcmp(thg->name, $3) == 0)
					if (strcmp(thg->password, $5) == 0) {
						if (clt->subs++ >=
						    pthgsd->max_sub) {
						    	log_warn("max "
							    "subscriptions "
							    "reached");
							continue;
						}
						clt->subscribed = true;
						clt->sub_names[clt->le]
						    = thg->name;
						clt->le++;
						thg->clt_cnt++;
						log_info("client %s subscribed "
						    "to %s", clt->name,
						    thg->name);
						continue;
					}
			}
		}
		;
logging		: LOG VERBOSE NUMBER {
	 		if (pthgsd->debug == 0)
				pthgsd->verbose = $3;
		}
		;
bindopts1	: BIND INTERFACE STRING {
			pthgsd->iface = $3;
		}
		;
bindopts2	: BIND INTERFACE STRING {
			newthg->iface = $3;
		}
		;
maxclients	: MAX CLIENTS NUMBER {
			pthgsd->max_clt = $3;
		}
		;
maxclientssub	: MAX CLIENTS NUMBER {
			newthg->max_clt = $3;
		}
		;
thgretry	: CONNECTION RETRY NUMBER {
			if ($3 >= MIN_RTRY && $3 <= MAX_RTRY)
				pthgsd->conn_rtry = $3;
		}
		;
maxsubs		: MAX SUBSCRIPTIONS NUMBER {
			pthgsd->max_sub = $3;
		}
		;
locopts		: /* empty */
		|  '{' optnl locopts2 '}'
		;
locopts2	: locopts2 locopts1 nl
		| locopts1 optnl
		;
locopts1	: LISTEN ON opttls PORT NUMBER {
			struct thg		*thg;

			TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
				if (thg->port == $5 && (thg->tls || $3)) {
					yyerror("tls port already used");
					YYERROR;
				}
			}
	 		newthg->port = $5;
		}
		| BAUD NUMBER {
			newthg->baud = -1;
			for (bc = 0; bc < cbauds; bc++) {
				if ($2 == baudrates[bc]) {
					newthg->baud = $2;
					continue;
				}
			}
			if (newthg->baud == -1) {
				yyerror("baud rate syntax error");
				YYERROR;
			}
		}
		| DATA NUMBER {
			if ($2 > 8 || $2 < 5) {
				yyerror("data bits syntax error");
				YYERROR;
			} else
				newthg->data_bits = $2;
		}
		| PARITY STRING {
			for (pc = 0; pc < sparity; pc++) {
				if (strcmp($2, parity[pc]) == 0) {
					newthg->parity = $2;
					continue;
				}
			}
			if (newthg->parity == NULL) {
				yyerror("parity syntax error");
				YYERROR;
			}
		}
		| STOP NUMBER {
			if ($2 > 2 || $2 < 1) {
				yyerror("stop bits syntax error");
				YYERROR;
			} else if ($2 > 0)
				newthg->stop_bits = $2;
		}
		| HARDWARE NUMBER {
			if ($2 > 1 || $2 < 0) {
				yyerror("hardware syntax error");
				YYERROR;
			} else if ($2 > 0)
				newthg->hw_ctl = true;
		}
		| SOFTWARE NUMBER {
			if ($2 > 1 || $2 < 0) {
				yyerror("software syntax error");
				YYERROR;
			} else
				newthg->sw_ctl = true;
		}
		| PASSWORD STRING {
			if ((newthg->password = strdup($2)) == NULL)
				fatalx("out of memory");
			free($2);
		}
		| bindopts2
		| maxclientssub
		| TLS tlsopts {
			if (newthg->tls == false) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
		;
socopts2	: socopts2 socopts1 nl
		| socopts1 optnl
		;
socopts1	: LISTEN ON opttls PORT NUMBER {
			struct thg		*thg;

			TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
				if (thg->port == $5 && (thg->tls || $3)) {
					yyerror("tls port already used");
					YYERROR;
				}
			}
			newthg->port = $5;
		}
		| CONNECT ON PORT NUMBER {
			newthg->conn_port = $4;
		}
		| RECEIVE ON PORT NUMBER {
			newthg->conn_port = $4;
		}
		| PASSWORD STRING {
			if ((newthg->password = strdup($2)) == NULL)
				fatalx("out of memory");
			free($2);
		}
		| PERSISTENT NUMBER {
			if ($2)
				newthg->persist = true;
			else
				newthg->persist = false;
		}
		| bindopts2
		| maxclientssub
		| TLS tlsopts {
			if (newthg->tls == false) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
		;
thingopts2	: thingopts2 thingopts1 nl
		| thingopts1 optnl
		;
thingopts1	:  LOCATION STRING {
			newthg->location = $2;
		} locopts
		| IPADDR STRING {
			newthg->ipaddr = $2;
		} '{' optnl socopts2 '}'
		| UDP STRING {
			newthg->udp = $2;
		} '{' optnl socopts2 '}'
		;
thing		: THING STRING	 {
       			newthg = new_thg($2);
			newthg->location = NULL;
			newthg->ipaddr = NULL;
			newthg->udp = NULL;
			newthg->max_clt = pthgsd->max_clt;
			newthg->port = pthgsd->port;
			newthg->baud = DEFAULT_BAUD;
			newthg->iface = pthgsd->iface;
			newthg->conn_port = -1;
			newthg->data_bits = -1;
			newthg->parity = NULL;
			newthg->stop_bits = -1;
			newthg->hw_ctl = false;
			newthg->sw_ctl = false;
			newthg->persist = true;
			newthg->password = "";

			newthg->tls_protocols = TLS_PROTOCOLS_DEFAULT;
			newthg->tls_flags = 0;
			if ((newthg->tls_cert_file = strdup(TLS_CERT)) == NULL)
				fatalx("out of memory");
			if ((newthg->tls_key_file = strdup(TLS_KEY)) == NULL)
				fatalx("out of memory");
			strlcpy(newthg->tls_ciphers, TLS_CIPHERS,
			    sizeof(newthg->tls_ciphers));
			strlcpy(newthg->tls_dhe_params, TLS_DHE_PARAMS,
			    sizeof(newthg->tls_dhe_params));
			strlcpy(newthg->tls_ecdhe_curves, TLS_ECDHE_CURVES,
			    sizeof(newthg->tls_ecdhe_curves));
		} '{' optnl thingopts2 '}' {
			if (newthg->ipaddr != NULL && newthg->conn_port == -1) {
				yyerror("ipaddr connect port empty");
				YYERROR;
			}
			if (newthg->ipaddr != NULL &&
			    newthg->location != NULL) {
				yyerror("too many ipaddr device arguments");
				YYERROR;
			}
			if (newthg->udp != NULL && newthg->conn_port == -1) {
				yyerror("udp receive port empty");
				YYERROR;
			}
			if (newthg->udp != NULL && newthg->location != NULL) {
				yyerror("too many udp device arguments");
				YYERROR;
			}
			if (pthgsd->port == 0) {
				yyerror("could not set default port");
				YYERROR;
			}
			if (newthg->tls)
				if (load_tls(newthg) == -2)
					YYABORT;
			TAILQ_INSERT_TAIL(&pthgsd->thgs, newthg, entry);
		}
		;
tlsopts		: CERTIFICATE STRING {
			free(newthg->tls_cert_file);
			if ((newthg->tls_cert_file = strdup($2)) == NULL)
				fatalx("out of memory");
			free($2);
		}
		| KEY STRING {
			free(newthg->tls_key_file);
			if ((newthg->tls_key_file = strdup($2)) == NULL)
				fatalx("out of memory");
			free($2);
		}
		| OCSP STRING {
			free(newthg->tls_ocsp_staple_file);
			if ((newthg->tls_ocsp_staple_file = strdup($2)) == NULL)
				fatalx("out of memory");
			free($2);
		}
		| CIPHERS STRING {
			if (strlcpy(newthg->tls_ciphers, $2,
			    sizeof(newthg->tls_ciphers)) >=
			    sizeof(newthg->tls_ciphers)) {
				yyerror("ciphers too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| CLIENT CA STRING tlscltopt {
			newthg->tls_flags |= TLSFLAG_CA;
			free(newthg->tls_ca_file);
			if ((newthg->tls_ca_file = strdup($3)) == NULL)
				fatalx("out of memory");
			free($3);
		}
		| DHE STRING {
			if (strlcpy(newthg->tls_dhe_params, $2,
			    sizeof(newthg->tls_dhe_params)) >=
			    sizeof(newthg->tls_dhe_params)) {
				yyerror("dhe too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| ECDHE STRING {
			if (strlcpy(newthg->tls_ecdhe_curves, $2,
			    sizeof(newthg->tls_ecdhe_curves)) >=
			    sizeof(newthg->tls_ecdhe_curves)) {
				yyerror("ecdhe too long");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| PROTOCOLS STRING {
			if (tls_config_parse_protocols(
			    &newthg->tls_protocols, $2) != 0) {
				yyerror("invalid tls protocols");
				free($2);
				YYERROR;
			}
			free($2);
		}
		;
tlscltopt	: /* empty */
		| tlscltopt CRL STRING {
			newthg->tls_flags = TLSFLAG_CRL;
			free(newthg->tls_crl_file);
			if ((newthg->tls_crl_file = strdup($3)) == NULL)
				fatalx("out of memory");
			free($3);
		}
		| tlscltopt OPTIONAL {
			newthg->tls_flags |= TLSFLAG_OPTIONAL;
		}
		;
optcomma	: ',' optcomma
		| /* emtpy */
		;
optnl		: '\n' optnl
		| /* empty */
		;
nl		: '\n' optnl
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

int lookup(char *s) {
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "baud",		BAUD },
		{ "bind",		BIND },
		{ "ca",			CA },
		{ "certificate",	CERTIFICATE },
		{ "ciphers",		CIPHERS },
		{ "clients",		CLIENTS },
		{ "connect",		CONNECT },
		{ "connection",		CONNECTION },
		{ "crl",		CRL },
		{ "data",		DATA },
		{ "default",		DEFAULT },
		{ "dhe",		DHE },
		{ "ecdhe",		ECDHE },
		{ "hardware",		HARDWARE },
		{ "interface",		INTERFACE },
		{ "ipaddr",		IPADDR },
		{ "key",		KEY },
		{ "listen",		LISTEN },
		{ "location",		LOCATION },
		{ "log",		LOG },
		{ "max",		MAX },
		{ "name",		NAME },
		{ "ocsp",		OCSP },
		{ "on",			ON },
		{ "optional",		OPTIONAL },
		{ "parity",		PARITY },
		{ "password",		PASSWORD },
		{ "persistent",		PERSISTENT },
		{ "protocols",		PROTOCOLS },
		{ "port",		PORT },
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
u_char	*parsebuf;
int	 parseindex;
u_char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c = 0, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of file input */
		if (parseindex >= 0) {
			if (parsebuf == NULL)
				return(0);
			if (parseindex > pkt_len)
				return(0);
			c = parsebuf[parseindex++];
			if (c != '\0')
				return(c);
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
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			"quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
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
	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
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
	/* skip to either EOF or the first real EOL */
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
	u_char	 buf[8096];
	u_char	*p;
	int	 quotec, next, c;
	int	 token;

	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */
	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
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
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			fatalx("yylex: strdup");
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
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))
	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				fatalx("yylex: strdup");
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

struct file *
pushfile(const char *name)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("malloc");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

struct file *
pushbuff(u_char *pkt)
{
	struct file	*bfile;

	if ((bfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((bfile->name = strdup("subscribe buffer")) == NULL) {
		log_warn("malloc");
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
	TAILQ_INSERT_TAIL(&files, bfile, entry);
	return (bfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
popbuff(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;
	TAILQ_REMOVE(&files, file, entry);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_conf(const char *filename)
{
	int		 errors;

	pthgsd->conn_rtry = CONN_RTRY;
	pthgsd->iface = NULL;
	pthgsd->clt_fptr = clt_do_chk;

	TAILQ_INIT(&pthgsd->thgs);
	TAILQ_INIT(&pthgsd->socks);
	TAILQ_INIT(&pthgsd->clts);
	TAILQ_INIT(&pdthgs->zthgs);

	if ((file = pushfile(filename)) == NULL)
		return (-1);
	topfile = file;
	yyparse();
	errors = file->errors;
	popfile();
	return (errors ? -1 : 0);
}

int
parse_buf(struct clt *pclt, u_char *pkt, int len)
{
	int		 errors;

	pkt_len = len;
	tclt = pclt;
	my_fd = tclt->fd;
	if ((file = pushbuff(pkt)) == NULL)
		return (-1);
	topfile = file;
	yyparse();
	errors = file->errors;
	popbuff();
	return (errors ? -1 : 0);
}

struct thg *
new_thg(char *name)
{
	struct thg	 *thg;

	if ((thg = calloc(1, sizeof(*thg))) == NULL)
		fatalx("no thg calloc");
	if ((thg->name = strdup(name)) == NULL)
		fatalx("no thg name");
	return (thg);
};

int
load_tls(struct thg *pthg)
{
	if (tls_load_keypair(pthg) == -1) {
		log_warnx("%s:%d: thing \"%s\": failed to load public/private"
		    " keys", file->name, yylval.lineno, pthg->name);
		return -1;
	}
	if (tls_load_ca(pthg) == -1) {
		yyerror("failed to load ca cert(s) for thing %s", pthg->name);
		return -2;
	}
	if (tls_load_crl(pthg) == -1) {
		yyerror("failed to load crl(s) for thing %s", pthg->name);
		free(pthg);
		return -2;
	}
	if (tls_load_ocsp(pthg) == -1) {
		yyerror("failed to load ocsp staple for thing %s", pthg->name);
		free(pthg);
		return -2;
	}
	return 0;
}
