/*
 * Copyright (c) 2016-2019 Tracey Emery <tracey@traceyemery.net>
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

int				 bc, pc, my_fd;
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
%token	DEFAULT PORT MAX CLIENTS SUBSCRIPTIONS BIND INTERFACE SUBSCRIBE ERROR
%token	RECEIVE
%token	<v.string>		STRING
%token	<v.number>		NUMBER

%%
grammar		: /* empty */
		| grammar '\n'
		| grammar main '\n'
		| grammar dosub
		| grammar error '\n' { file->errors++; }
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
						log_info("client exists");
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
						    	log_info("max " \
							    "subscriptions " \
							    "reached");
							continue;
						}
						clt->subscribed = true;
						clt->sub_names[clt->le]
						    = thg->name;
						clt->le++;
						thg->clt_cnt++;
						log_info("client %s subscribed" \
						    " to %s", clt->name,
						    thg->name);
						continue;
					}
			}
		}
		;
optcomma	: ',' optcomma
		| /* emtpy */
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
locopts1	: LISTEN STRING PORT NUMBER {
	 		newthg->port = $4;
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
			newthg->password = $2;
		}
		| bindopts2
		| maxclientssub
		;
socopts2	: socopts2 socopts1 nl
		| socopts1 optnl
		;
socopts1	: LISTEN STRING PORT NUMBER {
			newthg->port = $4;
		}
		| CONNECT STRING PORT NUMBER {
			newthg->conn_port = $4;
		}
		| RECEIVE STRING PORT NUMBER {
			newthg->conn_port = $4;
		}
		| PASSWORD STRING {
			newthg->password = $2;
		}
		| PERSISTENT NUMBER {
			if ($2)
				newthg->persist = true;
			else
				newthg->persist = false;
		}
		| bindopts2
		| maxclientssub
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
			newthg->password = "";
			newthg->persist = true;
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
			TAILQ_INSERT_TAIL(&pthgsd->thgs, newthg, entry);
		}
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
	log_warnx("%s:%d: %s", file->name, yylval.lineno, msg);
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
		{"baud",		BAUD},
		{"bind",		BIND},
		{"clients",		CLIENTS},
		{"connect",		CONNECT},
		{"connection",		CONNECTION},
		{"data",		DATA},
		{"default",		DEFAULT},
		{"hardware",		HARDWARE},
		{"interface",		INTERFACE},
		{"ipaddr",		IPADDR},
		{"listen",		LISTEN},
		{"location",		LOCATION},
		{"log",			LOG},
		{"max",			MAX},
		{"name",		NAME},
		{"parity",		PARITY},
		{"password",		PASSWORD},
		{"persistent",		PERSISTENT},
		{"port",		PORT},
		{"receive",		RECEIVE},
		{"retry",		RETRY},
		{"software",		SOFTWARE},
		{"stop",		STOP},
		{"subscribe",		SUBSCRIBE},
		{"subscriptions",	SUBSCRIPTIONS},
		{"thing",		THING},
		{"things",		THINGS},
		{"udp",			UDP},
		{"verbose",		VERBOSE}
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
			if (parseindex > (int)strlen(parsebuf))
				return 0;
			c = parsebuf[parseindex++];
			if (c != '\0')
				return(c);
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
			fatal("yylex: strdup");
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
				fatal("yylex: strdup");
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
parse_buf(struct clt *pclt, u_char *pkt)
{
	int		 errors;

	tclt = pclt;
	my_fd = tclt->fd;
	if ((file = pushbuff(pkt)) == NULL)
		return (-1);
	topfile = file;
	yyparse();
	errors = file->errors;
	popbuff();
	free(pkt);
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
