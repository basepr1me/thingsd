#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 23 "parse.y"
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
#line 83 "parse.c"
#define BAUD 257
#define DATA 258
#define PARITY 259
#define STOP 260
#define HARDWARE 261
#define SOFTWARE 262
#define PASSWORD 263
#define NAME 264
#define RETRY 265
#define PERSISTENT 266
#define VERBOSE 267
#define CONNECT 268
#define THING 269
#define LISTEN 270
#define LOCATION 271
#define IPADDR 272
#define UDP 273
#define THINGS 274
#define CONNECTION 275
#define DEFAULT 276
#define PORT 277
#define MAX 278
#define CLIENTS 279
#define SUBSCRIPTIONS 280
#define BIND 281
#define INTERFACE 282
#define SUBSCRIBE 283
#define TLS 284
#define ERROR 285
#define RECEIVE 286
#define CERTIFICATE 287
#define CIPHERS 288
#define CLIENT 289
#define CA 290
#define CRL 291
#define OPTIONAL 292
#define DHE 293
#define ECDHE 294
#define KEY 295
#define OCSP 296
#define PROTOCOLS 297
#define ON 298
#define STRING 299
#define NUMBER 300
#define YYERRCODE 256
const short yylhs[] =
	{                                        -1,
    0,    0,    0,    0,    0,    1,    1,    2,    2,    2,
    2,    2,    2,    3,   10,    9,   11,   12,   13,   13,
   14,    6,   16,    4,   17,    8,    5,   18,   18,   20,
   20,   21,   21,   21,   21,   21,   21,   21,   21,   21,
   21,   21,   24,   24,   25,   25,   25,   25,   25,   25,
   25,   25,   26,   26,   28,   27,   29,   27,   30,   27,
   31,    7,   23,   23,   23,   23,   23,   23,   23,   23,
   32,   32,   32,   15,   15,   19,   19,   22,
};
const short yylen[] =
	{                                         2,
    0,    2,    3,    2,    3,    0,    1,    3,    1,    1,
    1,    1,    1,    4,    0,    8,    3,    4,    2,    1,
    7,    3,    3,    3,    3,    3,    3,    0,    4,    3,
    2,    5,    2,    2,    2,    2,    2,    2,    2,    1,
    1,    2,    3,    2,    5,    4,    4,    2,    2,    1,
    1,    2,    3,    2,    0,    4,    0,    7,    0,    7,
    0,    7,    2,    2,    2,    2,    4,    2,    2,    2,
    0,    3,    2,    2,    0,    2,    0,    2,
};
const short yydefred[] =
	{                                      1,
    0,    0,    0,    0,    0,    0,    0,    0,    2,    0,
    4,    9,   10,   11,   12,   13,    5,   61,    0,    0,
    0,    0,    0,   15,    3,    0,   26,    8,   24,   27,
   22,    0,    0,    0,   14,    0,    0,    0,    0,    0,
   76,    0,    0,    0,    0,    0,    0,    0,   55,   57,
   59,   62,    0,   54,   17,    0,    0,    0,    0,    0,
   53,    0,    0,   56,    0,    0,   78,    0,    0,    0,
    0,    0,    0,   16,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   40,   41,    0,    0,    0,
    0,    0,    0,    0,    0,   50,   51,    0,    0,    0,
    0,    0,   20,   33,   34,   35,   36,   37,   38,   39,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   42,   29,    0,   31,   48,   49,    0,    0,   52,
    0,   58,    0,   44,   60,    0,   18,   19,    7,    0,
   25,   23,   63,   66,    0,   68,   69,   64,   65,   70,
   30,    0,    0,    0,   43,    0,    0,   71,   46,    0,
   47,    0,   32,    0,   45,    0,    0,   73,    0,   72,
    0,   21,   74,
};
const short yydgoto[] =
	{                                       1,
  140,   10,   11,   12,   13,   14,   15,   16,   32,   33,
   40,   69,  102,  103,  172,   96,   97,   64,   38,   88,
   89,   61,  122,   98,   99,   45,   46,   57,   58,   59,
   26,  164,
};
const short yysindex[] =
	{                                      0,
    3,   -2, -285, -242, -252, -262, -255,  -93,    0,   23,
    0,    0,    0,    0,    0,    0,    0,    0, -266, -253,
 -251, -247, -245,    0,    0,  -65,    0,    0,    0,    0,
    0,  -68,  -63,   51,    0, -201,   51, -229,   20,  -51,
    0, -218, -217, -216, -120,   51, -215,   33,    0,    0,
    0,    0,   75,    0,    0,  -37,  -31,  -28,  -26,   51,
    0, -185,   51,    0,   51,   51,    0,  -25,  -24, -222,
 -190, -190, -169,    0, -197, -195, -192, -189, -188, -187,
 -181, -179, -171, -173,  -72,    0,    0,  -50,   51, -178,
 -177, -174, -172,  -72, -170,    0,    0, -106,   51,  -97,
  -13, -115,    0,    0,    0,    0,    0,    0,    0,    0,
 -159, -168, -166, -158, -157, -163, -155, -153, -134, -132,
 -131,    0,    0,   75,    0,    0,    0, -148, -159,    0,
 -147,    0,   75,    0,    0, -129,    0,    0,    0, -146,
    0,    0,    0,    0, -125,    0,    0,    0,    0,    0,
    0, -124, -100, -121,    0,  138, -109,    0,    0, -105,
    0, -114,    0, -271,    0,   71, -102,    0,  155,    0,
  155,    0,    0,};
const short yyrindex[] =
	{                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0, -221,    0,    0, -123,    0,    0,    0,
    0,    0,    0,    0,    0,  -79,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   -9,    0,    0, -123,
    0,    0, -191,    0, -164, -164,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   31,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -80,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  -77,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -77,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  -10,    0,    0,    0,    0, -110,    0,
 -110,    0,    0,};
const short yygindex[] =
	{                                      0,
   73,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  101,   34,  -66,  -64,    0,  -34,    0,
  126, -117,  124,  147,  -89,    0,  181,    0,    0,    0,
    0,    0,
};
#define YYTABLESIZE 315
const short yytable[] =
	{                                      67,
   28,   77,   41,   86,   52,   87,  151,   17,  133,  137,
  133,   54,    9,   18,   75,  155,   21,   22,  132,  167,
  168,   86,   19,   87,   20,   67,   23,  135,   70,   24,
   71,   72,   25,   27,   75,   76,   77,   78,   79,   80,
   81,   42,   43,   44,   77,   77,   28,   82,   29,   77,
   77,   77,   30,   31,  125,   83,   35,   34,   84,   36,
   37,   85,   39,   47,  134,   77,   77,   77,   77,   77,
   77,   77,   90,   48,  123,   91,   56,   92,   77,   93,
   49,   50,   51,   55,   60,   62,   77,   83,   68,   77,
   84,   63,   77,   94,   65,   95,   66,   73,   77,  101,
   74,   77,  104,   77,  105,   77,  106,  112,  113,  136,
  107,  108,  109,   77,   67,   28,   77,  110,  111,   77,
  126,   77,  127,  128,  139,  129,  145,  131,  152,  154,
  157,  141,  142,   77,   77,   77,   77,   77,   77,   77,
  143,  144,   77,  146,   77,  147,   77,   77,   77,   77,
   42,   43,   44,  101,   77,   77,   90,   77,   75,   91,
   77,   92,   77,   93,  148,   90,  149,  150,   91,  156,
   92,   83,   93,  158,   84,  159,  160,   94,  161,   95,
   83,  162,   77,   84,  166,   77,   94,   77,   95,   77,
  163,   77,   77,   77,  165,  169,  170,   77,  171,    6,
   77,  153,  138,   77,  173,   77,   75,   76,   77,   78,
   79,   80,   81,  124,  114,  115,  116,  130,  100,   82,
  117,  118,  119,  120,  121,   53,    0,   83,    0,    0,
   84,    0,    0,   85,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   67,   67,   67,   67,
   67,   67,   67,    0,    0,   67,    0,   67,    2,   67,
    0,   28,   28,   28,    0,    0,    0,   67,    0,    0,
   67,    3,    0,   67,    0,   67,    0,    4,    5,    0,
    6,    0,    0,    7,    0,    8,    0,   77,   77,   77,
   77,   77,   77,   77,    0,    0,    0,    0,    0,    0,
   77,    0,    0,    0,    0,    0,    0,    0,   77,    0,
    0,   77,    0,    0,   77,
};
const short yycheck[] =
	{                                      10,
   10,  125,   37,   70,  125,   70,  124,   10,   98,  125,
  100,   46,   10,  299,  125,  133,  279,  280,  125,  291,
  292,   88,  265,   88,  277,   60,  282,  125,   63,  123,
   65,   66,   10,  300,  257,  258,  259,  260,  261,  262,
  263,  271,  272,  273,  125,  125,  300,  270,  300,  271,
  272,  273,  300,  299,   89,  278,  125,  123,  281,  123,
   10,  284,  264,   44,   99,  257,  258,  259,  260,  261,
  262,  263,  263,  125,  125,  266,   44,  268,  270,  270,
  299,  299,  299,  299,   10,  123,  278,  278,  274,  281,
  281,  123,  284,  284,  123,  286,  123,  123,  263,  269,
  125,  266,  300,  268,  300,  270,  299,  279,  282,  123,
  300,  300,  300,  278,  125,  125,  281,  299,  298,  284,
  299,  286,  300,  298,  284,  298,  290,  298,  277,  277,
  277,  300,  299,  257,  258,  259,  260,  261,  262,  263,
  299,  299,  266,  299,  268,  299,  270,  271,  272,  273,
  271,  272,  273,  269,  278,  125,  263,  281,  269,  266,
  284,  268,  286,  270,  299,  263,  299,  299,  266,  299,
  268,  278,  270,  299,  281,  300,  277,  284,  300,  286,
  278,   44,  263,  281,  299,  266,  284,  268,  286,  270,
  300,  271,  272,  273,  300,  125,  299,  278,   44,  277,
  281,  129,  102,  284,  171,  286,  257,  258,  259,  260,
  261,  262,  263,   88,  287,  288,  289,   94,   72,  270,
  293,  294,  295,  296,  297,   45,   -1,  278,   -1,   -1,
  281,   -1,   -1,  284,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  257,  258,  259,  260,
  261,  262,  263,   -1,   -1,  266,   -1,  268,  256,  270,
   -1,  271,  272,  273,   -1,   -1,   -1,  278,   -1,   -1,
  281,  269,   -1,  284,   -1,  286,   -1,  275,  276,   -1,
  278,   -1,   -1,  281,   -1,  283,   -1,  257,  258,  259,
  260,  261,  262,  263,   -1,   -1,   -1,   -1,   -1,   -1,
  270,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  278,   -1,
   -1,  281,   -1,   -1,  284,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 300
#if YYDEBUG
const char * const yyname[] =
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"BAUD","DATA",
"PARITY","STOP","HARDWARE","SOFTWARE","PASSWORD","NAME","RETRY","PERSISTENT",
"VERBOSE","CONNECT","THING","LISTEN","LOCATION","IPADDR","UDP","THINGS",
"CONNECTION","DEFAULT","PORT","MAX","CLIENTS","SUBSCRIPTIONS","BIND",
"INTERFACE","SUBSCRIBE","TLS","ERROR","RECEIVE","CERTIFICATE","CIPHERS",
"CLIENT","CA","CRL","OPTIONAL","DHE","ECDHE","KEY","OCSP","PROTOCOLS","ON",
"STRING","NUMBER",
};
const char * const yyrule[] =
	{"$accept : grammar",
"grammar :",
"grammar : grammar '\\n'",
"grammar : grammar main '\\n'",
"grammar : grammar dosub",
"grammar : grammar error '\\n'",
"opttls :",
"opttls : TLS",
"main : DEFAULT PORT NUMBER",
"main : maxclients",
"main : maxsubs",
"main : bindopts1",
"main : thing",
"main : thgretry",
"dosub : SUBSCRIBE '{' subopts '}'",
"$$1 :",
"subopts : $$1 '{' name '}' ',' '{' things '}'",
"name : NAME ',' STRING",
"things : THINGS '{' subthgs2 '}'",
"subthgs2 : subthgs2 subthgs",
"subthgs2 : subthgs",
"subthgs : THING '{' STRING ',' STRING '}' optcomma",
"bindopts1 : BIND INTERFACE STRING",
"bindopts2 : BIND INTERFACE STRING",
"maxclients : MAX CLIENTS NUMBER",
"maxclientssub : MAX CLIENTS NUMBER",
"thgretry : CONNECTION RETRY NUMBER",
"maxsubs : MAX SUBSCRIPTIONS NUMBER",
"locopts :",
"locopts : '{' optnl locopts2 '}'",
"locopts2 : locopts2 locopts1 nl",
"locopts2 : locopts1 optnl",
"locopts1 : LISTEN ON opttls PORT NUMBER",
"locopts1 : BAUD NUMBER",
"locopts1 : DATA NUMBER",
"locopts1 : PARITY STRING",
"locopts1 : STOP NUMBER",
"locopts1 : HARDWARE NUMBER",
"locopts1 : SOFTWARE NUMBER",
"locopts1 : PASSWORD STRING",
"locopts1 : bindopts2",
"locopts1 : maxclientssub",
"locopts1 : TLS tlsopts",
"socopts2 : socopts2 socopts1 nl",
"socopts2 : socopts1 optnl",
"socopts1 : LISTEN ON opttls PORT NUMBER",
"socopts1 : CONNECT ON PORT NUMBER",
"socopts1 : RECEIVE ON PORT NUMBER",
"socopts1 : PASSWORD STRING",
"socopts1 : PERSISTENT NUMBER",
"socopts1 : bindopts2",
"socopts1 : maxclientssub",
"socopts1 : TLS tlsopts",
"thingopts2 : thingopts2 thingopts1 nl",
"thingopts2 : thingopts1 optnl",
"$$2 :",
"thingopts1 : LOCATION STRING $$2 locopts",
"$$3 :",
"thingopts1 : IPADDR STRING $$3 '{' optnl socopts2 '}'",
"$$4 :",
"thingopts1 : UDP STRING $$4 '{' optnl socopts2 '}'",
"$$5 :",
"thing : THING STRING $$5 '{' optnl thingopts2 '}'",
"tlsopts : CERTIFICATE STRING",
"tlsopts : KEY STRING",
"tlsopts : OCSP STRING",
"tlsopts : CIPHERS STRING",
"tlsopts : CLIENT CA STRING tlscltopt",
"tlsopts : DHE STRING",
"tlsopts : ECDHE STRING",
"tlsopts : PROTOCOLS STRING",
"tlscltopt :",
"tlscltopt : tlscltopt CRL STRING",
"tlscltopt : tlscltopt OPTIONAL",
"optcomma : ',' optcomma",
"optcomma :",
"optnl : '\\n' optnl",
"optnl :",
"nl : '\\n' optnl",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
unsigned int yystacksize;
int yyparse(void);
#line 509 "parse.y"
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
#line 873 "parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    unsigned int newsize;
    long sslen;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    sslen = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + sslen;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + sslen;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse(void)
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 5:
#line 108 "parse.y"
{ file->errors++; }
break;
case 6:
#line 110 "parse.y"
{
			yyval.v.number = 0;
			newthg->tls = false;
		}
break;
case 7:
#line 114 "parse.y"
{
			yyval.v.number = 1;
			newthg->tls = true;
		}
break;
case 8:
#line 119 "parse.y"
{
			pthgsd->port = yyvsp[0].v.number;
		}
break;
case 15:
#line 130 "parse.y"
{
	 	/* empty */
		}
break;
case 17:
#line 134 "parse.y"
{
      			/* test we're us and set name */
      			TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
				if (clt == tclt) {
					clt->name = yyvsp[0].v.string;
					my_name = yyvsp[0].v.string;
					break;
				}
			}
		}
break;
case 21:
#line 150 "parse.y"
{
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
						    yyvsp[-4].v.string) == 0)
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
				if (strcmp(thg->name, yyvsp[-4].v.string) == 0)
					if (strcmp(thg->password, yyvsp[-2].v.string) == 0) {
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
break;
case 22:
#line 203 "parse.y"
{
			pthgsd->iface = yyvsp[0].v.string;
		}
break;
case 23:
#line 207 "parse.y"
{
			newthg->iface = yyvsp[0].v.string;
		}
break;
case 24:
#line 211 "parse.y"
{
			pthgsd->max_clt = yyvsp[0].v.number;
		}
break;
case 25:
#line 215 "parse.y"
{
			newthg->max_clt = yyvsp[0].v.number;
		}
break;
case 26:
#line 219 "parse.y"
{
			if (yyvsp[0].v.number >= MIN_RTRY && yyvsp[0].v.number <= MAX_RTRY)
				pthgsd->conn_rtry = yyvsp[0].v.number;
		}
break;
case 27:
#line 224 "parse.y"
{
			pthgsd->max_sub = yyvsp[0].v.number;
		}
break;
case 32:
#line 234 "parse.y"
{
			struct thg		*thg;

			TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
				if (thg->port == yyvsp[0].v.number && (thg->tls || yyvsp[-2].v.number)) {
					yyerror("tls port already used");
					YYERROR;
				}
			}
	 		newthg->port = yyvsp[0].v.number;
		}
break;
case 33:
#line 245 "parse.y"
{
			newthg->baud = -1;
			for (bc = 0; bc < cbauds; bc++) {
				if (yyvsp[0].v.number == baudrates[bc]) {
					newthg->baud = yyvsp[0].v.number;
					continue;
				}
			}
			if (newthg->baud == -1) {
				yyerror("baud rate syntax error");
				YYERROR;
			}
		}
break;
case 34:
#line 258 "parse.y"
{
			if (yyvsp[0].v.number > 8 || yyvsp[0].v.number < 5) {
				yyerror("data bits syntax error");
				YYERROR;
			} else
				newthg->data_bits = yyvsp[0].v.number;
		}
break;
case 35:
#line 265 "parse.y"
{
			for (pc = 0; pc < sparity; pc++) {
				if (strcmp(yyvsp[0].v.string, parity[pc]) == 0) {
					newthg->parity = yyvsp[0].v.string;
					continue;
				}
			}
			if (newthg->parity == NULL) {
				yyerror("parity syntax error");
				YYERROR;
			}
		}
break;
case 36:
#line 277 "parse.y"
{
			if (yyvsp[0].v.number > 2 || yyvsp[0].v.number < 1) {
				yyerror("stop bits syntax error");
				YYERROR;
			} else if (yyvsp[0].v.number > 0)
				newthg->stop_bits = yyvsp[0].v.number;
		}
break;
case 37:
#line 284 "parse.y"
{
			if (yyvsp[0].v.number > 1 || yyvsp[0].v.number < 0) {
				yyerror("hardware syntax error");
				YYERROR;
			} else if (yyvsp[0].v.number > 0)
				newthg->hw_ctl = true;
		}
break;
case 38:
#line 291 "parse.y"
{
			if (yyvsp[0].v.number > 1 || yyvsp[0].v.number < 0) {
				yyerror("software syntax error");
				YYERROR;
			} else
				newthg->sw_ctl = true;
		}
break;
case 39:
#line 298 "parse.y"
{
			if ((newthg->password = strdup(yyvsp[0].v.string)) == NULL)
				fatalx("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 42:
#line 305 "parse.y"
{
			if (newthg->tls == false) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
break;
case 45:
#line 315 "parse.y"
{
			struct thg		*thg;

			TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
				if (thg->port == yyvsp[0].v.number && (thg->tls || yyvsp[-2].v.number)) {
					yyerror("tls port already used");
					YYERROR;
				}
			}
			newthg->port = yyvsp[0].v.number;
		}
break;
case 46:
#line 326 "parse.y"
{
			newthg->conn_port = yyvsp[0].v.number;
		}
break;
case 47:
#line 329 "parse.y"
{
			newthg->conn_port = yyvsp[0].v.number;
		}
break;
case 48:
#line 332 "parse.y"
{
			if ((newthg->password = strdup(yyvsp[0].v.string)) == NULL)
				fatalx("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 49:
#line 337 "parse.y"
{
			if (yyvsp[0].v.number)
				newthg->persist = true;
			else
				newthg->persist = false;
		}
break;
case 52:
#line 345 "parse.y"
{
			if (newthg->tls == false) {
				yyerror("tls options without tls listener");
				YYERROR;
			}
		}
break;
case 55:
#line 355 "parse.y"
{
			newthg->location = yyvsp[0].v.string;
		}
break;
case 57:
#line 358 "parse.y"
{
			newthg->ipaddr = yyvsp[0].v.string;
		}
break;
case 59:
#line 361 "parse.y"
{
			newthg->udp = yyvsp[0].v.string;
		}
break;
case 61:
#line 365 "parse.y"
{
       			newthg = new_thg(yyvsp[0].v.string);
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
		}
break;
case 62:
#line 395 "parse.y"
{
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
break;
case 63:
#line 423 "parse.y"
{
			free(newthg->tls_cert_file);
			if ((newthg->tls_cert_file = strdup(yyvsp[0].v.string)) == NULL)
				fatalx("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 64:
#line 429 "parse.y"
{
			free(newthg->tls_key_file);
			if ((newthg->tls_key_file = strdup(yyvsp[0].v.string)) == NULL)
				fatalx("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 65:
#line 435 "parse.y"
{
			free(newthg->tls_ocsp_staple_file);
			if ((newthg->tls_ocsp_staple_file = strdup(yyvsp[0].v.string)) == NULL)
				fatalx("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 66:
#line 441 "parse.y"
{
			if (strlcpy(newthg->tls_ciphers, yyvsp[0].v.string,
			    sizeof(newthg->tls_ciphers)) >=
			    sizeof(newthg->tls_ciphers)) {
				yyerror("ciphers too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 67:
#line 451 "parse.y"
{
			newthg->tls_flags |= TLSFLAG_CA;
			free(newthg->tls_ca_file);
			if ((newthg->tls_ca_file = strdup(yyvsp[-1].v.string)) == NULL)
				fatalx("out of memory");
			free(yyvsp[-1].v.string);
		}
break;
case 68:
#line 458 "parse.y"
{
			if (strlcpy(newthg->tls_dhe_params, yyvsp[0].v.string,
			    sizeof(newthg->tls_dhe_params)) >=
			    sizeof(newthg->tls_dhe_params)) {
				yyerror("dhe too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 69:
#line 468 "parse.y"
{
			if (strlcpy(newthg->tls_ecdhe_curves, yyvsp[0].v.string,
			    sizeof(newthg->tls_ecdhe_curves)) >=
			    sizeof(newthg->tls_ecdhe_curves)) {
				yyerror("ecdhe too long");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 70:
#line 478 "parse.y"
{
			if (tls_config_parse_protocols(
			    &newthg->tls_protocols, yyvsp[0].v.string) != 0) {
				yyerror("invalid tls protocols");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 72:
#line 489 "parse.y"
{
			newthg->tls_flags = TLSFLAG_CRL;
			free(newthg->tls_crl_file);
			if ((newthg->tls_crl_file = strdup(yyvsp[0].v.string)) == NULL)
				fatalx("out of memory");
			free(yyvsp[0].v.string);
		}
break;
case 73:
#line 496 "parse.y"
{
			newthg->tls_flags |= TLSFLAG_OPTIONAL;
		}
break;
#line 1542 "parse.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
