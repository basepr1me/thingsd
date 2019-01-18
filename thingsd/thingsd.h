/*
 * Copyright (c) 2016-2019 Tracey Emery <tracey@traceyemery.net>
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

#ifndef _THINGSD_H
#define _THINGSD_H

#include <sys/queue.h>
#include <sys/time.h>

#include <event.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>

#define PATH_CONF		 "/etc/thingsd.conf"
#define TH_USER			 "_thingsd"
#define CONN_RTRY		 30
#define MIN_RTRY		 10
#define MAX_RTRY		 600
#define DEFAULT_BAUD		 9600
#define CLT_SUB_TIME		 5
#define BUFF			 1024
#define DTHG_CHK		 2
#define EB_TIMEOUT		 10

enum socktypes {
	TCP,
	UDP,
	DEV
};

struct dthgs {
	TAILQ_HEAD(zthgs, dthg)	 zthgs;
	volatile sig_atomic_t	 run;
};

struct dthg {
	TAILQ_ENTRY(dthg)	 entry;
	char			*name;
	int			 type;
	time_t			 dtime;
};

struct thg {
	TAILQ_ENTRY(thg)	 entry;
	struct bufferevent	*bev;
	struct evbuffer		*evb;
	bool			 exists;
	bool			 hw_ctl;
	bool			 persist;
	bool			 sw_ctl;
	char			*iface;
	char			*ipaddr;
	char			*name;
	char			*parity;
	char			*password;
	char			*location;
	char			*udp;
	int			 fd;
	int			 baud;
	int			 conn_port;
	int			 data_bits;
	int			 max_clt;
	int			 port;
	int			 stop_bits;
	int			 type;
	size_t			 clt_cnt;
};

struct sock {
	TAILQ_ENTRY(sock)	 entry;
	struct event		*ev;
	struct bufferevent	*bev;
	struct evbuffer		*evb;
	char			*name;
	int			 fd;
	int			 port;
	size_t			 clt_cnt;
	size_t			 max_clts;
};

struct clt {
	TAILQ_ENTRY(clt)	 entry;
	struct evbuffer		*evb;
	struct bufferevent	*bev;
	struct sock		*sock;
	bool			 subscribed;
	char			*name;
	char			**sub_names;
	int			 fd;
	int			 port;
	time_t			 join_time;
	size_t			 le;
	size_t			 subs;
};

struct thgsd {
	/* things things */
	TAILQ_HEAD(thgs, thg)	 thgs;
	TAILQ_HEAD(socks, sock)	 socks;
	TAILQ_HEAD(clts, clt)	 clts;
	struct event_base	*eb;
	struct passwd		*pw;
	char			*iface;
	int			 max_clt;
	int			 port;
	size_t			 debug;
	size_t			 clt_cnt;
	size_t			 conn_rtry;
	size_t			 max_sub;
	size_t			 verbose;
	void			 (*clt_fptr)(struct thgsd *);

	/* disconnected things parts */
	bool			 exists;
	int			 dcount;

	/* signal handlers */
	struct event		 evsigquit;
	struct event		 evsigterm;
	struct event		 evsigint;
	struct event		 evsighup;
};

/* thingsd.c */
struct dthg			*new_dthg(struct thg *);
void				 add_reconn(struct thg *);

/* parse.y */
struct thg			*new_thg(char *);
int				 parse_conf(const char *);
int				 parse_buf(struct clt *, u_char *, int);

/* serial.c */
void				 open_thgs(struct thgsd *, bool);

/* sockets.c */
struct sock			*new_sock(int);
struct sock			*get_sock(struct thgsd *, int);
char				*get_ifaddrs(char *);
void				 create_socks(struct thgsd *, bool);
void				 sock_rd(struct bufferevent *, void *);
void				 sock_wr(struct bufferevent *, void *);
void				 sock_err(struct bufferevent *, short, void *);
int				 create_sock(int, char *, int);
int				 open_clt_sock(char *, int);

/* things.c */
pid_t				 thgs_main(struct thgsd *, const char *);

/* events.c */
void				 udp_evt(int, short, void *);

/* client.c */
void				 clt_conn(int, short, void *);
void				 clt_del(struct thgsd *, struct clt *);
void				 clt_rd(struct bufferevent *, void *);
void				 clt_wr(struct bufferevent *, void *);
void				 clt_err(struct bufferevent *, short, void *);
void				 start_clt_chk(struct thgsd *);
void				*clt_chk(void *);
void				 clt_do_chk(struct thgsd *);
void				 clt_wr_thgs(struct clt *, struct thg *,
				    size_t);

/* log.c */
void	log_init(int, int);
void	log_procinit(const char *);
void	log_setverbose(int);
int	log_getverbose(void);
void	log_warn(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_warnx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_debug(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	logit(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	vlog(int, const char *, va_list)
	    __attribute__((__format__ (printf, 2, 0)));
__dead void fatal(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
__dead void fatalx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
#endif /* _THINGSD_H */
