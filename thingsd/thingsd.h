/*
 * Copyright (c) 2016, 2019 Tracey Emery <tracey@traceyemery.net>
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
#include <imsg.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <tls.h>

#include "log.h"

#define PATH_CONF		 "/etc/thingsd.conf"
#define TH_USER			 "_thingsd"
#define THINGSD_SOCK		 "/var/run/thingsd.sock"
#define CONN_RTRY		 30
#define MIN_RTRY		 10
#define MAX_RTRY		 600
#define DEFAULT_BAUD		 9600
#define CLT_SUB_TIME		 5
#define BUFF			 1024
#define DTHG_CHK		 2
#define EB_TIMEOUT		 10

#define TLS_CONFIG_MAX		 511
#define TLS_CERT		"/etc/ssl/thing.crt"
#define TLS_KEY			"/etc/ssl/private/thing.key"
#define TLS_CIPHERS		"compat"
#define TLS_DHE_PARAMS		"none"
#define TLS_ECDHE_CURVES	"default"
#define TLSFLAG_CA		0x01
#define TLSFLAG_CRL		0x02
#define TLSFLAG_OPTIONAL	0x04
#define TLSFLAG_BITS		"\10\01CA\02CRL\03OPTIONAL"

#define PARENT_SOCK_FD		 (STDERR_FILENO + 1)

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

struct thg_imsg {
	bool			 exists;
	bool			 hw_ctl;
	bool			 persist;
	bool			 sw_ctl;
	char			 iface[BUFF];
	char			 ipaddr[BUFF];
	char			 name[BUFF];
	char			 parity[BUFF];
	char			 password[BUFF];
	char			 location[BUFF];
	char			 udp[BUFF];
	int			 fd;
	int			 baud;
	int			 conn_port;
	int			 data_bits;
	int			 max_clt;
	int			 port;
	int			 stop_bits;
	int			 type;
	size_t			 clt_cnt;

	bool			 tls;
	char			 tls_cert_file[BUFF];
	char			 tls_key_file[BUFF];
	char			 tls_ca_file[BUFF];
	char			 tls_crl_file[BUFF];
	char			 tls_ocsp_staple_file[BUFF];
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

	bool			 tls;
	uint8_t			 tls_flags;
	uint8_t			*tls_cert;
	size_t			 tls_cert_len;
	char			*tls_cert_file;
	uint8_t			*tls_key;
	size_t			 tls_key_len;
	char			*tls_key_file;
	uint8_t			*tls_ca;
	size_t			 tls_ca_len;
	char			*tls_ca_file;
	uint8_t			*tls_crl;
	size_t			 tls_crl_len;
	char			*tls_crl_file;
	uint8_t			*tls_ocsp_staple;
	size_t			 tls_ocsp_staple_len;
	char			*tls_ocsp_staple_file;
	char			 tls_ciphers[TLS_CONFIG_MAX];
	char			 tls_dhe_params[TLS_CONFIG_MAX];
	char			 tls_ecdhe_curves[TLS_CONFIG_MAX];
	uint32_t		 tls_protocols;
};

struct sock_imsg {
	char			 name[BUFF];
	int			 fd;
	int			 port;
	size_t			 clt_cnt;
	size_t			 max_clts;

	bool			 tls;
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

	bool			 tls;
	struct tls_config	*tls_config;
	struct tls		*tls_ctx;
};

struct clt_imsg {
	bool			 subscribed;
	char			 name[BUFF];
	int			 fd;
	int			 port;
	size_t			 subs;

	bool			 tls;
};

struct clt {
	TAILQ_ENTRY(clt)	 entry;
	struct event		*ev;
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

	bool			 tls;
	struct tls		*tls_ctx;
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

	/* thgs */
	struct event_base	*thgs_eb;
	struct event		 thgs_evsigquit;
	struct event		 thgs_evsigterm;
	struct event		 thgs_evsigint;
};

/* thingsd.c */
int			 	 main_imsg_compose_thgs(int, pid_t, void *,
				    uint16_t);

/* control.c */
#define IMSG_DATA_SIZE(imsg)    ((imsg).hdr.len - IMSG_HEADER_SIZE)

enum {
	PROC_MAIN,
	PROC_THGS,
} thgsd_process;

static const char * const log_procnames[] = {
	"main",
	"things",
};

enum thgs_list_type {
	THGS_LIST_CLTS,
	THGS_LIST_THGS,
	THGS_LIST_THGS_ROOT,
	THGS_LIST_SOCKS,
};

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	short			 events;
};

int				 control_init(char *);
int				 control_listen(void);
void				 control_accept(int, short, void *);
void				 control_dispatch_imsg(int, short, void *);
int				 control_imsg_relay(struct imsg *);

TAILQ_HEAD(ctl_conns, ctl_conn)	ctl_conns;

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_END,
	IMSG_THGS_LOG_VERBOSE,
	IMSG_THGS_LIST,
	IMSG_LIST_CLTS,
	IMSG_LIST_THGS,
	IMSG_LIST_SOCKS,
	IMSG_KILL_CLT,
	IMSG_ADD_THG,
	IMSG_DEL_THG,
	IMSG_SHOW_PKTS
};

void				 imsg_event_add(struct imsgev *);
int				 imsg_compose_event(struct imsgev *, uint16_t,
				    uint32_t, pid_t, int, void *, uint16_t);

/* thgs.c */
void             		 thgs_main(int, int, char*);
void				 add_reconn(struct thg *);
struct dthg			*new_dthg(struct thg *);

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

/* events.c */
void				 udp_evt(int, short, void *);

/* client.c */
void				 clt_conn(int, short, void *);
void				 clt_add(struct thgsd *, struct clt *);
void				 clt_del(struct thgsd *, struct clt *);
void				 clt_rd(struct bufferevent *, void *);
void				 clt_wr(struct bufferevent *, void *);
void				 clt_err(struct bufferevent *, short, void *);
void				 start_clt_chk(struct thgsd *);
void				*clt_chk(void *);
void				 clt_do_chk(struct thgsd *);
void				 clt_wr_thgs(struct clt *, struct thg *,
				    size_t);
void				 clt_tls_readcb(int, short, void *);
void				 clt_tls_writecb(int, short, void *);

/* tls.c */
int				 tls_load_keypair(struct thg *);
int				 tls_load_ca(struct thg *);
int				 tls_load_crl(struct thg *);
int				 tls_load_ocsp(struct thg *);
int				 sock_tls_init(struct sock *, struct thg *);
void				 sock_tls_handshake(int, short, void *);
#endif /* _THINGSD_H */
