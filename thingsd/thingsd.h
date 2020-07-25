/*
 * Copyright (c) 2016, 2019, 2020 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
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

#include <limits.h>
#include <pthread.h>

#ifdef THINGSD_DEBUG
#define dprintf(x...)   do { log_debug(x); } while(0)
#else
#define dprintf(x...)
#endif /* THINGSD_DEBUG */

#define THINGSD_CONF		"/etc/thingsd.conf"
#define	THINGSD_SOCKET		"/var/run/thingsd.sock"
#define THINGSD_USER		"_thingsd"

#define CONN_RETRY		 30
#define MIN_RETRY		 10
#define MAX_RETRY		 600
#define DEFAULT_BAUD		 9600
#define CLIENT_SUB_TIME		 5
#define CLIENT_SUB_CHK		 1
#define EB_TIMEOUT		 10

#define TLS_CONFIG_MAX		 511
#define TLS_CERT		 "/etc/ssl/thing.crt"
#define TLS_KEY			 "/etc/ssl/private/thing.key"
#define TLS_CIPHERS		 "compat"
#define TLS_DHE_PARAMS		 "none"
#define TLS_ECDHE_CURVES	 "default"
#define TLSFLAG_CA		 0x01
#define TLSFLAG_CRL		 0x02
#define TLSFLAG_OPTIONAL	 0x04
#define TLSFLAG_BITS		 "\10\01CA\02CRL\03OPTIONAL"

#define THINGSD_MAXTEXT		 511
#define THINGSD_MAXNAME		 16

#define THINGS_NUMPROC		 3

#define PKT_BUFF		 2048

enum imsg_type {
	IMSG_GET_INFO_PARENT_REQUEST = IMSG_PROC_MAX,
	IMSG_GET_INFO_PARENT_DATA,
	IMSG_GET_INFO_PARENT_END_DATA,

	IMSG_GET_INFO_CONTROL_REQUEST,
	IMSG_GET_INFO_CONTROL_DATA,
	IMSG_GET_INFO_CONTROL_END_DATA,

	IMSG_GET_INFO_THINGS_REQUEST,
	IMSG_GET_INFO_THINGS_REQUEST_ROOT,
	IMSG_GET_INFO_THINGS_DATA,
	IMSG_GET_INFO_THINGS_END_DATA,

	IMSG_GET_INFO_CLIENTS_REQUEST,
	IMSG_GET_INFO_CLIENTS_DATA,
	IMSG_GET_INFO_CLIENTS_END_DATA,

	IMSG_GET_INFO_SOCKETS_REQUEST,
	IMSG_GET_INFO_SOCKETS_DATA,
	IMSG_GET_INFO_SOCKETS_END_DATA,

	IMSG_SHOW_PACKETS_REQUEST,
	IMSG_SHOW_PACKETS_DATA,
	IMSG_SHOW_PACKETS_END_DATA,

	IMSG_ADD_THING,
	IMSG_KILL_CLIENT,
};

enum socktypes {
	TCP,
	UDP,
	DEV
};

struct thingsd_control_info {
	int		 verbose;
};

struct thingsd_parent_info {
	int		 verbose;
	char		 text[THINGSD_MAXTEXT];
};

struct client {
	TAILQ_ENTRY(client)	 entry;
	struct event		*ev;
	struct evbuffer		*evb;
	struct bufferevent	*bev;
	struct socket		*socket;
	bool			 subscribed;
	char			 name[THINGSD_MAXNAME];
	char			*sub_names[THINGSD_MAXTEXT];
	int			 fd;
	int			 port;
	time_t			 join_time;
	size_t			 le;
	size_t			 subs;

	bool			 tls;
	struct tls		*tls_ctx;
};
TAILQ_HEAD(clientlist, client);

struct socket {
	TAILQ_ENTRY(socket)	 entry;
	struct event		*ev;
	char			 name[THINGSD_MAXNAME];
	int			 fd;
	int			 port;
	size_t			 client_cnt;
	size_t			 max_clients;

	bool			 tls;
	struct tls_config	*tls_config;
	struct tls		*tls_ctx;
};
TAILQ_HEAD(socketlist, socket);

struct thing {
	TAILQ_ENTRY(thing)	 entry;
	struct bufferevent	*bev;
	struct evbuffer		*evb;

	bool			 exists;
	bool			 hw_ctl;
	bool			 persist;
	bool			 sw_ctl;

	char			 iface[THINGSD_MAXTEXT];
	char			 ipaddr[THINGSD_MAXTEXT];
	char			 name[THINGSD_MAXNAME];
	char			 parity[THINGSD_MAXTEXT];
	char			 password[THINGSD_MAXTEXT];
	char			 location[THINGSD_MAXTEXT];
	char			 udp[THINGSD_MAXTEXT];

	int			 fd;
	int			 baud;
	int			 conn_port;
	int			 rcv_port;
	int			 data_bits;
	int			 max_clients;
	int			 port;
	int			 stop_bits;
	int			 type;

	size_t			 client_cnt;

	bool			 tls;
	uint8_t			 tls_flags;

	uint8_t			*tls_cert;
	size_t			 tls_cert_len;
	char			 tls_cert_file[THINGSD_MAXTEXT];

	uint8_t			*tls_key;
	size_t			 tls_key_len;
	char			 tls_key_file[THINGSD_MAXTEXT];

	uint8_t			*tls_ca;
	size_t			 tls_ca_len;
	char			 tls_ca_file[THINGSD_MAXTEXT];

	uint8_t			*tls_crl;
	size_t			 tls_crl_len;
	char			 tls_crl_file[THINGSD_MAXTEXT];

	uint8_t			*tls_ocsp_staple;
	size_t			 tls_ocsp_staple_len;
	char			 tls_ocsp_staple_file[THINGSD_MAXTEXT];

	char			 tls_ciphers[TLS_CONFIG_MAX];
	char			 tls_dhe_params[TLS_CONFIG_MAX];
	char			 tls_ecdhe_curves[TLS_CONFIG_MAX];

	uint32_t		 tls_protocols;
};
TAILQ_HEAD(thinglist, thing);

struct dead_thing {
	TAILQ_ENTRY(dead_thing)	 entry;
	char			 name[THINGSD_MAXTEXT];
	int			 type;
	time_t			 dtime;
};
TAILQ_HEAD(deadthinglist, dead_thing);

struct dead_things {
	struct deadthinglist	*dead_things_list;
	volatile sig_atomic_t	 run;
};

struct thing_pkt {
	TAILQ_ENTRY(thing_pkt) entry;
	struct privsep		 ps;
	struct imsg		 imsg;
	char			 name[THINGSD_MAXNAME];
	bool			 exists;
};
TAILQ_HEAD(controlpacketlist, thing_pkt);

struct thingsd {
	struct thinglist	*things;
	struct clientlist	*clients;
	struct socketlist	*sockets;
	struct thingpktlist	*control

	struct privsep		 thingsd_ps;
	const char		*thingsd_conffile;

	int			 thingsd_debug;
	int			 thingsd_verbose;
	int			 thingsd_noaction;

	char			 iface[THINGSD_MAXTEXT];
	int			 max_clients;
	int			 port;
	size_t			 client_cnt;
	size_t			 conn_retry;
	size_t			 max_subs;
	uint16_t		 prefork_things;
	void			 (*client_fptr)(struct thingsd *);

	/* disconnected things parts */
	struct dead_things	*dead_things;
	bool			 exists;
	int			 dcount;

	/* things */
	struct event_base	*things_eb;
	struct event		 things_evsigquit;
	struct event		 things_evsigterm;
	struct event		 things_evsigint;
	struct thing_pkt	 thing_pkt;
};

extern struct thingsd	*thingsd_env;

/* events.c */
void	 udp_event(int, short, void *);

/* client.c */
void	 client_conn(int, short, void *);
void	 client_add(struct thingsd *, struct client *);
void	 client_del(struct thingsd *, struct client *);
void	 client_rd(struct bufferevent *, void *);
void	 client_wr(struct bufferevent *, void *);
void	 client_err(struct bufferevent *, short, void *);
void	 start_client_chk(struct thingsd *);
void	*client_chk(void *);
void	 client_do_chk(struct thingsd *);
void	 client_wr_things(struct client *, struct thing *, size_t);
void	 client_tls_readcb(int, short, void *);
void	 client_tls_writecb(int, short, void *);
void	 clients_show_info(struct privsep *, struct imsg *);

/* serial.c */
void	 open_things(struct thingsd *, bool);

/* sockets.c */
struct socket	*new_socket(int);
struct socket	*get_socket(struct thingsd *, int);
char	*get_ifaddrs(char *);
void	 create_sockets(struct thingsd *, bool);
void	 socket_rd(struct bufferevent *, void *);
void	 socket_wr(struct bufferevent *, void *);
void	 socket_err(struct bufferevent *, short, void *);
int	 create_socket(int, char *, int);
int	 open_client_socket(char *, int);
void	 sockets_show_info(struct privsep *, struct imsg *);

/* thingsd.c */
void	 thingsd_reload(int);

/* things.c */
struct	 dead_thing *new_dead_thing(struct thing *);
void	 things(struct privsep *, struct privsep_proc *);
void	 things_reset(void);
void	 things_shutdown(void);
void	 add_reconn(struct thing *);
void	 do_reconn(void);
void	 things_sighdlr(int, short, void *);
void	 things_show_info(struct privsep *, struct imsg *);
void	 things_echo_pkt(struct privsep *, struct imsg *);
void	 things_stop_pkt(void);
void	 send_thing_pkt(struct privsep *, struct imsg *, char *, char *, int);

/* control.c */
int	 config_init(struct thingsd *);
void	 config_purge(struct thingsd *, unsigned int);
int	 config_setreset(struct thingsd *, unsigned int);
int	 config_getreset(struct thingsd *, struct imsg *);

/* parse.y */
int	 parse_config(const char *);
int	 parse_buf(struct client *, u_char *, int);
int	 cmdline_symset(char *);

/* tls.c */
int	 tls_load_keypair(struct thing *);
int	 tls_load_ca(struct thing *);
int	 tls_load_crl(struct thing *);
int	 tls_load_ocsp(struct thing *);
int	 socket_tls_init(struct socket *, struct thing *);
void	 socket_tls_handshake(int, short, void *);
