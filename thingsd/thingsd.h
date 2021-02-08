/*
 * Copyright (c) 2016, 2019-2021 Tracey Emery <tracey@traceyemery.net>
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

#include <net/if.h>
#include <netinet/in.h>
#include <sys/tree.h>

#include <limits.h>

#ifdef THINGSD_DEBUG
#define dprintf(x...)   do { log_debug(x); } while(0)
#else
#define dprintf(x...)
#endif /* THINGSD_DEBUG */

#define THINGSD_CONF		 "/etc/thingsd.conf"
#define THINGSD_SOCKET		 "/var/run/thingsd.sock"
#define THINGSD_USER		 "_thingsd"

#define CONN_RETRY		 30
#define MIN_RETRY		 10
#define MAX_RETRY		 600
#define DEFAULT_BAUD		 9600
#define CLIENT_SUB_TIME_SEC	 5
#define CLIENT_SUB_TIME_USEC	 100
#define CLIENT_SUB_CHK		 1
#define EB_TIMEOUT		 1

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
#define THINGSD_MAXPORT		 6
#define THINGSD_MAXIFACE	 16

#define SOCKS_NUMPROC		 3

#define PKT_BUFF		 2048

#define MAX_IMSG_DATA_SIZE	(MAX_IMSGSIZE - IMSG_HEADER_SIZE)

enum imsg_type {
	IMSG_GET_INFO_THINGSD_REQUEST = IMSG_PROC_MAX,
	IMSG_GET_INFO_THINGSD_DATA,
	IMSG_GET_INFO_THINGSD_END_DATA,

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
	IMSG_BAD_THING,

	IMSG_KILL_CLIENT,

	IMSG_CTL_START,
	IMSG_CFG_DONE,

	IMSG_CFG_SOCKS,
	IMSG_CFG_TLS,
	IMSG_DIST_THING_PACKAGE,
	IMSG_DIST_CLIENT_PACKAGE,
};

/* 
 * parse.y contains TCP and UDP
 * so, these have to be different
 * to use "socketypes" in parse.y code
 */
enum socktypes {
	S_TCP,
	S_UDP,
	S_DEV
};

struct thingsd_control_info {
	int		 verbose;
};

struct thingsd_thingsd_info {
	int		 verbose;
	char		 text[THINGSD_MAXTEXT];
};

struct subscription {
	TAILQ_ENTRY(subscription)	 entry;
	char				 thing_name[THINGSD_MAXNAME];
};
TAILQ_HEAD(subscriptionlist, subscription);

struct address {
	TAILQ_ENTRY(address)	 entry;
	struct sockaddr_storage	 ss;
	int			 ipproto;
	int			 prefixlen;
	in_port_t		 port;
	char			 ifname[IFNAMSIZ];
};
TAILQ_HEAD(addresslist, address);

struct package {
	TAILQ_ENTRY(package)	 entry;
	char			 pkt[PKT_BUFF];
	int			 len;
	int			 thing_id;
};
TAILQ_HEAD(packages, package);

struct client {
	TAILQ_ENTRY(client)	 entry;
	struct packages		*packages;
	int			 id;
	int			 thing_id;
	int			 sock_id;
	void			*sock;
	void			*sock_conf;

	struct clt_time		*clt;
	struct evbuffer		*evb;
	struct bufferevent	*bev;
	struct event		 ev;
	struct event		 timeout;

	int			 subscribed;
	char			 name[THINGSD_MAXNAME];

	int			 fd;
	in_port_t		 port;
	time_t			 join_time;
	size_t			 subs;

	int			 tls;
	struct tls		*tls_ctx;
};
TAILQ_HEAD(clientlist, client);

struct socket_config {
	struct addresslist	*al;
	char			 iface[THINGSD_MAXTEXT];
	char			 name[THINGSD_MAXTEXT];
	char			 thing_name[THINGSD_MAXTEXT];
	int			 id;
	int			 child_id;
	int			 parent_id;
	int			 thing_id;

	struct sockaddr_storage	 ss;
	int			 ipv4;
	int			 ipv6;

	in_port_t		 port;
	size_t			 max_clients;
	char			 password[THINGSD_MAXTEXT];

	int			 tls;
	uint8_t			 tls_flags;

	uint8_t			*tls_cert;
	char			*tls_cert_file;
	size_t			 tls_cert_len;

	uint8_t			*tls_key;
	char			*tls_key_file;
	size_t			 tls_key_len;

	uint8_t			*tls_ca;
	char			*tls_ca_file;
	size_t			 tls_ca_len;

	uint8_t			*tls_crl;
	char			*tls_crl_file;
	size_t			 tls_crl_len;

	uint8_t			*tls_ocsp_staple;
	char			*tls_ocsp_staple_file;
	size_t			 tls_ocsp_staple_len;

	char			 tls_ciphers[TLS_CONFIG_MAX];
	char			 tls_dhe_params[TLS_CONFIG_MAX];
	char			 tls_ecdhe_curves[TLS_CONFIG_MAX];

	uint32_t		 tls_protocols;
};

enum tls_config_type {
	TLS_CFG_CA,
	TLS_CFG_CERT,
	TLS_CFG_CRL,
	TLS_CFG_KEY,
	TLS_CFG_OCSP_STAPLE,
};

struct tls_config {
	uint32_t		 id;

	enum tls_config_type	 tls_type;
	size_t			 tls_len;
	size_t			 tls_chunk_len;
	size_t			 tls_chunk_offset;
};

struct socket {
	TAILQ_ENTRY(socket)	 entry;
	struct clientlist	*clients;
	struct socket_config	 conf;

	int			 fd;

	size_t			 client_cnt;

	struct tls_config	*tls_config;
	struct tls		*tls_ctx;

	/* event for client fd */
	struct event		 ev;
	struct event		 pause;
};
TAILQ_HEAD(socketlist, socket);

struct thing_config {
	struct thingsd		*env;
	struct addresslist	*tcp_al;
	struct addresslist	*udp_al;

	int			 ipv4;
	int			 ipv6;

	char			 name[THINGSD_MAXNAME];

	int			 id;
	int			 sock_id;
	int			 child_id;
	int			 parent_id;

	int			 hw_ctl;
	int			 persist;
	int			 sw_ctl;

	char			 tcp_iface[THINGSD_MAXTEXT];
	char			 ipaddr[THINGSD_MAXTEXT];
	char			 parity[THINGSD_MAXTEXT];
	char			 password[THINGSD_MAXTEXT];
	char			 location[THINGSD_MAXTEXT];

	char			 udp[THINGSD_MAXTEXT];
	char			 udp_iface[THINGSD_MAXTEXT];

	in_port_t		 tcp_listen_port;
	in_port_t		 tcp_conn_port;
	in_port_t		 udp_rcv_port;

	int			 baud;
	int			 data_bits;
	size_t			 max_clients;
	int			 stop_bits;
	int			 type;

	int			 tls;
	uint8_t			 tls_flags;

	uint8_t			*tls_cert;
	char			*tls_cert_file;
	size_t			 tls_cert_len;

	uint8_t			*tls_key;
	char			*tls_key_file;
	size_t			 tls_key_len;

	uint8_t			*tls_ca;
	char			*tls_ca_file;
	size_t			 tls_ca_len;

	uint8_t			*tls_crl;
	char			*tls_crl_file;
	size_t			 tls_crl_len;

	uint8_t			*tls_ocsp_staple;
	char			*tls_ocsp_staple_file;
	size_t			 tls_ocsp_staple_len;

	char			 tls_ciphers[TLS_CONFIG_MAX];
	char			 tls_dhe_params[TLS_CONFIG_MAX];
	char			 tls_ecdhe_curves[TLS_CONFIG_MAX];

	uint32_t		 tls_protocols;
};

struct thing {
	TAILQ_ENTRY(thing)	 entry;
	struct thing_config	 conf;
	int			 exists;

	/* either DEV, TCP conn, or UDP rcv fd */
	int			 fd;

	/* event for TCP thing fd */
	struct bufferevent	*bev;
	struct evbuffer		*evb;

	/* event for UDP thing fd */
	struct event		 udp_ev;
};
TAILQ_HEAD(thinglist, thing);

struct dead_thing {
	TAILQ_ENTRY(dead_thing)	 entry;
	char			 name[THINGSD_MAXTEXT];
	int			 type;
	time_t			 dtime;
};
TAILQ_HEAD(deadthinglist, dead_thing);

struct packet_client {
	TAILQ_ENTRY(packet_client)	 entry;
	struct privsep		 ps;
	struct imsg		 imsg;
	int			 fd;
	char			 name[THINGSD_MAXNAME];
};
TAILQ_HEAD(packetclientlist, packet_client);

struct thingsd {
	struct thinglist	*things;
	struct socketlist	*sockets;
	struct packages		*packages;

	struct privsep		*thingsd_ps;
	const char		*thingsd_conffile;

	int			 thingsd_debug;
	int			 thingsd_verbose;
	int			 thingsd_noaction;

	char			 tcp_iface[THINGSD_MAXTEXT];
	char			 udp_iface[THINGSD_MAXTEXT];

	size_t			 max_clients;
	size_t			 client_cnt;
	size_t			 conn_retry;
	uint16_t		 prefork_socks;
	int			 run;

	/* disconnected things parts */
	struct deadthinglist	*dead_things;
	int			 exists;
	int			 dcount;

	/* things */
	struct event_base	*thingsd_eb;

	/* socks */
	int			 socks_reload;

	/* control packets */
	struct packetclientlist	*packet_clients;
	int			 packet_client_count;
};

extern struct thingsd	*thingsd_env;
extern int		 thing_id;

/* client.c */
void	 client_del(struct client *);
void	 client_rd(struct bufferevent *, void *);
void	 client_wr(struct bufferevent *, void *);
void	 client_err(struct bufferevent *, short, void *);

/* sockets.c */
struct socket
	*sockets_new_socket(char *);
struct socket
	*sockets_get_socket(struct thingsd *, int);
struct socket
	*sockets_get_socket_byid(struct thingsd *, int);
int	 sockets_create_socket(struct addresslist *, in_port_t, int);
int	 sockets_open_client(char *, in_port_t);
int	 sockets_privinit(struct socket *);
int	 sockets_client_cmp(struct client *, struct client *);
void	 sockets_parse_sockets(struct thingsd *);
void	 sockets_socket_rlimit(int);
void	 sockets_sighdlr(int, short, void *);
void	 sockets_shutdown(void);
void	 sockets(struct privsep *, struct privsep_proc *);

/* thingsd.c */
struct thing	*thingsd_conf_new_thing(struct thingsd *, struct thing *,
		    char *, int);

/* config.c */
int	 config_init(struct thingsd *);
void	 config_purge(struct thingsd *, unsigned int);
int	 config_setreset(struct thingsd *, unsigned int);
int	 config_getreset(struct thingsd *, struct imsg *);
int	 config_setsocks(struct thingsd *, struct socket *);
int	 config_getsocks(struct thingsd *, struct imsg *);
int	 config_getcfg(struct thingsd *, struct imsg *);
int	 config_getsocks_tls(struct thingsd *, struct imsg *);

/* parse.y */
int	 parse_config(const char *, struct thingsd *);
int	 parse_buf(struct client *, u_char *, int);
int	 cmdline_symset(char *);
struct address	*host_v4(const char *);
struct address	*host_v6(const char *);
int		 host_dns(const char *, struct addresslist *,
		    int, in_port_t, const char *, int);
int		 host_if(const char *, struct addresslist *,
		    int, in_port_t, const char *, int);
int		 host(const char *, struct addresslist *,
		    int, in_port_t, const char *, int);
int		 is_if_in_group(const char *, const char *);

/* tls.c */
int	 tls_load_keypair(struct socket *);
int	 tls_load_ca(struct socket *);
int	 tls_load_crl(struct socket *);
int	 tls_load_ocsp(struct socket *);
void	 socket_tls_load(struct socket *);
int	 socket_tls_init(struct socket *);
void	 socket_tls_handshake(int, short, void *);
