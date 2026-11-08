/*
 * Copyright (c) 2016, 2019-2026 Tracey Emery <tracey@openbsd.org>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2007 - 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/queue.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <imsg.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "thingsd.h"

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

#define FD_RESERVE		5

void	 bufferevent_read_pressure_cb(struct evbuffer *, size_t, size_t,
	    void *);

int	 sockets_socket_af(struct sockaddr_storage *, in_port_t);
int	 sockets_accept_reserve(int, struct sockaddr *, socklen_t *, int);

void	 sockets_dispatch_thingsd(int, short, void *);
void	 sockets_dispatch_control(int, short, void *);
void	 sockets_sighdlr(int, short, void *);
__dead void
	 sockets_shutdown(void);
void	 sockets_socket_conn(int, short, void *);
void	 sockets_launch(void);
void	 sockets_client_sub_timeout(int, short, void *);
void	 sockets_client_accept_paused(int, short, void *);
void	 sockets_write_to_clients(struct package *);
void	 sockets_show_info(struct imsg *);
void	 sockets_show_clients_info(struct imsg *);
void	 sockets_kill_client(struct imsg *);
void	 sockets_tls_readcb(int, short, void *);
void	 sockets_tls_writecb(int, short, void *);

struct socket
	*sockets_conf_new_socket(struct thingsd *, struct thing *, int,
	    struct address *, int);

struct imsgev		*socks_iev_parent;
static struct imsgev	*socks_iev_control;

static struct event	 ev_sigint;
static struct event	 ev_sigterm;
static struct event	 ev_sighup;
static struct event	 ev_sigpipe;
static struct event	 ev_sigusr1;

__dead void
sockets(int fd_parent, int fd_control)
{
	struct passwd	*pw;

	log_procinit("sockets");

	if ((pw = getpwnam(THINGSD_USER)) == NULL)
		fatal("unknown user %s", THINGSD_USER);

	if (chroot(pw->pw_dir) == -1)
		fatal("%s: chroot", __func__);
	if (chdir("/") == -1)
		fatal("%s: chdir(\"/\")", __func__);

	setproctitle("%s", "sockets");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("%s: cannot drop privileges", __func__);

	/* start from empty lists, the listeners arrive from the parent */
	if (config_init(thingsd_env) == -1)
		fatal("failed to initialize configuration");

	sockets_socket_rlimit();

	event_init();

	signal_set(&ev_sigint, SIGINT, sockets_sighdlr, NULL);
	signal_set(&ev_sigterm, SIGTERM, sockets_sighdlr, NULL);
	signal_set(&ev_sighup, SIGHUP, sockets_sighdlr, NULL);
	signal_set(&ev_sigpipe, SIGPIPE, sockets_sighdlr, NULL);
	signal_set(&ev_sigusr1, SIGUSR1, sockets_sighdlr, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigpipe, NULL);
	signal_add(&ev_sigusr1, NULL);

	if ((socks_iev_parent = calloc(1, sizeof(*socks_iev_parent))) == NULL)
		fatal("%s: calloc", __func__);
	imsg_event_init(socks_iev_parent, fd_parent, sockets_dispatch_thingsd);

	if ((socks_iev_control = calloc(1, sizeof(*socks_iev_control)))
	    == NULL)
		fatal("%s: calloc", __func__);
	imsg_event_init(socks_iev_control, fd_control,
	    sockets_dispatch_control);

	if (pledge("stdio inet recvfd", NULL) == -1)
		fatal("pledge");

	event_dispatch();

	sockets_shutdown();
}

void
sockets_launch(void)
{
	struct socket		*sock;

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		log_debug("%s: configuring thing listener %d (%d)", __func__,
		    sock->conf.id, sock->fd);

		if (socket_tls_init(sock) == -1)
			fatalx("%s: tls init failed for listener %d", __func__,
			    sock->conf.id);

		event_set(&sock->ev, sock->fd, EV_READ | EV_PERSIST,
		    sockets_socket_conn, sock);

		if (event_add(&sock->ev, NULL))
			fatalx("event add sock");

		evtimer_set(&sock->pause, sockets_client_accept_paused, sock);

		log_debug("%s: running thing listener %d", __func__,
		    sock->conf.id);
	}
}

int
sockets_privinit(struct socket *sock)
{
	log_debug("%s: initializing thing listener %d", __func__,
	    sock->conf.id);

	if ((sock->fd = sockets_create_socket(&sock->conf.ss, sock->conf.port,
	    S_TCP)) == -1) {
		log_warnx("%s: create sock socket failed", __func__);
		return (-1);
	}

	return (0);
}

void
sockets_dispatch_control(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	int		 n;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			log_warnx("%s: lost control process", __func__);
			sockets_shutdown();
		}
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				log_warnx("%s: lost control process", __func__);
				sockets_shutdown();
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	/* control only ever listens to us, requests arrive via the parent */
	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)
			break;

		log_warnx("%s: unexpected imsg %d from control", __func__,
		    imsg.hdr.type);
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/*
 * Every bound address gets its own listener.  The first one for a thing is
 * the parent, the rest point back at it so thingsctl can group them.
 */
void
sockets_parse_sockets(struct thingsd *env)
{
	struct thing		*thing;
	struct socket		*sock, *parent;
	struct address		*a;
	int			 sock_id = 0, n;

	TAILQ_FOREACH(thing, env->things, entry) {
		parent = NULL;
		n = 0;
		TAILQ_FOREACH(a, thing->conf.tcp_al, entry) {
			sock = sockets_conf_new_socket(env, thing, ++sock_id,
			    a, n++);
			if (parent == NULL) {
				parent = sock;
				thing->conf.sock_id = sock->conf.id;
			} else {
				sock->conf.parent_id = parent->conf.id;
				parent->conf.child_id = sock->conf.id;
			}
			TAILQ_INSERT_TAIL(env->sockets, sock, entry);
		}
	}
}

struct socket *
sockets_conf_new_socket(struct thingsd *env, struct thing *thing, int id,
    struct address *a, int n)
{
	struct socket		*sock;

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		fatal("%s: calloc", __func__);

	if ((sock->clients = calloc(1, sizeof(*sock->clients))) == NULL)
		fatal("%s: calloc", __func__);
	TAILQ_INIT(sock->clients);

	sock->fd = -1;
	sock->conf.id = id;
	sock->conf.thing_id = thing->conf.id;
	sock->conf.max_clients = thing->conf.max_clients;

	memcpy(&sock->conf.ss, &a->ss, sizeof(sock->conf.ss));
	sock->conf.ipv4 = (a->ss.ss_family == AF_INET);
	sock->conf.ipv6 = (a->ss.ss_family == AF_INET6);

	if (strlcpy(sock->conf.iface, a->ifname, sizeof(sock->conf.iface)) >=
	    sizeof(sock->conf.iface))
		fatalx("%s: interface name truncated", __func__);

	if (n == 0)
		snprintf(sock->conf.name, sizeof(sock->conf.name), "%s_parent",
		    thing->conf.name);
	else
		snprintf(sock->conf.name, sizeof(sock->conf.name), "%s_child%d",
		    thing->conf.name, n);

	if (strlcpy(sock->conf.thing_name, thing->conf.name,
	    sizeof(sock->conf.thing_name)) >= sizeof(sock->conf.thing_name))
		fatalx("%s: strlcpy", __func__);

	if (strlcpy(sock->conf.password, thing->conf.password,
	    sizeof(sock->conf.password)) >= sizeof(sock->conf.password))
		fatalx("%s: strlcpy", __func__);

	sock->conf.port = thing->conf.tcp_listen_port;

	sock->conf.tls = thing->conf.tls;
	sock->conf.tls_protocols = thing->conf.tls_protocols;
	sock->conf.tls_flags = thing->conf.tls_flags;

	if (sock->conf.tls == 0)
		return (sock);

	if ((sock->conf.tls_cert_file =
	    strdup(thing->conf.tls_cert_file)) == NULL)
		fatal("%s: strdup", __func__);

	if ((sock->conf.tls_key_file =
	    strdup(thing->conf.tls_key_file)) == NULL)
		fatal("%s: strdup", __func__);

	if (thing->conf.tls_ca_file != NULL &&
	    (sock->conf.tls_ca_file = strdup(thing->conf.tls_ca_file)) == NULL)
		fatal("%s: strdup", __func__);

	if (thing->conf.tls_crl_file != NULL &&
	    (sock->conf.tls_crl_file =
	    strdup(thing->conf.tls_crl_file)) == NULL)
		fatal("%s: strdup", __func__);

	if (thing->conf.tls_ocsp_staple_file != NULL &&
	    (sock->conf.tls_ocsp_staple_file =
	    strdup(thing->conf.tls_ocsp_staple_file)) == NULL)
		fatal("%s: strdup", __func__);

	if (strlcpy(sock->conf.tls_ciphers, thing->conf.tls_ciphers,
	    sizeof(sock->conf.tls_ciphers)) >= sizeof(sock->conf.tls_ciphers))
		fatalx("%s: strlcpy", __func__);

	if (strlcpy(sock->conf.tls_dhe_params, thing->conf.tls_dhe_params,
	    sizeof(sock->conf.tls_dhe_params)) >=
	    sizeof(sock->conf.tls_dhe_params))
		fatalx("%s: strlcpy", __func__);

	if (strlcpy(sock->conf.tls_ecdhe_curves, thing->conf.tls_ecdhe_curves,
	    sizeof(sock->conf.tls_ecdhe_curves)) >=
	    sizeof(sock->conf.tls_ecdhe_curves))
		fatalx("%s: strlcpy", __func__);

	return (sock);
}

int
sockets_socket_af(struct sockaddr_storage *ss, in_port_t port)
{
	switch (ss->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)ss)->sin_port = port;
		((struct sockaddr_in *)ss)->sin_len =
		    sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)ss)->sin6_port = port;
		((struct sockaddr_in6 *)ss)->sin6_len =
		    sizeof(struct sockaddr_in6);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
sockets_create_socket(struct sockaddr_storage *ss, in_port_t port, int type)
{
	char			 hbuf[NI_MAXHOST];
	int			 fd, o_val = 1, socktype;

	if (sockets_socket_af(ss, port) == -1) {
		log_warnx("%s: unsupported address family %d", __func__,
		    ss->ss_family);
		return (-1);
	}

	socktype = (type == S_UDP) ? SOCK_DGRAM : SOCK_STREAM;

	if ((fd = socket(ss->ss_family, socktype | SOCK_NONBLOCK, 0)) == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	if (getnameinfo((struct sockaddr *)ss, ss->ss_len, hbuf, sizeof(hbuf),
	    NULL, 0, NI_NUMERICHOST) != 0)
		strlcpy(hbuf, "?", sizeof(hbuf));
	log_debug("%s: opening socket (%d) on %s port %d", __func__, fd, hbuf,
	    ntohs(port));

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &o_val,
	    sizeof(o_val)) == -1) {
		log_warn("%s: setsockopt", __func__);
		close(fd);
		return (-1);
	}

	if (bind(fd, (struct sockaddr *)ss, ss->ss_len) == -1) {
		log_warn("%s: can't bind %s port %d", __func__, hbuf,
		    ntohs(port));
		close(fd);
		return (-1);
	}

	if (type == S_TCP && listen(fd, SOMAXCONN) == -1) {
		log_warn("%s: unable to listen on %s port %d", __func__, hbuf,
		    ntohs(port));
		close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * Start a non-blocking connect to a thing.  The caller learns about the
 * outcome through the fd becoming writable (or erroring), so the event
 * loop is never stalled by an unreachable host.
 */
int
sockets_open_client(const char *host, in_port_t port)
{
	struct addrinfo		 hints, *res0, *res;
	char			 serv[NI_MAXSERV];
	int			 fd = -1, error, save_errno;

	snprintf(serv, sizeof(serv), "%u", ntohs(port));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((error = getaddrinfo(host, serv, &hints, &res0)) != 0) {
		log_warnx("%s: %s: %s", __func__, host, gai_strerror(error));
		return (-1);
	}

	for (res = res0; res != NULL; res = res->ai_next) {
		if ((fd = socket(res->ai_family,
		    res->ai_socktype | SOCK_NONBLOCK, res->ai_protocol)) == -1)
			continue;

		if (connect(fd, res->ai_addr, res->ai_addrlen) == 0 ||
		    errno == EINPROGRESS)
			break;

		save_errno = errno;
		close(fd);
		fd = -1;
		errno = save_errno;
	}

	if (fd == -1)
		log_warn("%s: can't connect to %s port %u", __func__, host,
		    ntohs(port));

	freeaddrinfo(res0);
	return (fd);
}

struct socket *
sockets_get_socket_byid(struct thingsd *env, int val)
{
	struct socket		*sock = NULL;

	TAILQ_FOREACH(sock, env->sockets, entry) {
		if (sock->conf.id == val)
			return sock;
	}

	return NULL;
}

/* subscribed clients across every listener of a thing in this process */
size_t
sockets_thing_client_cnt(int id)
{
	struct socket		*sock;
	size_t			 cnt = 0;

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry)
		if (sock->conf.thing_id == id)
			cnt += sock->client_cnt;

	return (cnt);
}

void
sockets_write_to_clients(struct package *package)
{
	struct socket		*sock = NULL;
	struct client		*client = NULL;

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		if (sock->conf.thing_id != package->thing_id)
			continue;
		TAILQ_FOREACH(client, sock->clients, entry) {
			if (client->subscribed)
				bufferevent_write(client->bev, package->pkt,
				    package->len);
		}
	}
}

void
sockets_show_clients_info(struct imsg *imsg)
{
	struct client	*client, nci;
	struct socket	*sock;
	char		 filter[THINGSD_MAXNAME];

	memset(&nci, 0, sizeof(nci));
	imsg_get_string(imsg, filter, sizeof(filter));

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		TAILQ_FOREACH(client, sock->clients, entry) {
			if (filter[0] != '\0' &&
			    strcmp(filter, client->name) != 0)
				continue;

			memcpy(nci.name, client->name, sizeof(nci.name));

			nci.subscribed = client->subscribed;
			nci.fd = client->fd;
			nci.port = client->port;
			nci.tls = client->tls;

			if (imsg_compose_event(socks_iev_control,
			    IMSG_GET_INFO_CLIENTS_DATA, imsg->hdr.peerid, 0,
			    -1, &nci, sizeof(nci)) == -1)
				return;
		}
	}

	imsg_compose_event(socks_iev_control, IMSG_GET_INFO_CLIENTS_END_DATA,
	    imsg->hdr.peerid, 0, -1, &nci, sizeof(nci));
}

void
sockets_show_info(struct imsg *imsg)
{
	struct socket	*socket, nsi;
	char		 filter[THINGSD_MAXNAME];

	memset(&nsi, 0, sizeof(nsi));
	imsg_get_string(imsg, filter, sizeof(filter));

	TAILQ_FOREACH(socket, thingsd_env->sockets, entry) {
		if (filter[0] != '\0' && strcmp(filter, socket->conf.name) != 0)
			continue;

		memcpy(nsi.conf.name, socket->conf.name,
		    sizeof(nsi.conf.name));

		nsi.fd = socket->fd;
		nsi.conf.port = socket->conf.port;
		nsi.conf.tls = socket->conf.tls;
		nsi.client_cnt = socket->client_cnt;
		nsi.conf.max_clients = socket->conf.max_clients;

		if (imsg_compose_event(socks_iev_control,
		    IMSG_GET_INFO_SOCKETS_DATA, imsg->hdr.peerid, 0,
		    -1, &nsi, sizeof(nsi)) == -1)
			return;
	}

	imsg_compose_event(socks_iev_control, IMSG_GET_INFO_SOCKETS_END_DATA,
	    imsg->hdr.peerid, 0, -1, &nsi, sizeof(nsi));
}

void
sockets_socket_rlimit(void)
{
	struct rlimit	 rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to get resource limit", __func__);

	log_debug("%s: max open files %llu", __func__, rl.rlim_max);

	/*
	 * Allow the maximum number of open file descriptors for this
	 * login class (which should be the class "daemon" by default).
	 */
	rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to set resource limit", __func__);
}

void
sockets_kill_client(struct imsg *imsg)
{
	struct socket		*sock;
	struct client		*client;
	char			 client_name[THINGSD_MAXNAME];

	imsg_get_string(imsg, client_name, sizeof(client_name));
	if (client_name[0] == '\0')
		return;

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		TAILQ_FOREACH(client, sock->clients, entry) {
			if (strcmp(client->name, client_name) == 0) {
				log_debug("Control killed client: %s",
				    client_name);
				client_del(client);
				return;
			}
		}
	}
}

void
sockets_dispatch_thingsd(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	struct package	*package;
	int		 n, verbose;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			log_warnx("%s: lost parent process", __func__);
			sockets_shutdown();
		}
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				log_warnx("%s: lost parent process", __func__);
				sockets_shutdown();
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_KILL_CLIENT:
			sockets_kill_client(&imsg);
			break;
		case IMSG_DIST_THING_PACKAGE:
			IMSG_SIZE_CHECK(&imsg, package);
			package = (struct package *)imsg.data;
			if (package->len < 0 ||
			    (size_t)package->len > sizeof(package->pkt))
				fatalx("%s: bad package length", __func__);
			sockets_write_to_clients(package);
			break;
		case IMSG_CFG_SOCKS:
			config_getsocks(thingsd_env, &imsg);
			break;
		case IMSG_CFG_DONE:
			config_getcfg(thingsd_env, &imsg);
			break;
		case IMSG_CFG_TLS:
			config_getsocks_tls(thingsd_env, &imsg);
			break;
		case IMSG_CTL_VERBOSE:
			IMSG_SIZE_CHECK(&imsg, &verbose);
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_setverbose(verbose);
			break;
		case IMSG_CTL_START:
			sockets_launch();
			break;
		case IMSG_GET_INFO_CLIENTS_REQUEST:
			sockets_show_clients_info(&imsg);
			break;
		case IMSG_GET_INFO_SOCKETS_REQUEST:
			sockets_show_info(&imsg);
			break;
		default:
			log_warnx("%s: unexpected imsg %d from parent",
			    __func__, imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
sockets_sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		sockets_shutdown();
		break;
	case SIGHUP:
	case SIGPIPE:
	case SIGUSR1:
		/* ignore */
		break;
	default:
		fatalx("%s: unexpected signal", __func__);
	}
}

__dead void
sockets_shutdown(void)
{
	struct socket		*sock = NULL, *tsock;
	struct client		*client, *tclient;

	TAILQ_FOREACH_SAFE(sock, thingsd_env->sockets, entry, tsock) {
		TAILQ_FOREACH_SAFE(client, sock->clients, entry, tclient)
			client_del(client);
		free(sock->clients);

		if (sock->conf.tls) {
			tls_config_free(sock->tls_config);
			tls_free(sock->tls_ctx);
			free(sock->conf.tls_cert);
			free(sock->conf.tls_key);
			free(sock->conf.tls_ca);
			free(sock->conf.tls_crl);
			free(sock->conf.tls_ocsp_staple);
		}
		if (event_initialized(&sock->ev))
			event_del(&sock->ev);
		if (evtimer_initialized(&sock->pause))
			evtimer_del(&sock->pause);
		if (sock->fd != -1)
			close(sock->fd);
		TAILQ_REMOVE(thingsd_env->sockets, sock, entry);
		free(sock);
	}
	free(thingsd_env->sockets);

	event_del(&socks_iev_parent->ev);
	imsgbuf_clear(&socks_iev_parent->ibuf);
	close(socks_iev_parent->ibuf.fd);
	free(socks_iev_parent);
	event_del(&socks_iev_control->ev);
	imsgbuf_clear(&socks_iev_control->ibuf);
	close(socks_iev_control->ibuf.fd);
	free(socks_iev_control);

	log_info("sockets exiting, pid %d", getpid());
	exit(0);
}

int
sockets_accept_reserve(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve)
{
	if (getdtablecount() + reserve >= getdtablesize()) {
		log_debug("%s: descriptor table nearly full", __func__);
		errno = EMFILE;
		return (-1);
	}

	return (accept4(sockfd, addr, addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC));
}

void
sockets_client_accept_paused(int fd, short events, void *arg)
{
	struct socket		*sock = arg;

	event_add(&sock->ev, NULL);
}

void
sockets_client_sub_timeout(int fd, short type, void *arg)
{
	struct client		*client = (struct client *)arg;

	if (client->subscribed == 0)
		client_del(client);
}

void
sockets_socket_conn(int fd, short event, void *arg)
{
	struct sockaddr_storage	 ss;
	struct timeval		 backoff, subtime;
	struct client		*client = NULL;
	struct socket		*sock = (struct socket *)arg;
	int			 client_fd;
	socklen_t		 len = sizeof(ss);

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	subtime.tv_sec = CLIENT_SUB_TIME_SEC;
	subtime.tv_usec = CLIENT_SUB_TIME_USEC;

	log_debug("%s: client connection started on listener %d", __func__,
	    sock->conf.id);

	client_fd = sockets_accept_reserve(fd, (struct sockaddr *)&ss, &len,
	    FD_RESERVE);
	if (client_fd == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			break;
		case EMFILE:
		case ENFILE:
			event_del(&sock->ev);
			evtimer_add(&sock->pause, &backoff);
			break;
		default:
			log_warn("%s: accept", __func__);
		}
		return;
	}

	if (sock->conf.max_clients > 0 &&
	    sockets_thing_client_cnt(sock->conf.thing_id) >=
	    sock->conf.max_clients) {
		log_debug("%s: listener %d max clients reached", __func__,
		    sock->conf.id);
		close(client_fd);
		return;
	}

	if ((client = calloc(1, sizeof(*client))) == NULL)
		goto err;

	client->fd = client_fd;
	client->port = sock->conf.port;
	client->sock_id = sock->conf.id;
	client->thing_id = sock->conf.thing_id;
	client->sock = sock;
	client->join_time = time(NULL);

	if ((client->packages = calloc(1, sizeof(*client->packages))) == NULL)
		goto err;
	TAILQ_INIT(client->packages);

	if (sock->conf.tls) {
		if (tls_accept_socket(sock->tls_ctx, &client->tls_ctx,
		    client_fd) == -1) {
			log_warnx("tls accept failed: %s",
			    tls_error(sock->tls_ctx));
			goto err;
		}
		client->tls = 1;
	}

	client->bev = bufferevent_new(client->fd, client_rd, client_wr,
	    client_err, client);
	if (client->bev == NULL)
		goto err;

	/*
	 * libtls completes the handshake from within tls_read/tls_write,
	 * so the regular bufferevent callbacks are simply replaced.
	 */
	if (client->tls) {
		event_set(&client->bev->ev_read, client->fd, EV_READ,
		    sockets_tls_readcb, client->bev);
		event_set(&client->bev->ev_write, client->fd, EV_WRITE,
		    sockets_tls_writecb, client->bev);
	}

	bufferevent_setwatermark(client->bev, EV_READ, 0, PKT_BUFF);
	bufferevent_enable(client->bev, EV_READ | EV_WRITE);

	evtimer_set(&client->timeout, sockets_client_sub_timeout, client);
	evtimer_add(&client->timeout, &subtime);

	TAILQ_INSERT_TAIL(sock->clients, client, entry);

	log_debug("%s: client connected (%d)", __func__, client->fd);
	return;
err:
	log_debug("%s: client setup error", __func__);
	close(client_fd);
	if (client != NULL) {
		if (client->tls)
			tls_free(client->tls_ctx);
		free(client->packages);
		free(client);
	}
}

void
sockets_tls_readcb(int fd, short event, void *arg)
{
	struct bufferevent	*bufev = (struct bufferevent *)arg;
	struct client		*client = bufev->cbarg;
	char			 pkt[PKT_BUFF];
	ssize_t			 ret;
	size_t			 len;
	int			 toread = EVBUFFER_READ;

	ret = tls_read(client->tls_ctx, pkt, sizeof(pkt));
	if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
		goto retry;
	} else if (ret < 0) {
		log_debug("%s: %s", __func__, tls_error(client->tls_ctx));
		toread |= EVBUFFER_ERROR;
		goto err;
	}

	len = ret;
	if (len == 0) {
		toread |= EVBUFFER_EOF;
		goto err;
	}

	if (evbuffer_add(bufev->input, pkt, len) == -1) {
		toread |= EVBUFFER_ERROR;
		goto err;
	}

	event_add(&bufev->ev_read, NULL);

	len = EVBUFFER_LENGTH(bufev->input);
	if (bufev->wm_read.low != 0 && len < bufev->wm_read.low)
		return;

	if (bufev->wm_read.high != 0 && len > bufev->wm_read.high) {
		struct evbuffer *buf = bufev->input;
		event_del(&bufev->ev_read);
		evbuffer_setcb(buf, bufferevent_read_pressure_cb, bufev);
		return;
	}

	if (bufev->readcb != NULL)
		(*bufev->readcb)(bufev, bufev->cbarg);

	return;
retry:
	event_del(&bufev->ev_read);
	event_add(&bufev->ev_read, NULL);
	return;
err:
	(*bufev->errorcb)(bufev, toread, bufev->cbarg);
}

void
sockets_tls_writecb(int fd, short event, void *arg)
{
	struct bufferevent	*bufev = (struct bufferevent *)arg;
	struct client		*client = bufev->cbarg;
	ssize_t			 ret;
	size_t			 len;
	int			 towrite = EVBUFFER_WRITE;

	if (EVBUFFER_LENGTH(bufev->output)) {
		ret = tls_write(client->tls_ctx,
		    EVBUFFER_DATA(bufev->output),
		    EVBUFFER_LENGTH(bufev->output));

		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
			goto retry;
		} else if (ret < 0) {
			log_debug("%s: %s", __func__,
			    tls_error(client->tls_ctx));
			towrite |= EVBUFFER_ERROR;
			goto err;
		}

		len = ret;
		evbuffer_drain(bufev->output, len);
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0) {
		event_del(&bufev->ev_write);
		event_add(&bufev->ev_write, NULL);
	}

	if (bufev->writecb != NULL && EVBUFFER_LENGTH(bufev->output) <=
	    bufev->wm_write.low)
		(*bufev->writecb)(bufev, bufev->cbarg);

	return;
retry:
	event_del(&bufev->ev_write);
	event_add(&bufev->ev_write, NULL);
	return;
err:
	(*bufev->errorcb)(bufev, towrite, bufev->cbarg);
}
