/*
 * Copyright (c) 2016, 2019-2021 Tracey Emery <tracey@traceyemery.net>
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "proc.h"
#include "thingsd.h"

#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))

#define FD_RESERVE		5
#define FD_NEEDED		6

volatile int client_inflight = 0;

int	 sockets_dispatch_thingsd(int, struct privsep_proc *, struct imsg *);
int	 sockets_socket_af(struct sockaddr_storage *, struct portrange);
int	 sockets_accept_reserve(int, struct sockaddr *, socklen_t *, int,
	    volatile int *);
int	 sockets_dispatch_control(int, struct privsep_proc *, struct imsg *);

void	 sockets_dup_new_socket(struct socket *, struct socket *);
void	 sockets_run(struct privsep *, struct privsep_proc *, void *);
void	 sockets_socket_conn(int, short, void *);
void	 sockets_launch(void);
void	 sockets_client_sub_timeout(int, short, void *);
void	 sockets_client_accept_paused(int, short, void *);
void	 sockets_write_to_clients(struct package *);
void	 sockets_show_info(struct privsep *, struct imsg *);
void	 sockets_show_clients_info(struct privsep *, struct imsg *);
void	 sockets_kill_client(struct privsep *, struct imsg *);

struct socket
	*sockets_conf_new_socket(struct thingsd *, struct thing *, int, int);


extern enum privsep_procid privsep_process;

static struct privsep_proc procs[] = {
	{ "control",	PROC_CONTROL,	sockets_dispatch_control, control },
	{ "thingsd",	PROC_PARENT,	sockets_dispatch_thingsd  },
};

void
sockets(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), sockets_run, NULL);
}

void
sockets_run(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	if (config_init(ps->ps_env) == -1)
		fatal("failed to initialize configuration");

	p->p_shutdown = sockets_shutdown;

	sockets_socket_rlimit(-1);

	signal_del(&ps->ps_evsigchld);
	signal_set(&ps->ps_evsigchld, SIGCHLD, sockets_sighdlr, ps);
	signal_add(&ps->ps_evsigchld, NULL);

	if (pledge("stdio inet recvfd", NULL) == -1)
		fatal("pledge");
}

void
sockets_launch(void)
{
	struct socket		*sock;

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		log_debug("%s: configuring thing listener %d (%d)", __func__,
		    sock->conf.id, sock->fd);

		socket_tls_init(sock);

		if ((sock->clients = calloc(1, sizeof(*sock->clients))) == NULL)
			fatalx("%s: calloc", __func__);
		TAILQ_INIT(sock->clients);

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

	if ((sock->fd = sockets_create_socket(sock->conf.al, sock->conf.port,
	    S_TCP)) == -1) {
		log_warnx("%s: create sock socket failed", __func__);
		return (-1);
	}

	return (0);
}

int
sockets_dispatch_control(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	int		 res = 0, cmd = 0;

	switch (imsg->hdr.type) {
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	default:
		if (proc_compose_imsg(ps, PROC_CONTROL, -1, cmd,
		    imsg->hdr.peerid, -1, &res, sizeof(res)) == -1)
			return (-1);
		break;
	}

	return (0);
}

void
sockets_parse_sockets(struct thingsd *env)
{
	struct thing		*thing;
	struct socket		*sock, *new_sock = NULL;
	struct address		*a;
	int			 sock_id = 0, ipv4 = 0, ipv6 = 0;

	TAILQ_FOREACH(thing, env->things, entry) {
		sock_id++;
		new_sock = sockets_conf_new_socket(env, thing, sock_id, 0);
		TAILQ_INSERT_TAIL(env->sockets, new_sock, entry);

		/* add ipv6 children */
		TAILQ_FOREACH(sock, env->sockets, entry) {
			ipv4 = ipv6 = 0;

			TAILQ_FOREACH(a, sock->conf.al, entry) {
				if (a->ss.ss_family == AF_INET)
					ipv4 = 1;
				if (a->ss.ss_family == AF_INET6)
					ipv6 = 1;
			}

			/* create ipv6 sock */
			if (ipv4 == 1 && ipv6 == 1) {
				sock_id++;
				sock->conf.child_id = sock_id;
				new_sock = sockets_conf_new_socket(env, thing,
				    sock_id, 1);
				sockets_dup_new_socket(sock, new_sock);
				TAILQ_INSERT_TAIL(env->sockets, new_sock,
				    entry);
				continue;
			}
		}
	}
}

void
sockets_dup_new_socket(struct socket *p_sock, struct socket *sock)
{
	struct address		*a, *acp;

	sock->conf.parent_id = p_sock->conf.id;
	sock->conf.thing_id = p_sock->conf.thing_id;
	sock->conf.ipv4 = 0;
	sock->conf.ipv6 = 1;

	if (strlcpy(sock->conf.password, p_sock->conf.password,
	    sizeof(sock->conf.password)) >= sizeof(sock->conf.password))
		fatalx("%s: strlcpy", __func__);

	sock->conf.port.val[0] = p_sock->conf.port.val[0];
	sock->conf.port.op = p_sock->conf.port.op;

	sock->conf.tls = p_sock->conf.tls;
	sock->conf.tls_protocols = p_sock->conf.tls_flags;
	sock->conf.tls_flags = p_sock->conf.tls_flags;
	sock->conf.max_clients = p_sock->conf.max_clients;

	memcpy(&sock->conf.thing_name, p_sock->conf.thing_name,
	    sizeof(sock->conf.thing_name));

	snprintf(sock->conf.name, THINGSD_MAXTEXT, "%s_child",
	    p_sock->conf.thing_name);

	TAILQ_FOREACH(a, p_sock->conf.al, entry) {
		if (a->ss.ss_family == AF_INET)
			continue;

		if ((acp = calloc(1, sizeof(*acp))) == NULL)
			fatal("%s: calloc", __func__);
		memcpy(&acp->ss, &a->ss, sizeof(acp->ss));
		acp->ipproto = a->ipproto;
		acp->prefixlen = a->prefixlen;
		acp->port.val[0] = a->port.val[0];
		if (strlen(a->ifname) != 0) {
			if (strlcpy(acp->ifname, a->ifname,
			    sizeof(acp->ifname)) >= sizeof(acp->ifname)) {
				fatalx("%s: interface name truncated",
				    __func__);
			}
		}

		TAILQ_INSERT_TAIL(sock->conf.al, acp, entry);
	}

	if(sock->conf.tls == 0)
		return;

	if((sock->conf.tls_cert_file =
	    strdup(p_sock->conf.tls_cert_file)) == NULL)
		fatal("%s: strdup", __func__);

	if((sock->conf.tls_key_file =
	    strdup(p_sock->conf.tls_key_file)) == NULL)
		fatal("%s: strdup", __func__);

	if (strlcpy(sock->conf.tls_ciphers, p_sock->conf.tls_ciphers,
	    sizeof(sock->conf.tls_ciphers)) >= sizeof(sock->conf.tls_ciphers))
		fatalx("%s: strlcpy", __func__);

	if (strlcpy(sock->conf.tls_dhe_params, p_sock->conf.tls_dhe_params,
	    sizeof(sock->conf.tls_dhe_params)) >=
	    sizeof(sock->conf.tls_dhe_params))
		fatalx("%s: strlcpy", __func__);

	if (strlcpy(sock->conf.tls_ecdhe_curves, p_sock->conf.tls_ecdhe_curves,
	    sizeof(sock->conf.tls_ecdhe_curves)) >=
	    sizeof(sock->conf.tls_ecdhe_curves))
		fatalx("%s: strlcpy", __func__);

	socket_tls_load(sock);
}

struct socket *
sockets_conf_new_socket(struct thingsd *env, struct thing *thing, int id,
    int is_dup)
{
	struct socket		*sock;
	struct address		*a, *acp;

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		fatal("%s: calloc", __func__);

	if ((sock->conf.al = calloc(1,
	    sizeof(*sock->conf.al))) == NULL)
		fatal("%s: calloc", __func__);

	TAILQ_INIT(sock->conf.al);

	sock->conf.parent_id = 0;
	sock->conf.id = id;
	sock->conf.ipv4 = 1;
	sock->conf.thing_id = thing->conf.id;
	sock->conf.max_clients = thing->conf.max_clients;

	memset(sock->conf.tls_ciphers, 0,
	    sizeof(sock->conf.tls_ciphers));
	memset(sock->conf.tls_dhe_params, 0,
	    sizeof(sock->conf.tls_dhe_params));
	memset(sock->conf.tls_ecdhe_curves, 0,
	    sizeof(sock->conf.tls_ecdhe_curves));

	if (is_dup)
		goto done;

	snprintf(sock->conf.name, THINGSD_MAXTEXT, "%s_parent",
	    thing->conf.name);

	if (strlcpy(sock->conf.thing_name, thing->conf.name,
	    sizeof(sock->conf.thing_name)) >= sizeof(sock->conf.thing_name)) {
		free(sock->conf.al);
		free(sock);
		fatalx("%s: strlcpy", __func__);
	}

	TAILQ_FOREACH(a, thing->conf.tcp_al, entry) {
		if ((acp = calloc(1, sizeof(*acp))) == NULL)
			fatal("%s: calloc", __func__);
		memcpy(&acp->ss, &a->ss, sizeof(acp->ss));
		acp->ipproto = a->ipproto;
		acp->prefixlen = a->prefixlen;
		acp->port.val[0] = a->port.val[0];
		if (strlen(a->ifname) != 0) {
			if (strlcpy(acp->ifname, a->ifname,
			    sizeof(acp->ifname)) >= sizeof(acp->ifname)) {
				fatalx("%s: interface name truncated",
				    __func__);
			}
		}

		TAILQ_INSERT_TAIL(sock->conf.al, acp, entry);
	}

	thing->conf.sock_id = id;

	if (strlcpy(sock->conf.password, thing->conf.password,
	    sizeof(sock->conf.password)) >= sizeof(sock->conf.password))
		fatalx("%s: strlcpy", __func__);

	sock->conf.port.val[0] = thing->conf.tcp_listen_port.val[0];
	sock->conf.port.op = thing->conf.tcp_listen_port.op;

	sock->conf.tls = thing->conf.tls;
	sock->conf.tls_protocols = thing->conf.tls_flags;
	sock->conf.tls_flags = thing->conf.tls_flags;

	if(sock->conf.tls == 0)
		goto done;

	if((sock->conf.tls_cert_file =
	    strdup(thing->conf.tls_cert_file)) == NULL)
		fatal("%s: strdup", __func__);

	if((sock->conf.tls_key_file =
	    strdup(thing->conf.tls_key_file)) == NULL)
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
	socket_tls_load(sock);
done:
	return (sock);
}

int
sockets_socket_af(struct sockaddr_storage *ss, struct portrange port)
{
	switch (ss->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)ss)->sin_port = port.val[0];
		((struct sockaddr_in *)ss)->sin_len =
		    sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)ss)->sin6_port = port.val[0];
		((struct sockaddr_in6 *)ss)->sin6_len =
		    sizeof(struct sockaddr_in6);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
sockets_create_socket(struct addresslist *al, struct portrange port, int type)
{
	struct addrinfo		 hints;
	struct address		*a;
	int			 fd = -1, o_val = 1, flags;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	switch (type) {
	case S_UDP:
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
		hints.ai_protocol = 0;
		break;
	case S_TCP:
	default:
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags |= AI_PASSIVE;
		break;
	}

	TAILQ_FOREACH(a, al, entry) {
		if (sockets_socket_af(&a->ss, port) == -1) {
			log_warnx("%s: sockets_socket_af", __func__);
			goto fail;
		}

		fd = socket(a->ss.ss_family, hints.ai_socktype,
		    a->ipproto);
			log_debug("%s: opening socket (%d) for %s", __func__,
			    fd, a->ifname);

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &o_val,
		    sizeof(int)) == -1) {
			log_warn("%s: setsockopt error", __func__);
			return (-1);
		}

		/* non-blocking */
		flags = fcntl(fd, F_GETFL);
		flags |= O_NONBLOCK;
		fcntl(fd, F_SETFL, flags);

		if (bind(fd, (struct sockaddr *)&a->ss, a->ss.ss_len) == -1) {
			close(fd);
			log_info("%s: can't bind to port %d", __func__,
			    ntohs(port.val[0]));
			goto fail;
		}
		if (type == S_TCP) {
			if (listen(fd, SOMAXCONN) == -1) {
				log_warn("%s, unable to listen on socket",
				    __func__);
				goto fail;
			}
		}
	}

	free(a);
	return (fd);
fail:
	free(a);
	return (-1);
}

int
sockets_open_client(char *ip_addr, struct portrange *port)
{
	int			 fd = -1;

	struct addresslist	 al;
	struct address		*a;

	TAILQ_INIT(&al);
	if (host(ip_addr, &al, 1, port, ip_addr, -1) <= 0) {
		log_warnx("invalid listen ip: %s", ip_addr);
		return (-1);
	}

	TAILQ_FOREACH(a, &al, entry) {
		if (sockets_socket_af(&a->ss, *port) == -1) {
			log_warnx("%s: sockets_socket_af", __func__);
			return (-1);
		}

		if ((fd = socket(a->ss.ss_family, SOCK_STREAM,
		    a->ipproto)) == -1)
			continue;

		if ((connect(fd, (struct sockaddr *)&a->ss,
		    a->ss.ss_len)) == -1) {
			if (errno != EINPROGRESS) {
				close(fd);
				return (-1);
			}
		}
	}

	if (fd == -1)
		log_warnx("can't connect ip: %s", ip_addr);

	free(a);
	return fd;
}

struct socket *
sockets_new_socket(char *port)
{
	struct socket		*sock;

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		fatal("%s: calloc", __func__);

	return (sock);
};

struct socket *
sockets_get_socket(struct thingsd *env, int val)
{
	struct socket		*sock = NULL;

	TAILQ_FOREACH(sock, env->sockets, entry) {
		if (sock->fd == val)
			return sock;
	}

	return NULL;
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

void
sockets_write_to_clients(struct package *package)
{
	struct socket		*sock = NULL;
	struct client		*client = NULL;

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		if (sock->conf.thing_id == package->thing_id &&
		    sock->client_cnt > 0) {
			TAILQ_FOREACH(client, sock->clients, entry) {
				if (client->subscribed) {
					bufferevent_write(client->bev,
					    package->pkt, package->len);
				}
			}
		}
	}
}

void
sockets_show_clients_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[THINGSD_MAXNAME];
	struct client	*client, nci;
	struct socket	*sock;

	memcpy(filter, imsg->data, sizeof(filter));

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		if (sock->client_cnt == 0)
			continue;
		TAILQ_FOREACH(client, sock->clients, entry) {
			if (filter[0] == '\0' || strcmp(filter,
			    client->name) == 0) {

				memcpy(&nci.name, client->name,
				    sizeof(nci.name));

				nci.subscribed = client->subscribed;
				nci.fd = client->fd;
				nci.port = client->port;
				nci.tls = client->tls;

				if (proc_compose_imsg(ps, PROC_CONTROL, -1,
				    IMSG_GET_INFO_CLIENTS_DATA,
				    imsg->hdr.peerid, -1, &nci,
				    sizeof(nci)) == -1)
					return;

			}
		}
	}

	if (proc_compose_imsg(ps, PROC_CONTROL, -1,
	    IMSG_GET_INFO_CLIENTS_END_DATA, imsg->hdr.peerid,
		    -1, &nci, sizeof(nci)) == -1)
			return;
}

void
sockets_show_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[THINGSD_MAXNAME];
	struct socket	*socket, nsi;

	memcpy(filter, imsg->data, sizeof(filter));

	TAILQ_FOREACH(socket, thingsd_env->sockets, entry) {
		if (filter[0] == '\0' || strcmp(filter,
		    socket->conf.name) == 0) {

			memcpy(&nsi.conf.name, socket->conf.name,
			    sizeof(nsi.conf.name));

			nsi.fd = socket->fd;
			nsi.conf.port = socket->conf.port;
			nsi.conf.tls = socket->conf.tls;
			nsi.client_cnt = socket->client_cnt;
			nsi.conf.max_clients = socket->conf.max_clients;

			if (proc_compose_imsg(ps, PROC_CONTROL, -1,
			    IMSG_GET_INFO_SOCKETS_DATA,
			    imsg->hdr.peerid, -1, &nsi,
			    sizeof(nsi)) == -1)
				return;

		}
	}

	if (proc_compose_imsg(ps, PROC_CONTROL, -1,
	    IMSG_GET_INFO_SOCKETS_END_DATA, imsg->hdr.peerid,
		    -1, &nsi, sizeof(nsi)) == -1)
			return;
}

void
sockets_socket_rlimit(int maxfd)
{
	struct rlimit	 rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to get resource limit", __func__);

	log_debug("%s: max open files %llu", __func__, rl.rlim_max);

	/*
	 * Allow the maximum number of open file descriptors for this
	 * login class (which should be the class "daemon" by default).
	 */
	if (maxfd == -1)
		rl.rlim_cur = rl.rlim_max;
	else
		rl.rlim_cur = MAXIMUM(rl.rlim_max, (rlim_t)maxfd);
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to set resource limit", __func__);
}

void
sockets_kill_client(struct privsep *ps, struct imsg *imsg)
{
	struct socket		*sock;
	struct client		*client;
	char			 client_name[THINGSD_MAXTEXT];

	memcpy(client_name, imsg->data, sizeof(client_name));

	TAILQ_FOREACH(sock, thingsd_env->sockets, entry) {
		TAILQ_FOREACH(client, sock->clients, entry) {
			if (strcmp(client->name, client_name) == 0) {
				log_debug("Control killed client: %s",
				    client_name);
				client_del(client);
				break;
			}
		}
	}
}

int
sockets_dispatch_thingsd(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct package		*package = NULL;
	struct privsep		*ps = p->p_ps;
	int			 res = 0, cmd = 0, verbose;
	unsigned int		 mode;

	switch (imsg->hdr.type) {
	case IMSG_KILL_CLIENT:
		sockets_kill_client(ps, imsg);
		break;
	case IMSG_DIST_THING_PACKAGE:
		IMSG_SIZE_CHECK(imsg, package);
		package = (struct package *)imsg->data;
		sockets_write_to_clients(package);
		break;
	case IMSG_CFG_SOCKS:
		config_getsocks(thingsd_env, imsg);
		break;
	case IMSG_CFG_DONE:
		config_getcfg(thingsd_env, imsg);
		break;
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &mode);
		memcpy(&mode, imsg->data, sizeof(mode));

		config_getreset(thingsd_env, imsg);
		break;
	case IMSG_CFG_TLS:
		config_getsocks_tls(thingsd_env, imsg);
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		break;
	case IMSG_CTL_START:
		sockets_launch();
		break;
	case IMSG_GET_INFO_CLIENTS_REQUEST:
		sockets_show_clients_info(ps, imsg);
		break;
	case IMSG_GET_INFO_SOCKETS_REQUEST:
		sockets_show_info(ps, imsg);
		break;
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	default:
		if (proc_compose_imsg(ps, PROC_PARENT, -1, cmd,
		    imsg->hdr.peerid, -1, &res, sizeof(res)) == -1)
			return (-1);
		break;
	}

	return (0);
}

void
sockets_sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	default:
		fatalx("unexpected signal");
	}
}

void
sockets_shutdown(void)
{
	struct socket		*sock = NULL, *tsock;
	struct client		*client, *tclient;

	/* clean up sockets */
	TAILQ_FOREACH_SAFE(sock, thingsd_env->sockets, entry, tsock) {
		/* clean up clients */
		TAILQ_FOREACH_SAFE(client, sock->clients, entry, tclient) {
			if (client->tls) {
				if (event_initialized(&client->ev))
					event_del(&client->ev);
				tls_free(client->tls_ctx);
			} else {
				if (client->bev != NULL)
					bufferevent_disable(client->bev,
					    EV_READ | EV_WRITE);
				if (client->bev != NULL)
					bufferevent_free(client->bev);
			}
			close(client->fd);
			TAILQ_REMOVE(sock->clients, client, entry);
			free(client);
		}

		if (sock->conf.tls) {
			tls_config_free(sock->tls_config);
			tls_free(sock->tls_ctx);
			free(sock->conf.tls_cert);
			free(sock->conf.tls_key);
			free(sock->conf.tls_ca);
			free(sock->conf.tls_ca_file);
			free(sock->conf.tls_crl);
			free(sock->conf.tls_crl_file);
			free(sock->conf.tls_ocsp_staple);
			free(sock->conf.tls_ocsp_staple_file);
		}
		if (event_initialized(&sock->ev))
			event_del(&sock->ev);
		evtimer_del(&sock->pause);
		close(sock->fd);
		TAILQ_REMOVE(thingsd_env->sockets, sock, entry);
		free(sock);
	}
	free(thingsd_env->sockets);

}

int
sockets_client_cmp(struct client *a, struct client *b)
{
	return ((int)a->id - b->id);
}

int
sockets_accept_reserve(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve, volatile int *counter)
{
	int ret;

	if (getdtablecount() + reserve +
	    ((*counter + 1) * FD_NEEDED) >= getdtablesize()) {
		log_debug("inflight fds exceeded");
		errno = EMFILE;
		return -1;
	}

	if ((ret = accept4(sockfd, addr, addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC))
	    > -1) {
		(*counter)++;
		log_debug("inflight incremented, now %d", *counter);
	}
	return ret;
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
	evbuffercb		 clientrd = client_rd;
	evbuffercb		 clientwr = client_wr;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	subtime.tv_sec = CLIENT_SUB_TIME_SEC;
	subtime.tv_usec = CLIENT_SUB_TIME_USEC;

	sock = sockets_get_socket(thingsd_env, fd);
	if (sock == NULL)
		return;

	log_debug("%s: client connection started on listener %d", __func__,
	    sock->conf.id);

	event_add(&sock->ev, NULL);

	client_fd = sockets_accept_reserve(fd, (struct sockaddr *)&ss, &len,
	    FD_RESERVE, &client_inflight);
	if (client_fd == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		case EMFILE:
		case ENFILE:
			event_del(&sock->ev);
			evtimer_add(&sock->pause, &backoff);
			return;
		default:
			log_warnx("client accept failed");
		}
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto err2;

	client->port.val[0] = sock->conf.port.val[0];
	client->port.op = sock->conf.port.op;

	memset(&client->timeout, 0, sizeof(struct event));
	evtimer_set(&client->timeout, sockets_client_sub_timeout, client);

	if (sock->conf.tls) {
		if (tls_accept_socket(sock->tls_ctx, &client->tls_ctx,
		    client_fd) == -1) {
			log_warnx("tls accept failed: %s",
			    tls_error(sock->tls_ctx));
			goto err;
		}
	}

	client->packages = calloc(1, sizeof(*client->packages));
	if (client->packages == NULL)
		goto err2;

	TAILQ_INIT(client->packages);

	if (sock->conf.max_clients > 0)
		if (sock->client_cnt > sock->conf.max_clients) {
			log_debug("%s: listener %d max clients reached",
			    __func__, sock->conf.id);
			goto err;
		}

	client->sock_id = sock->conf.id;
	client->thing_id = sock->conf.thing_id;
	client->sock = sock;
	client->sock_conf = &sock->conf;
	client->subscribed = 0;
	client->evb = evbuffer_new();

	evtimer_pending(&client->timeout, NULL);
	log_debug("%s: started client timer", __func__);
	evtimer_add(&client->timeout, &subtime);

	if (client->evb == NULL)
		goto err;

	client->fd = client_fd;
	client->join_time = time(NULL);

	if (sock->conf.tls) {
		client->tls = 1;
		event_del(&client->ev);
		event_set(&client->ev, client->fd, EV_READ | EV_PERSIST,
		    socket_tls_handshake, client);
		event_add(&client->ev, NULL);
		goto done;
	}

	client->bev = bufferevent_new(client->fd, clientrd, clientwr,
	    client_err, client);

	if (client->bev == NULL)
		goto err;

	if (client->tls) {
		event_set(&client->bev->ev_read, client->fd, EV_READ,
		    client_tls_readcb, client->bev);
		event_set(&client->bev->ev_write, client->fd, EV_WRITE,
		    client_tls_writecb, client->bev);
	}

	bufferevent_setwatermark(client->bev, EV_READ, 0, PKT_BUFF);
	bufferevent_enable(client->bev, EV_READ|EV_WRITE);
	TAILQ_INSERT_TAIL(sock->clients, client, entry);
done:
	log_debug("%s: client connected (%d)", __func__, client->fd);
	return;
err:
	sock->client_cnt--;
err2:
	log_debug("%s: client error", __func__);
	client_inflight--;
	if (client_fd != -1)
		close(client_fd);
	if (client != NULL) {
		if (sock->conf.tls)
			tls_free(client->tls_ctx);
		free(client);
	}
}
