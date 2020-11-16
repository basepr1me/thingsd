/*
 * Copyright (c) 2016, 2019, 2020 Tracey Emery <tracey@traceyemery.net>
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
#include <sys/socket.h>

#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <imsg.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "proc.h"
#include "thingsd.h"

extern struct ctl_pkt	*ctl_pkt;
extern bool		 ctl_conn;

void
create_sockets(struct thingsd *env, bool reconn)
{
	struct thing		*thing;
	struct socket		*sock = NULL, *tsock, *conn_socket = NULL;
	char			*iface = NULL;
	int			 csock = 0, conn_csock = 0;
	bool			 fail = false;
	evbuffercb		 socketrd = socket_rd;
	evbuffercb		 socketwr = socket_wr;

	TAILQ_FOREACH(thing, env->things, entry) {
		if (reconn) {
			if (thing->exists)
				continue;
			if (thing->type == TCP)
				goto recreate;
			else
				continue;
		}

		sock = new_socket(thing->port);

		if (thing->tls)
			socket_tls_init(sock, thing);
		else
			sock->tls = false;

		sock->max_clients += thing->max_clients;

		memcpy(&sock->name, thing->name, sizeof(sock->name));

		if (strlen(thing->iface) != 0)
			iface = get_ifaddrs(thing->iface);

		if (thing->type == DEV) {
			if((csock = sock->fd = create_socket(thing->port, iface,
			    TCP)) == -1)
				log_warnx("fd create socket failed");
			else if (thing->fd != -1)
				thing->exists = true;
			else {
				thing->exists = false;
			}
		}

		if (strlen(thing->udp) != 0) {
			/* create fd for udp instead of serial device */
			thing->type = UDP;
			conn_socket = new_socket(thing->rcv_port);

			csock = sock->fd = create_socket(thing->port,
			    iface, TCP);
			if (csock == -1)
				log_warnx("udp create socket failed");
			else
				thing->exists = true;

			conn_csock = conn_socket->fd =
			    create_socket(thing->rcv_port, iface, thing->type);
			if (conn_csock == -1)
				log_warnx("udp create socket failed");
			else
				thing->exists = true;

			thing->fd = conn_socket->fd;
		}
recreate:
		if (strlen(thing->ipaddr) != 0) {
			thing->type = TCP;

			if (thing->persist == 1) {
				thing->fd = open_client_socket(thing->ipaddr,
				    thing->conn_port);
				if (thing->fd == -1) {
					log_warnx("ipaddr connection failed");
					if (reconn)
						continue;
					thing->exists = false;
					add_reconn(thing);
				} else
					thing->exists = true;

				if (thing->fd != -1) {
					thing->bev = bufferevent_new(thing->fd,
					    socketrd, socketwr, socket_err,
					    env);

					if (thing->bev == NULL)
						fatalx("ipaddr bev error");

					thing->evb = evbuffer_new();

					if (thing->evb == NULL)
						fatalx("ipaddr evb error");

					bufferevent_enable(thing->bev,
					    EV_READ | EV_WRITE);
				}
			} else
				thing->fd = -1;

			if (reconn == false) {
				csock = sock->fd = create_socket(thing->port,
				    iface, TCP);
				if (csock == -1) {
					log_warnx("tcp create socket failed");
					thing->exists = false;
					add_reconn(thing);
				} else {
					if (thing->fd != -1)
						thing->exists = true;
				}
			}

		}
		if (reconn && thing->exists) {
			log_info("reconnected: %s", thing->name);
			continue;
		}

		if (csock == -1 || conn_csock == -1)
			fatalx("socket creation failed");
		else if (csock == -2 || conn_csock == -2) {
			fail = true;

			TAILQ_FOREACH(tsock, env->sockets, entry) {
				if (thing->port == tsock->port) {
					fail = false;
					break;
				}
			}

			if (fail)
				fatalx("can't set socket port");
			else {
				log_info("   -socket exists: skipping");
				fail = true;
			}

		}

		if (fail == false)
			TAILQ_INSERT_TAIL(env->sockets, sock, entry);

		if (thing->type == UDP)
			TAILQ_INSERT_TAIL(env->sockets, conn_socket, entry);

		if (sock->fd > 0) {
			event_set(sock->ev, sock->fd, EV_READ | EV_PERSIST,
			    client_conn, env);
			if (event_add(sock->ev, NULL))
				fatalx("event add sock");
			evtimer_set(&sock->pause, client_accept_paused, sock);
		}

		if (conn_socket != NULL && conn_socket->fd > 0) {
			event_set(conn_socket->ev, conn_socket->fd,
			    EV_READ | EV_PERSIST, udp_event, env);

			if (event_add(conn_socket->ev, NULL))
				fatalx("event add conn_socket");
		}

	}
	free(iface);
}

int
create_socket(int iport, char *iface, int type)
{
	struct addrinfo		 addr_hints, *addr_res, *loop_res;
	char			 port[6];
	int			 socket_fd, gai, o_val = 1, flags;

	snprintf(port, sizeof(port), "%d", iport);
	memset(&addr_hints, 0, sizeof(addr_hints));
	addr_hints.ai_family = AF_UNSPEC;
	switch (type) {
	case UDP:
		addr_hints.ai_socktype = SOCK_DGRAM;
		addr_hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
		addr_hints.ai_protocol = 0;
		break;
	case TCP:
	default:
		addr_hints.ai_socktype = SOCK_STREAM;
		addr_hints.ai_flags |= AI_PASSIVE;
		break;
	}
	gai = getaddrinfo(iface, port, &addr_hints, &addr_res);
	if (gai != 0)
		fatalx("getaddrinfo failed on %s: %s:%s", gai_strerror(gai),
		    iface, port);
	for (loop_res = addr_res; loop_res != NULL;
	    loop_res = loop_res->ai_next) {
		socket_fd = socket(loop_res->ai_family, loop_res->ai_socktype,
		    loop_res->ai_protocol);
		if (socket_fd == -1)
			fatalx("unable to create socket");

		if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &o_val,
		    sizeof(int)) == -1) {
			freeaddrinfo(addr_res);
			fatalx("setsockopt error");

		}

		/* non-blocking */
		flags = fcntl(socket_fd, F_GETFL);
		flags |= O_NONBLOCK;

		fcntl(socket_fd, F_SETFL, flags);

		if (bind(socket_fd, loop_res->ai_addr,
		    loop_res->ai_addrlen) == -1) {
			close(socket_fd);
			log_warnx("%s%s", "bind address busy\n",
			    " -checking existing sockets");
			return -2;
		}

		break;
	}

	if (loop_res == NULL) {
		freeaddrinfo(addr_res);
		fatalx("can't bind to port");
	}

	freeaddrinfo(addr_res);

	if (type == TCP) {
		if (listen(socket_fd, SOMAXCONN) == -1) {
			fatal("unable to listen on socket");
			return -1;
		}
	}

	return socket_fd;
}

int
open_client_socket(char *ip_addr, int cport)
{
	struct addrinfo		 hints, *res, *res0;
	int			 client_fd, error;
	char			 port[6];

	memset(&hints, 0, sizeof(hints));

	snprintf(port, sizeof(port), "%d", cport);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error = getaddrinfo(ip_addr, port, &hints, &res0);
	if (error)
		fatalx("getaddrinfo failed: %s", gai_strerror(error));

	client_fd = -1;

	for (res = res0; res; res = res->ai_next) {
		client_fd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);

		if (client_fd == -1)
			continue;

		if (connect(client_fd, res->ai_addr, res->ai_addrlen) == -1) {
			close(client_fd);
			client_fd = -1;
			continue;
		}

		break;
	}

	if (client_fd == -1)
		log_warnx("can't connect ip: %s", ip_addr);

	freeaddrinfo(res0);

	return client_fd;
}

char *
get_ifaddrs(char *name)
{
	struct ifaddrs		*ifaps, *ifap;
	struct sockaddr		*sa = NULL;
	char			*addr = NULL;
	char			 hbuf[NI_MAXHOST];

	if (getifaddrs(&ifaps) == -1)
		fatalx("getifaddrs error");

	ifap = ifaps;

	while (ifap) {
		if ((ifap->ifa_addr) &&
		    ((ifap->ifa_addr->sa_family == AF_INET) ||
		    (ifap->ifa_addr->sa_family == AF_INET6))) {

			if (ifap->ifa_addr->sa_family == AF_INET) {
				struct sockaddr_in *in =
				    (struct sockaddr_in *) ifap->ifa_addr;
				sa = (struct sockaddr *) in;
			}

			if (ifap->ifa_addr->sa_family == AF_INET6) {
				struct sockaddr_in6 *in6 =
				    (struct sockaddr_in6*) ifap->ifa_addr;
				sa = (struct sockaddr *) in6;
			}

			if (getnameinfo(sa, sa->sa_len, hbuf,
			    sizeof(hbuf), NULL, 0, NI_NAMEREQD |
			    NI_NUMERICHOST))
				log_warnx("getnameinfo error");

			free(addr);

			addr = NULL;
			addr = strdup(hbuf);

			if (addr == NULL)
				fatalx("out of memory");

			if (strcmp(name, ifap->ifa_name) == 0) {
				freeifaddrs(ifaps);
				return addr;
			}

		}

		ifap = ifap->ifa_next;

	}

	free(addr);
	freeifaddrs(ifaps);
	return NULL;
}

struct socket *
new_socket(int port)
{
	struct socket		*sock;

	sock = calloc(1, sizeof(*sock));
	if (sock == NULL)
		fatal("%s: calloc", __func__);

	sock->ev = calloc(1, sizeof(*sock->ev));
	if (sock->ev == NULL)
		fatal("%s: calloc", __func__);

	sock->port = port;

	return (sock);
};

struct socket *
get_socket(struct thingsd *env, int val)
{
	struct socket		*sock = NULL;

	TAILQ_FOREACH(sock, env->sockets, entry) {
		if (sock->fd == val || sock->port == val)
			return sock;
	}

	return NULL;
}

void
socket_rd(struct bufferevent *bev, void *arg)
{
	struct thingsd		*env = (struct thingsd *)arg;
	struct thing		*thing = NULL, *tthing;
	struct client		*client;
	struct subscription	*sub;
	size_t			 len;
	int			 fd = bev->ev_read.ev_fd;
	char			*pkt = NULL;

	TAILQ_FOREACH(tthing, env->things, entry) {
		if (tthing->fd == fd) {
			thing = tthing;

			thing->evb = EVBUFFER_INPUT(bev);

			len = EVBUFFER_LENGTH(thing->evb);

			pkt = calloc(len, sizeof(*pkt));
			if (pkt == NULL)
				return;

			evbuffer_remove(thing->evb, pkt, len);
			TAILQ_FOREACH(client, env->clients, entry) {
				TAILQ_FOREACH(sub, client->subscriptions,
				    entry) {
					if (strcmp(sub->thing_name,
					    thing->name) == 0)
						bufferevent_write(client->bev,
						    pkt, len);
				}
			}

			if (env->packet_client_count > 0)
				send_to_packet_client(env, thing->name, pkt,
				    len);

			free(pkt);
			pkt = NULL;
		}
	}
	free(pkt);
}

void
socket_wr(struct bufferevent *bev, void *arg)
{
}

void
socket_err(struct bufferevent *bev, short error, void *arg)
{
	struct thingsd		*env = (struct thingsd *)arg;
	struct thing		*thing = NULL;
	int			 fd = bev->ev_read.ev_fd;

	if ((error & EVBUFFER_ERROR) == 0 || error & EVBUFFER_TIMEOUT) {
		TAILQ_FOREACH(thing, env->things, entry) {
			if (thing->fd == fd && thing->persist) {
				bufferevent_free(thing->bev);
				close(thing->fd);
				thing->fd = -1;
				thing->exists = false;
				add_reconn(thing);
				log_warnx("thing error: %s disconnected",
				    thing->name);
			}
		}
	}
}

void
sockets_show_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[THINGSD_MAXNAME];
	struct socket	*socket, nsi;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_SOCKETS_REQUEST:

		memcpy(filter, imsg->data, sizeof(filter));

		TAILQ_FOREACH(socket, thingsd_env->sockets, entry) {
			if (filter[0] == '\0' || memcmp(filter,
			    socket->name, sizeof(filter)) == 0) {

				memcpy(&nsi.name, socket->name,
				    sizeof(nsi.name));

				nsi.fd = socket->fd;
				nsi.port = socket->port;
				nsi.tls = socket->tls;
				nsi.client_cnt = socket->client_cnt;
				nsi.max_clients = socket->max_clients;

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

		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}
