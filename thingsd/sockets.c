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

#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "thingsd.h"

extern struct dthgs	*pdthgs;
extern struct ctl_pkt	*ctl_pkt;
extern bool		 ctl_conn;

void
create_socks(struct thgsd *pthgsd, bool reconn)
{
	struct thg		*thg;
	struct sock		*sock = NULL, *tsock, *conn_sock = NULL;
	char			*iface = NULL;
	int			 csock = 0, conn_csock = 0;
	bool			 fail = false;
	evbuffercb		 sockrd = sock_rd;
	evbuffercb		 sockwr = sock_wr;

	TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
		if (reconn) {
			if (thg->exists)
				continue;
			if (thg->type == TCP)
				goto recreate;
			else
				continue;
		}
		sock = new_sock(thg->port);
		if (thg->tls)
			sock_tls_init(sock, thg);
		else
			sock->tls = false;
		sock->max_clts += thg->max_clt;
		sock->name = thg->name;
		if (thg->iface != NULL)
			iface = get_ifaddrs(thg->iface);
		if (thg->type == DEV) {
			if((csock = sock->fd = create_sock(thg->port, iface,
			    TCP)) == -1)
				log_warnx("fd create socket failed");
			else if (thg->fd != -1)
				thg->exists = true;
			else {
				thg->exists = false;
			}
		}
		if (thg->udp != NULL) {
			/* create fd for udp instead of serial device */
			thg->type = UDP;
			conn_sock = new_sock(thg->conn_port);
			if ((csock = sock->fd = create_sock(thg->port, iface,
			    TCP)) == -1)
				log_warnx("udp create socket failed");
			else
				thg->exists = true;
			if ((conn_csock = conn_sock->fd =
			    create_sock(thg->conn_port, iface,
		 	    thg->type)) == -1)
				log_warnx("udp create socket failed");
			else
				thg->exists = true;
			thg->fd = conn_sock->fd;
		}
 recreate:
		if (thg->ipaddr != NULL) {
			thg->type = TCP;
			if (thg->persist == 1) {
				if ((thg->fd = open_clt_sock(thg->ipaddr,
				    thg->conn_port)) == -1) {
					log_warnx("ipaddr connection failed");
					if (reconn)
						continue;
					thg->exists = false;
					add_reconn(thg);
				} else
					thg->exists = true;
				if (thg->fd != -1) {
					thg->bev = bufferevent_new(thg->fd,
					    sockrd, sockwr, sock_err, pthgsd);
					if (thg->bev == NULL)
						fatalx("ipaddr bev error");
					thg->evb = evbuffer_new();
					if (thg->evb == NULL)
						fatalx("ipaddr evb error");
					bufferevent_enable(thg->bev,
					    EV_READ|EV_WRITE);
				}
			} else
				thg->fd = -1;
			if (reconn == false) {
				if ((csock = sock->fd = create_sock(thg->port,
				    iface, TCP)) == -1) {
					log_warnx("tcp create socket failed");
					thg->exists = false;
					add_reconn(thg);
				} else {
					if (thg->fd != -1)
						thg->exists = true;
				}
			}
		}
		if (reconn && thg->exists) {
			log_info("reconnected: %s", thg->name);
			continue;
		}
		if (csock == -1 || conn_csock == -1)
			fatalx("socket creation failed");
		else if (csock == -2 || conn_csock == -2) {
			fail = true;
			TAILQ_FOREACH(tsock, &pthgsd->socks, entry) {
				if (thg->port == tsock->port) {
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
			TAILQ_INSERT_TAIL(&pthgsd->socks, sock, entry);
		if (thg->type == UDP)
			TAILQ_INSERT_TAIL(&pthgsd->socks, conn_sock, entry);
		if (sock->fd > 0) {
			event_set(sock->ev, sock->fd, EV_READ|EV_PERSIST,
			    clt_conn, pthgsd);
			if (event_add(sock->ev, NULL))
				fatalx("event add sock");
		}
		if (conn_sock != NULL && conn_sock->fd > 0) {
			event_set(conn_sock->ev, conn_sock->fd,
			    EV_READ|EV_PERSIST, udp_evt, pthgsd);
			if (event_add(conn_sock->ev, NULL))
				fatalx("event add conn_sock");
		}
	}
}

int
create_sock(int iport, char *iface, int type)
{
	struct addrinfo		 addr_hints, *addr_res, *loop_res;
	char			 port[6];
	int			 sock_fd, gai, o_val = 1, flags;

	snprintf(port, sizeof(port), "%d", iport);
	memset(&addr_hints, 0, sizeof(addr_hints));
	addr_hints.ai_family = AF_UNSPEC;
	switch (type) {
	case UDP:
		addr_hints.ai_socktype = SOCK_DGRAM;
		addr_hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG;
		addr_hints.ai_protocol = 0;
		break;
	case TCP:
	default:
		addr_hints.ai_socktype = SOCK_STREAM;
		addr_hints.ai_flags |= AI_PASSIVE;
		break;
	}
	if ((gai = getaddrinfo(iface, port, &addr_hints, &addr_res)) != 0)
		fatalx("getaddrinfo failed: %s", gai_strerror(gai));
	for (loop_res = addr_res; loop_res != NULL;
	    loop_res = loop_res->ai_next) {
		if ((sock_fd = socket(loop_res->ai_family,
		    loop_res->ai_socktype, loop_res->ai_protocol)) == -1)
			fatalx("unable to create socket");
		if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &o_val,
		    sizeof(int)) == -1) {
			freeaddrinfo(addr_res);
			fatalx("setsockopt error");
		}
		/* non-blocking */
		flags = fcntl(sock_fd, F_GETFL);
		flags |= O_NONBLOCK;
		fcntl(sock_fd, F_SETFL, flags);
		if (bind(sock_fd, loop_res->ai_addr,
		    loop_res->ai_addrlen) == -1) {
			close(sock_fd);
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
		if (listen(sock_fd, SOMAXCONN) == -1) {
			fatal("unable to listen on socket");
			return -1;
		}
	}
	return sock_fd;
}

int
open_clt_sock(char *ip_addr, int cport)
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
	struct ifaddrs		*ifap = 0, *ifa;
	struct sockaddr		*sa = NULL;
	char			*addr = NULL;
	char			 hbuf[NI_MAXHOST];
	int			 count = 0;

	if (getifaddrs(&ifap) == -1)
		fatalx("getifaddrs error");
	for (count = 0, ifa = ifap; ifa; ifa = ifa->ifa_next) {
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
			addr = strdup(hbuf);
			if (addr == NULL)
				goto err;
			if (strcmp(name, ifap->ifa_name) == 0) {
				freeifaddrs(ifap);
				return addr;
			}
		}
	}
err:
	freeifaddrs(ifap);
	return NULL;
}

struct sock *
new_sock(int port)
{
	struct sock		*sock;

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		fatalx("no sock calloc");
	if ((sock->ev = calloc(1, sizeof(*sock->ev))) == NULL)
		fatalx("no sock->ev calloc");
	sock->port = port;
	return (sock);
};

struct sock *
get_sock(struct thgsd *pthgsd, int val)
{
	struct sock		*sock = NULL;

	TAILQ_FOREACH(sock, &pthgsd->socks, entry) {
		if (sock->fd == val || sock->port == val)
			return sock;
	}
	return NULL;
}

void
sock_rd(struct bufferevent *bev, void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct thg		*thg = NULL, *tthg;
	struct clt		*clt;
	size_t			 len;
	int			 fd = bev->ev_read.ev_fd;
	size_t			 n;
	char			*pkt;

	TAILQ_FOREACH(tthg, &pthgsd->thgs, entry) {
		if (tthg->fd == fd) {
			thg = tthg;
			thg->evb = EVBUFFER_INPUT(bev);
			len = EVBUFFER_LENGTH(thg->evb);

			if ((pkt = calloc(len, sizeof(*pkt))) == NULL)
				return;

			evbuffer_remove(thg->evb, pkt, len);
			TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
				for (n = 0; n < clt->le; n++) {
					if (strcmp(clt->sub_names[n], thg->name)
					    == 0)
						bufferevent_write(clt->bev, pkt,
						    len);
				}
			}
			send_ctl_pkt(thg->name, pkt, len);
			free(pkt);
		}
	}
}

void
sock_wr(struct bufferevent *bev, void *arg)
{
}

void
sock_err(struct bufferevent *bev, short error, void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct thg		*thg = NULL;
	int			 fd = bev->ev_read.ev_fd;

	if ((error & EVBUFFER_ERROR) == 0 || error & EVBUFFER_TIMEOUT) {
		TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
			if (thg->fd == fd && thg->persist) {
				bufferevent_free(thg->bev);
				close(thg->fd);
				thg->fd = -1;
				thg->exists = false;
				add_reconn(thg);
				log_warnx("thing error: %s disconnected",
				    thg->name);
			}
		}
	}
}
