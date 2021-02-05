/*
 * Copyright (c) 2016, 2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
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
#include <sys/tree.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "proc.h"
#include "thingsd.h"

extern volatile int client_inflight;
extern enum privsep_procid privsep_process;

void	 client_write_to_things(struct packages *);

void
client_del(struct client *client)
{
	struct socket		*sock = client->sock;
	struct socket		*psock = NULL, *csock = NULL;
	struct client		*tclient, *uclient;

	TAILQ_FOREACH_SAFE(tclient, sock->clients, entry, uclient) {
		if (client->id == tclient->id)
			TAILQ_REMOVE(sock->clients, client, entry);
	}
	log_debug("%s: disconnecting client %s (%d)", __func__, client->name,
	    client->fd);
	if (client->tls)
		tls_free(client->tls_ctx);

	if (evtimer_initialized(&client->timeout))
		evtimer_del(&client->timeout);

	if (client->subscribed == 0)
		log_debug("%s: client disconnected", __func__);
	else
		log_debug("client disconnected: %s", client->name);

	if (client->bev != NULL)
		bufferevent_free(client->bev);

	client_inflight--;

	if (client->subscribed == 0)
		goto done;

	/* account for parent/child client counts */
	if (sock->conf.child_id) {
		TAILQ_FOREACH(csock, thingsd_env->sockets, entry)
			if (csock->conf.id == sock->conf.child_id)
				break;
	}
	if (sock->conf.parent_id) {
		TAILQ_FOREACH(psock, thingsd_env->sockets, entry)
			if (psock->conf.id == sock->conf.parent_id)
				break;
	}
	sock->client_cnt--;
	if (csock != NULL)
		csock->client_cnt--;
	if (psock != NULL)
		psock->client_cnt--;
done:
	close(client->fd);
	free(client);
}

void
client_rd(struct bufferevent *bev, void *arg)
{
	struct client		*client = (struct client *)arg;
	size_t			 len;
	char			*pkt = NULL, *npkt = NULL;
	struct package		*package = NULL;


	client->evb = EVBUFFER_INPUT(bev);
	len = EVBUFFER_LENGTH(client->evb);

	if (client->subscribed == 0) {
		log_debug("%s: client connection established (%d)", __func__,
		    client->fd);

		/* allow one shot at subscription so we don't get hammered */
		pkt = calloc(len, sizeof(*pkt));
		if (pkt == NULL)
			return;

		npkt = calloc(len, sizeof(*npkt));
		if (npkt == NULL) {
			free(pkt);
			return;
		}

		bufferevent_disable(client->bev, EV_READ);
		evbuffer_remove(client->evb, pkt, len);

		/* peak into packet and ensure it's a subscription packet */
		if (pkt[0] == 0x7E && pkt[1] == 0x7E && pkt[2] == 0x7E) {
			log_debug("%s: subscription packet received", __func__);
			memmove(npkt, pkt+3, len-3);
			parse_buf(client, npkt, len-3);
			if (client->subscribed) {
				bufferevent_enable(client->bev,
				    EV_READ | EV_WRITE);
				if (evtimer_initialized(&client->timeout))
				       evtimer_del(&client->timeout);
			}
		}
	} else if (client->subscribed) {
		/* write to things */
		if ((package = calloc(1, sizeof(*package))) == NULL)
			return;
		evbuffer_remove(client->evb, package->pkt, len);
		package->thing_id = client->thing_id;
		package->len = len;
		TAILQ_INSERT_TAIL(thingsd_env->packages, package, entry);
		client_write_to_things(thingsd_env->packages);
		evbuffer_drain(client->evb, len);
	}
	free(pkt);
	free(npkt);
}

void
client_write_to_things(struct packages *packages)
{
	struct privsep		*ps = thingsd_env->thingsd_ps;
	struct package		*package, *tpkg, p;
	unsigned int		 id, what;
	int			 fd = -1, n, m;
	struct iovec		 iov[6];
	size_t			 c;

	TAILQ_FOREACH_SAFE(package, packages, entry, tpkg) {
		for (id = 0; id < PROC_MAX; id++) {
			what = ps->ps_what[id];

			if ((what & CONFIG_SOCKS) == 0 || id == privsep_process)
				continue;

			memcpy(&p, package, sizeof(p));

			c = 0;
			iov[c].iov_base = &p;
			iov[c++].iov_len = sizeof(p);
			if (id == PROC_PARENT) {
			/* XXX imsg code will close the fd after 1st call */
				n = -1;
				proc_range(ps, id, &n, &m);
				for (n = 0; n < m; n++) {
					/* send thing fd */
					if (proc_composev_imsg(ps, id, n,
					    IMSG_DIST_CLIENT_PACKAGE, -1, fd,
					    iov, c) != 0) {
						log_warn("%s: failed to compose"
						    " IMSG_DIST_THING_PACKAGE"
						    " imsg",
					    __func__);
					return;
					}
					if (proc_flush_imsg(ps, id, n) == -1) {
						log_warn("%s: failed to flush "
						    "IMSG_DIST_CLIENT_PACKAGE "
						    "imsg",
						    __func__);
						return;
					}
				}
			}
		}
		TAILQ_REMOVE(packages, package, entry);
		free(package);
	}
}

void
client_wr(struct bufferevent *bev, void *arg)
{
}

void
client_err(struct bufferevent *bev, short error, void *arg)
{
	struct client		*client = (struct client *)arg;

	if ((error & EVBUFFER_EOF) == 0)
		log_warnx("%s: client socket error, disconnecting", __func__);

	client_del(client);
}
