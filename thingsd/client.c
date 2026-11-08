/*
 * Copyright (c) 2016, 2019, 2020-2026 Tracey Emery <tracey@openbsd.org>
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

#include "thingsd.h"

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

void	 client_write_to_things(struct packages *);

void
client_del(struct client *client)
{
	struct socket		*sock = client->sock;
	struct package		*package, *tpkg;

	TAILQ_REMOVE(sock->clients, client, entry);

	if (client->subscribed == 0)
		log_debug("%s: unsubscribed client disconnected (%d)", __func__,
		    client->fd);
	else
		log_debug("client disconnected: %s", client->name);

	if (evtimer_initialized(&client->timeout))
		evtimer_del(&client->timeout);

	if (client->bev != NULL)
		bufferevent_free(client->bev);

	if (client->tls) {
		tls_close(client->tls_ctx);
		tls_free(client->tls_ctx);
	}

	if (client->packages != NULL) {
		TAILQ_FOREACH_SAFE(package, client->packages, entry, tpkg) {
			TAILQ_REMOVE(client->packages, package, entry);
			free(package);
		}
		free(client->packages);
	}

	if (client->subscribed)
		sock->client_cnt--;

	close(client->fd);
	free(client);
}

void
client_rd(struct bufferevent *bev, void *arg)
{
	struct client		*client = (struct client *)arg;
	struct evbuffer		*evb = EVBUFFER_INPUT(bev);
	struct package		*package;
	size_t			 len, n;
	u_char			*pkt;

	len = EVBUFFER_LENGTH(evb);

	if (client->subscribed == 0) {
		log_debug("%s: client connection established (%d)", __func__,
		    client->fd);

		/* allow one shot at subscription so we don't get hammered */
		bufferevent_disable(client->bev, EV_READ);

		/* parse_buf() needs a NUL terminated buffer */
		if ((pkt = calloc(1, len + 1)) == NULL) {
			evbuffer_drain(evb, len);
			return;
		}
		evbuffer_remove(evb, pkt, len);

		if (len >= 3 && pkt[0] == 0x7E && pkt[1] == 0x7E &&
		    pkt[2] == 0x7E) {
			log_debug("%s: subscription packet received", __func__);
			parse_buf(client, pkt + 3);
			if (client->subscribed) {
				bufferevent_enable(client->bev,
				    EV_READ | EV_WRITE);
				if (evtimer_initialized(&client->timeout))
					evtimer_del(&client->timeout);
			}
		}
		free(pkt);
		return;
	}

	while ((len = EVBUFFER_LENGTH(evb)) > 0) {
		if ((package = calloc(1, sizeof(*package))) == NULL) {
			evbuffer_drain(evb, len);
			return;
		}
		n = MINIMUM(len, sizeof(package->pkt));
		evbuffer_remove(evb, package->pkt, n);
		package->thing_id = client->thing_id;
		package->len = n;
		TAILQ_INSERT_TAIL(thingsd_env->packages, package, entry);
	}
	client_write_to_things(thingsd_env->packages);
}

void
client_write_to_things(struct packages *packages)
{
	struct package		*package, *tpkg;

	TAILQ_FOREACH_SAFE(package, packages, entry, tpkg) {
		if (imsg_compose_event(socks_iev_parent,
		    IMSG_DIST_CLIENT_PACKAGE, 0, 0, -1, package,
		    sizeof(*package)) == -1) {
			log_warn("%s: failed to compose "
			    "IMSG_DIST_CLIENT_PACKAGE imsg", __func__);
			return;
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
