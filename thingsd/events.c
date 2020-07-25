/*
 * Copyright (c) 2019 Tracey Emery <tracey@traceyemery.net>
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

#include <event.h>
#include <imsg.h>
#include <stdbool.h>
#include <string.h>

#include "proc.h"
#include "thingsd.h"

void
udp_event(int fd, short event, void *arg)
{
	struct thingsd		*env = (struct thingsd *)arg;
	struct thing		*thing = NULL, *tthing;
	struct client		*client;
	char			 pkt[PKT_BUFF];
	int			 len, snm;
	size_t			 n;
	socklen_t		*addrlen = NULL;
	struct sockaddr		*addr = NULL;

	memset(pkt, 0, sizeof(pkt));

	TAILQ_FOREACH(tthing, env->things, entry) {
		if (tthing->fd == fd) {
			thing = tthing;
			break;
		}
	}

	len = recvfrom(fd, pkt, sizeof(pkt), 0, addr, addrlen);

	if (len > 0) {
		/*  write to clients */
		TAILQ_FOREACH(client, env->clients, entry) {
			for (n = 0; n < client->le; n++) {
				if (strcmp(client->sub_names[n],
				    thing->name) == 0)
					bufferevent_write(client->bev, pkt,
					    len);
			}
		}

		if (env->control_pkt.exists) {
			if (strlen(env->control_pkt.name) != 0)
				if ((snm = strcmp(thing->name,
				    env->control_pkt.name)) == 0)
					send_control_pkt(
					    &env->control_pkt.ps,
					    &env->control_pkt.imsg,
					    thing->name, pkt, len);
		}

	}
}
