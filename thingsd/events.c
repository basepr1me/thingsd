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
#include <stdbool.h>
#include <string.h>

#include "thingsd.h"

void
udp_evt(int fd, short event, void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct thg		*thg = NULL, *tthg;
	struct clt		*clt;
	char			 pkt[BUFF];
	int			 len;
	size_t			 n;
	socklen_t		*addrlen = NULL;
	struct sockaddr		*addr = NULL;

	memset(pkt, 0, sizeof(pkt));
	TAILQ_FOREACH(tthg, &pthgsd->thgs, entry) {
		if (tthg->fd == fd) {
			thg = tthg;
			break;
		}
	}
	len = recvfrom(fd, pkt, sizeof(pkt), 0, addr, addrlen);
	if (len > 0) {
		/*  write to clients */
		TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
			for (n = 0; n < clt->le; n++) {
				if (strcmp(clt->sub_names[n], thg->name) == 0)
					bufferevent_write(clt->bev, pkt, len);
			}
		}
	}
}
