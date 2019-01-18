/*
 * Copyright (c) 2016-2019 Tracey Emery <tracey@traceyemery.net>
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
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "thingsd.h"

void
clt_conn(int fd, short event, void *arg)
{
	struct sockaddr_storage	 ss;
	struct clt		*clt;
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct sock		*sock = NULL;
	evbuffercb		 cltrd = clt_rd;
	evbuffercb		 cltwr = clt_wr;
	int			 clt_fd;
	socklen_t		 len = sizeof(ss);

	if ((clt_fd = accept4(fd, (struct sockaddr *)&ss, &len,
	    SOCK_NONBLOCK)) == -1) {
		log_info("clt accept failed");
		return;
	}
	if ((clt = calloc(1, sizeof(*clt))) == NULL)
		goto err;
	if ((sock = get_sock(pthgsd, fd)) == NULL)
		goto err;
	if ((clt->sub_names = (char **)malloc(pthgsd->max_sub *
	    sizeof(char *))) == NULL)
		fatalx("no client subscription names malloc");
	/*  check for unlimited clts */
	sock->clt_cnt++;
	pthgsd->clt_cnt++;
	if (sock->max_clts > 0 && sock->clt_cnt > sock->max_clts) {
		log_info("%s max clients reached", sock->name);
		sock->clt_cnt--;
		pthgsd->clt_cnt--;
		goto err;
	}
	clt->port = sock->port;
	clt->sock = sock;
	clt->subscribed = false;
	clt->evb = evbuffer_new();
	if (clt->evb == NULL)
		goto err;
	clt->fd = clt_fd;
	clt->bev = bufferevent_new(clt->fd, cltrd, cltwr, clt_err, pthgsd);
	if (clt->bev == NULL)
		goto err;
	bufferevent_base_set(pthgsd->eb, clt->bev);
	bufferevent_setwatermark(clt->bev, EV_READ, 0, BUFF);
	bufferevent_enable(clt->bev, EV_READ);
	clt->join_time = time(NULL);
	log_info("client connected");
	start_clt_chk(pthgsd);
	TAILQ_INSERT_TAIL(&pthgsd->clts, clt, entry);
	return;
 err:
	log_info("client error");
	sock->clt_cnt--;
	pthgsd->clt_cnt--;
	if (clt_fd != -1) {
		close(clt_fd);
		free(clt);
	}
}

void
clt_del(struct thgsd *pthgsd, struct clt *pclt)
{
	struct thg		*thg;
	struct clt		*clt, *tclt;
	size_t			 n;

	TAILQ_FOREACH_SAFE(clt, &pthgsd->clts, entry, tclt) {
		if (clt == pclt) {
			if (clt->bev != NULL)
				bufferevent_free(clt->bev);
			close(clt->fd);
			for (n = 0; n < clt->le; n++)
				TAILQ_FOREACH(thg, &pthgsd->thgs, entry)
					if (strcmp(clt->sub_names[n],
					    thg->name) == 0)
						thg->clt_cnt--;
			pthgsd->clt_cnt--;
			clt->sock->clt_cnt--;
			if (clt->subscribed == false)
				log_info("client disconnected");
			else
				log_info("client disconnected: %s", clt->name);
			TAILQ_REMOVE(&pthgsd->clts, clt, entry);
			free(clt);
			break;
		}
	}
}

void
clt_rd(struct bufferevent *bev, void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct thg		*thg = NULL;
	struct clt		*clt = NULL, *tclt;
	size_t			 len, n;
	int			 fd = bev->ev_read.ev_fd;
	char			*pkt, *npkt;

	TAILQ_FOREACH(tclt, &pthgsd->clts, entry) {
		if (tclt->fd == fd) {
			clt = tclt;
			if (clt == NULL)
				return;
			break;
		}
	}
	clt->evb = EVBUFFER_INPUT(bev);
	len = EVBUFFER_LENGTH(clt->evb);
	if ((pkt = calloc(len, sizeof(*pkt))) == NULL)
		return;
	if (clt->subscribed == false) {
		/* allow one shot at subscription so we don't get hammered */
		bufferevent_disable(clt->bev, EV_READ);
		evbuffer_remove(clt->evb, pkt, len);
		/* peak into packet and ensure it's a subscription packet */
		if (pkt[0] == 0x7E && pkt[1] == 0x7E && pkt[2] == 0x7E) {
			if ((npkt = calloc(len, sizeof(*npkt))) == NULL)
				return;
			memmove(npkt, pkt+3, len-3);
			parse_buf(clt, npkt, len-3);
			free(pkt);
			free(npkt);
			if (clt->subscribed)
				bufferevent_enable(clt->bev, EV_READ|EV_WRITE);
		}
	} else if (clt->subscribed) {
		/* write to thgs */
		for (n = 0; n < clt->le; n++) {
			TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
				if (strcmp(clt->sub_names[n], thg->name) == 0 &&
				    clt->port == thg->port) {
					if (thg->exists)
						clt_wr_thgs(clt, thg, len);
					else
						evbuffer_drain(clt->evb, len);
				}
			}
		}
		free(pkt);
	}
}

void
clt_wr_thgs(struct clt *clt, struct thg *thg, size_t len)
{
	char			*pkt;

	if ((pkt = calloc(len, sizeof(*pkt))) == NULL)
		return;
	switch (thg->type) {
	case TCP:
	case DEV:
		if (thg->persist == false) {
			if ((thg->fd = open_clt_sock(thg->ipaddr,
			    thg->conn_port)) == -1) {
				log_info("temporary ipaddr connection failed");
				return;
			}
			evbuffer_remove(clt->evb, pkt, len);
			write(thg->fd, pkt, len);
			close(thg->fd);
			thg->fd = -1;
		} else {
			if (thg->fd != -1) {
				bufferevent_write_buffer(thg->bev, clt->evb);
				evbuffer_drain(clt->evb, len);
			}
		}
		free(pkt);
		break;
	default:
		evbuffer_remove(clt->evb, pkt, len);
		write(thg->fd, pkt, len);
		free(pkt);
		break;
	}
}

void
clt_wr(struct bufferevent *bev, void *arg)
{
}

void
clt_err(struct bufferevent *bev, short error, void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct clt		*clt;
	int			 fd = bev->ev_read.ev_fd;

	if ((error & EVBUFFER_EOF) == 0)
		log_info("client socket error, disconnecting");
	/* client disconnect */
	TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
		if (clt->fd == fd) {
			clt_del(pthgsd, clt);
			break;
		}
	}
}

void
clt_do_chk(struct thgsd *pthgsd)
{
	struct clt		*clt;
	time_t			 ctime = time(NULL);

	TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
		if (clt->subscribed == false) {
			if ((ctime - clt->join_time) >= CLT_SUB_TIME)
				clt_del(pthgsd, clt);
			break;
		}
	}
}

void
*clt_chk(void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	void			 (*tfptr)(struct thgsd *);

	tfptr = pthgsd->clt_fptr;
	sleep(CLT_SUB_TIME);
	(void)(*tfptr)(pthgsd);
	return NULL;
}

void
start_clt_chk(struct thgsd *pthgsd)
{
	pthread_t		 tclt_chk;
	int			 rclt_chk;

	rclt_chk = pthread_create(&tclt_chk, NULL, clt_chk, (void *)pthgsd);
	if (rclt_chk) {
		log_info("thread creation failed");
		clt_chk((void *) pthgsd);
	}
}
