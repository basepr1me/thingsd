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
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "thingsd.h"

extern void		 bufferevent_read_pressure_cb(struct evbuffer *, size_t,
			    size_t, void *);

void
clt_conn(int fd, short event, void *arg)
{
	struct sockaddr_storage	 ss;
	struct clt		*clt;
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct sock		*sock = NULL;
	int			 clt_fd;
	socklen_t		 len = sizeof(ss);

	if ((clt_fd = accept4(fd, (struct sockaddr *)&ss, &len,
	    SOCK_NONBLOCK)) == -1) {
		log_warnx("clt accept failed");
		return;
	}
	if ((clt = calloc(1, sizeof(*clt))) == NULL)
		goto err;
	if ((clt->ev = calloc(1, sizeof(*clt->ev))) == NULL)
		goto err;
	if ((sock = get_sock(pthgsd, fd)) == NULL)
		goto err;
	if (sock->tls) {
		if (tls_accept_socket(sock->tls_ctx, &clt->tls_ctx, clt_fd)
		    == -1) {
			log_warnx("tls accept failed: %s",
			    tls_error(sock->tls_ctx));
			goto err;
		}
	}
	if ((clt->sub_names = (char **)malloc(pthgsd->max_sub *
	    sizeof(char *))) == NULL)
		fatalx("no client subscription names malloc");
	/*  check for unlimited clts */
	sock->clt_cnt++;
	pthgsd->clt_cnt++;
	if (sock->max_clts > 0 && sock->clt_cnt > sock->max_clts) {
		log_debug("%s: %s max clients reached", __func__, sock->name);
		sock->clt_cnt--;
		pthgsd->clt_cnt--;
		free(clt->sub_names);
		goto err;
	}
	clt->port = sock->port;
	clt->sock = sock;
	clt->subscribed = false;
	clt->evb = evbuffer_new();
	if (clt->evb == NULL) {
		sock->clt_cnt--;
		pthgsd->clt_cnt--;
		free(clt->sub_names);
		goto err;
	}
	clt->fd = clt_fd;
	clt->join_time = time(NULL);
	TAILQ_INSERT_TAIL(&pthgsd->clts, clt, entry);
	if (sock->tls) {
		clt->tls = true;
		event_del(clt->ev);
		event_set(clt->ev, clt->fd, EV_READ|EV_PERSIST,
		    sock_tls_handshake, pthgsd);
		if (event_add(clt->ev, NULL)) {
			free(clt->sub_names);
			goto err;
		}
		return;
	}
	clt_add(pthgsd, clt);
	return;
 err:
	log_debug("%s: client error", __func__);
	if (clt_fd != -1)
		close(clt_fd);
	if (sock->tls)
		tls_free(clt->tls_ctx);
	free(clt->ev);
	free(clt);
}

void
clt_add(struct thgsd *pthgsd, struct clt *pclt)
{
	struct clt		*clt = pclt;
	struct sock 		*sock = clt->sock;
	evbuffercb		 cltrd = clt_rd;
	evbuffercb		 cltwr = clt_wr;

	log_debug("%s: client connected, %d", __func__, clt->fd);
	clt->bev = bufferevent_new(clt->fd, cltrd, cltwr, clt_err, pthgsd);
	if (clt->bev == NULL) {
		sock->clt_cnt--;
		pthgsd->clt_cnt--;
		goto err;
	}
	if (clt->tls) {
		event_set(&clt->bev->ev_read, clt->fd, EV_READ,
		    clt_tls_readcb, clt->bev);
		event_set(&clt->bev->ev_write, clt->fd, EV_WRITE,
		    clt_tls_writecb, clt->bev);
	}
	bufferevent_setwatermark(clt->bev, EV_READ, 0, BUFF);
	bufferevent_enable(clt->bev, EV_READ);
	return;
 err:
	log_debug("%s: client error", __func__);
	if (clt->fd != -1)
		close(clt->fd);
	if (sock->tls)
		tls_free(clt->tls_ctx);
	free(clt->ev);
	free(clt);
}

void
clt_del(struct thgsd *pthgsd, struct clt *pclt)
{
	struct thg		*thg;
	struct clt		*clt, *tclt;
	size_t			 n;

	TAILQ_FOREACH_SAFE(clt, &pthgsd->clts, entry, tclt) {
		if (clt->fd == pclt->fd) {
			if (clt->tls)
				tls_free(clt->tls_ctx);
			for (n = 0; n < clt->le; n++)
				TAILQ_FOREACH(thg, &pthgsd->thgs, entry)
					if (strcmp(clt->sub_names[n],
					    thg->name) == 0)
						thg->clt_cnt--;
			pthgsd->clt_cnt--;
			clt->sock->clt_cnt--;
			if (clt->subscribed == false)
				log_debug("%s: client disconnected", __func__);
			else
				log_info("client disconnected: %s", clt->name);
			if (clt->bev != NULL)
				bufferevent_free(clt->bev);
			close(clt->fd);
			TAILQ_REMOVE(&pthgsd->clts, clt, entry);
			free(clt->ev);
			free(clt->sub_names);
			free(clt->name);
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
	if (clt->subscribed == false) {
		/* allow one shot at subscription so we don't get hammered */
		if ((pkt = calloc(len, sizeof(*pkt))) == NULL)
			return;
		if ((npkt = calloc(len, sizeof(*npkt))) == NULL)
			return;
		bufferevent_disable(clt->bev, EV_READ);
		evbuffer_remove(clt->evb, pkt, len);
		/* peak into packet and ensure it's a subscription packet */
		if (pkt[0] == 0x7E && pkt[1] == 0x7E && pkt[2] == 0x7E) {
			memmove(npkt, pkt+3, len-3);
			parse_buf(clt, npkt, len-3);
			if (clt->subscribed)
				bufferevent_enable(clt->bev, EV_READ|EV_WRITE);
		}
		free(pkt);
		free(npkt);
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
	}
}

void
clt_tls_readcb(int fd, short event, void *arg)
{
	struct bufferevent	*bufev = (struct bufferevent *)arg;
	struct thgsd		*pthgsd = bufev->cbarg;
	struct clt		*clt = NULL, *tclt;
	char			 pkt[BUFF];
	ssize_t			 ret;
	size_t			 len;
	int			 toread = EVBUFFER_READ;

	TAILQ_FOREACH(tclt, &pthgsd->clts, entry) {
		if (tclt->fd == fd)
			clt = tclt;
	}
	memset(pkt, 0, sizeof(pkt));
	ret = tls_read(clt->tls_ctx, pkt, BUFF);
	if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
		goto retry;
	} else if (ret < 0) {
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
				log_warnx("%s: temporary ipaddr connection"
				    " failed", __func__);
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
clt_tls_writecb(int fd, short event, void *arg)
{
	struct bufferevent	*bufev = (struct bufferevent *)arg;
	struct thgsd		*pthgsd = bufev->cbarg;
	struct clt		*clt = NULL, *tclt;
	ssize_t			 ret;
	size_t			 len;
	int			 towrite = EVBUFFER_WRITE;

	TAILQ_FOREACH(tclt, &pthgsd->clts, entry) {
		if (tclt->fd == fd)
			clt = tclt;
	}
	if (EVBUFFER_LENGTH(bufev->output)) {
		ret = tls_write(clt->tls_ctx,
		    EVBUFFER_DATA(bufev->output),
		    EVBUFFER_LENGTH(bufev->output));
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
			goto retry;
		} else if (ret < 0) {
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

void
clt_err(struct bufferevent *bev, short error, void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct clt		*clt;
	int			 fd = bev->ev_read.ev_fd;

	if ((error & EVBUFFER_EOF) == 0)
		log_warnx("%s: client socket error, disconnecting", __func__);
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
			if ((ctime - clt->join_time) >= CLT_SUB_TIME) {
				clt_del(pthgsd, clt);
				break;
			}
		}
	}
}

void
*clt_chk(void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	void			(*tfptr)(struct thgsd *);

	tfptr = pthgsd->clt_fptr;
	while(1) {
		sleep(CLT_SUB_CHK);
		(void)(*tfptr)(pthgsd);
	}
	pthread_exit(NULL);
}

void
start_clt_chk(struct thgsd *pthgsd)
{
	pthread_t		 tclt_chk;
	int			 rclt_chk;

	rclt_chk = pthread_create(&tclt_chk, NULL, clt_chk, (void *)pthgsd);
	if (rclt_chk) {
		log_warnx("%s: thread creation failed", __func__);
		clt_chk((void *) pthgsd);
	}
}
