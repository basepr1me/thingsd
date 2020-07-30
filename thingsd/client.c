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
#include <imsg.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "proc.h"
#include "thingsd.h"

void bufferevent_read_pressure_cb(struct evbuffer *, size_t, size_t, void *);

void
client_conn(int fd, short event, void *arg)
{
	struct sockaddr_storage	 ss;
	struct client		*client;
	struct thingsd		*env = (struct thingsd *)arg;
	struct socket		*sock = NULL;
	int			 client_fd;
	socklen_t		 len = sizeof(ss);

	if ((client_fd = accept4(fd, (struct sockaddr *)&ss, &len,
	    SOCK_NONBLOCK)) == -1) {
		log_warnx("client accept failed");
		return;
	}

	if ((client = calloc(1, sizeof(*client))) == NULL)
		goto err;

	if ((client->ev = calloc(1, sizeof(*client->ev))) == NULL)
		goto err;

	if ((sock = get_socket(env, fd)) == NULL)
		goto err;

	if (sock->tls) {
		if (tls_accept_socket(sock->tls_ctx, &client->tls_ctx,
		    client_fd) == -1) {
			log_warnx("tls accept failed: %s",
			    tls_error(sock->tls_ctx));
			goto err;
		}
	}

	*client->sub_names = (char *) calloc(env->max_subs,
	    sizeof(client->sub_names));
	if (*client->sub_names == NULL)
		goto err;

	/*  check for unlimited clients */
	sock->client_cnt++;
	env->client_cnt++;
	if (sock->max_clients > 0 && sock->client_cnt > sock->max_clients) {
		log_debug("%s: %s max clients reached", __func__, sock->name);
		sock->client_cnt--;
		env->client_cnt--;
		free(*client->sub_names);
		goto err;
	}

	client->port = sock->port;
	client->socket = sock;
	client->subscribed = false;
	client->evb = evbuffer_new();

	if (client->evb == NULL) {
		sock->client_cnt--;
		env->client_cnt--;
		free(*client->sub_names);
		goto err;
	}

	client->fd = client_fd;
	client->join_time = time(NULL);

	TAILQ_INSERT_TAIL(env->clients, client, entry);
	if (sock->tls) {
		client->tls = true;
		event_del(client->ev);
		event_set(client->ev, client->fd, EV_READ | EV_PERSIST,
		    socket_tls_handshake, env);
		if (event_add(client->ev, NULL)) {
			free(*client->sub_names);
			goto err;
		}
		return;
	}

	client_add(env, client);

	return;
err:
	log_debug("%s: client error", __func__);
	if (client_fd != -1)
		close(client_fd);
	if (sock->tls)
		tls_free(client->tls_ctx);
	free(client->ev);
	free(client);
}

void
client_add(struct thingsd *env, struct client *client)
{
	struct socket 		*sock = client->socket;
	evbuffercb		 clientrd = client_rd;
	evbuffercb		 clientwr = client_wr;

	log_debug("%s: client connected, %d", __func__, client->fd);

	client->bev = bufferevent_new(client->fd, clientrd, clientwr,
	    client_err, env);

	if (client->bev == NULL) {
		sock->client_cnt--;
		env->client_cnt--;
		goto err;
	}

	if (client->tls) {
		event_set(&client->bev->ev_read, client->fd, EV_READ,
		    client_tls_readcb, client->bev);
		event_set(&client->bev->ev_write, client->fd, EV_WRITE,
		    client_tls_writecb, client->bev);
	}

	bufferevent_setwatermark(client->bev, EV_READ, 0, PKT_BUFF);
	bufferevent_enable(client->bev, EV_READ);

	return;
err:
	log_debug("%s: client error", __func__);
	if (client->fd != -1)
		close(client->fd);
	if (sock->tls)
		tls_free(client->tls_ctx);
	free(client->ev);
	free(client);
}

void
client_del(struct thingsd *env, struct client *client)
{
	struct thing		*thing;
	struct client		*pclient, *tclient;
	size_t			 n;

	TAILQ_FOREACH_SAFE(pclient, env->clients, entry, tclient) {
		if (pclient->fd == client->fd) {
			if (pclient->tls)
				tls_free(pclient->tls_ctx);

			for (n = 0; n < pclient->le; n++)
				TAILQ_FOREACH(thing, env->things, entry)
					if (strcmp(pclient->sub_names[n],
					    thing->name) == 0)
						thing->client_cnt--;

			env->client_cnt--;
			pclient->socket->client_cnt--;

			if (pclient->subscribed == false)
				log_debug("%s: client disconnected", __func__);
			else
				log_info("client disconnected: %s",
				    pclient->name);

			if (pclient->bev != NULL)
				bufferevent_free(pclient->bev);

			close(pclient->fd);
			TAILQ_REMOVE(env->clients, pclient, entry);
			free(pclient->ev);
			free(*pclient->sub_names);
			free(pclient);
			break;
		}
	}
}

void
client_rd(struct bufferevent *bev, void *arg)
{
	struct thingsd		*env = (struct thingsd *)arg;
	struct thing		*thing = NULL;
	struct client		*client = NULL, *tclient;
	size_t			 len, n;
	int			 fd = bev->ev_read.ev_fd;
	char			*pkt = NULL, *npkt = NULL;

	TAILQ_FOREACH(tclient, env->clients, entry) {
		if (tclient->fd == fd) {
			client = tclient;
			if (client == NULL)
				return;
			break;
		}
	}

	client->evb = EVBUFFER_INPUT(bev);
	len = EVBUFFER_LENGTH(client->evb);

	if (client->subscribed == false) {
		/* allow one shot at subscription so we don't get hammered */
		if ((pkt = calloc(len, sizeof(*pkt))) == NULL)
			return;

		if ((npkt = calloc(len, sizeof(*npkt))) == NULL)
			return;

		bufferevent_disable(client->bev, EV_READ);
		evbuffer_remove(client->evb, pkt, len);

		/* peak into packet and ensure it's a subscription packet */
		if (pkt[0] == 0x7E && pkt[1] == 0x7E && pkt[2] == 0x7E) {
			memmove(npkt, pkt+3, len-3);
			parse_buf(client, npkt, len-3);
			if (client->subscribed)
				bufferevent_enable(client->bev,
				    EV_READ | EV_WRITE);
		}
	} else if (client->subscribed) {
		/* write to things */
		for (n = 0; n < client->le; n++) {
			TAILQ_FOREACH(thing, env->things, entry) {
				if (strcmp(client->sub_names[n],
				    thing->name) == 0 &&
				    client->port == thing->port) {

					if (thing->exists)
						client_wr_things(client, thing,
						    len);
					else
						evbuffer_drain(client->evb,
						    len);

				}
			}
		}
	}
	free(pkt);
	free(npkt);
}

void
client_tls_readcb(int fd, short event, void *arg)
{
	struct bufferevent	*bufev = (struct bufferevent *)arg;
	struct thingsd		*env = bufev->cbarg;
	struct client		*client = NULL, *tclient;
	char			 pkt[PKT_BUFF];
	ssize_t			 ret;
	size_t			 len;
	int			 toread = EVBUFFER_READ;

	TAILQ_FOREACH(tclient, env->clients, entry) {
		if (tclient->fd == fd)
			client = tclient;
	}

	memset(pkt, 0, sizeof(pkt));

	ret = tls_read(client->tls_ctx, pkt, PKT_BUFF);
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
client_wr_things(struct client *client, struct thing *thing, size_t len)
{
	char			*pkt;

	if ((pkt = calloc(len, sizeof(*pkt))) == NULL)
		return;

	switch (thing->type) {
	case TCP:
	case DEV:
		if (thing->persist == false) {
			if ((thing->fd = open_client_socket(thing->ipaddr,
			    thing->conn_port)) == -1) {
				log_warnx("%s: temporary ipaddr connection"
				    " failed", __func__);
				return;
			}

			evbuffer_remove(client->evb, pkt, len);
			write(thing->fd, pkt, len);
			close(thing->fd);
			thing->fd = -1;
		} else {
			if (thing->fd != -1) {
				bufferevent_write_buffer(thing->bev,
				    client->evb);
				evbuffer_drain(client->evb, len);
			}
		}
		free(pkt);
		break;
	default:
		evbuffer_remove(client->evb, pkt, len);
		write(thing->fd, pkt, len);
		free(pkt);
		break;
	}
}

void
client_wr(struct bufferevent *bev, void *arg)
{
}

void
client_tls_writecb(int fd, short event, void *arg)
{
	struct bufferevent	*bufev = (struct bufferevent *)arg;
	struct thingsd		*env = bufev->cbarg;
	struct client		*client = NULL, *tclient;
	ssize_t			 ret;
	size_t			 len;
	int			 towrite = EVBUFFER_WRITE;

	TAILQ_FOREACH(tclient, env->clients, entry) {
		if (tclient->fd == fd)
			client = tclient;
	}

	if (EVBUFFER_LENGTH(bufev->output)) {
		ret = tls_write(client->tls_ctx,
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
client_err(struct bufferevent *bev, short error, void *arg)
{
	struct thingsd		*env = (struct thingsd *)arg;
	struct client		*client;
	int			 fd = bev->ev_read.ev_fd;

	if ((error & EVBUFFER_EOF) == 0)
		log_warnx("%s: client socket error, disconnecting", __func__);

	/* client disconnect */
	TAILQ_FOREACH(client, env->clients, entry) {
		if (client->fd == fd) {
			client_del(env, client);
			break;
		}
	}
}

void
client_do_chk(struct thingsd *env)
{
	struct client		*client;
	time_t			 ctime = time(NULL);

	TAILQ_FOREACH(client, env->clients, entry) {
		if (client->subscribed == false) {
			if ((ctime - client->join_time) >= CLIENT_SUB_TIME) {
				client_del(env, client);
				break;
			}
		}
	}
}

void
*client_chk(void *arg)
{
	struct thingsd		*env = (struct thingsd *)arg;
	void			(*tfptr)(struct thingsd *);

	tfptr = env->client_fptr;
	while(1) {
		sleep(CLIENT_SUB_CHK);
		(void)(*tfptr)(env);
	}
	pthread_exit(NULL);
}

void
start_client_chk(struct thingsd *env)
{
	pthread_t		 tclient_chk;
	int			 rclient_chk;

	rclient_chk = pthread_create(&tclient_chk, NULL, client_chk,
	    (void *)env);

	if (rclient_chk) {
		log_warnx("%s: thread creation failed", __func__);
		client_chk((void *) env);
	}
}

void
clients_show_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[THINGSD_MAXNAME];
	struct client	*client, nci;
	size_t		 n;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_CLIENTS_REQUEST:

		memcpy(filter, imsg->data, sizeof(filter));

		TAILQ_FOREACH(client, thingsd_env->clients, entry) {
			if (filter[0] == '\0' || memcmp(filter,
			    client->name, sizeof(filter)) == 0) {

				n = strlcpy(nci.name, client->name,
				    sizeof(nci.name));
				if (n >= sizeof(nci.name))
					fatalx("%s: nci.name too long",
					    __func__);

				nci.subscribed = client->subscribed;
				nci.fd = client->fd;
				nci.port = client->port;
				nci.tls = client->tls;
				nci.subs = client->subs;

				if (proc_compose_imsg(ps, PROC_CONTROL, -1,
				    IMSG_GET_INFO_CLIENTS_DATA,
				    imsg->hdr.peerid, -1, &nci,
				    sizeof(nci)) == -1)
					return;

			}
		}

		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_GET_INFO_CLIENTS_END_DATA, imsg->hdr.peerid,
			    -1, &nci, sizeof(nci)) == -1)
				return;

		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}
