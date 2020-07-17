/*
 * Copyright (c) 2016, 2019, 2020 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
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

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>
#include <util.h>

#include "proc.h"
#include "thingsd.h"

int things_dispatch_parent(int, struct privsep_proc *, struct imsg *);
void things_run(struct privsep *, struct privsep_proc *, void *);
void things_show_info(struct privsep *, struct imsg *);

struct thing compose_thing(struct thing *, enum imsg_type);

static struct privsep_proc procs[] = {
	{ "parent",	PROC_PARENT,	things_dispatch_parent  },
};

void
things(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), things_run, NULL);
}

void
things_run(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	if (config_init(ps->ps_env) == -1)
		fatal("failed to initialize configuration");

	signal_del(&ps->ps_evsigchld);
	signal_set(&ps->ps_evsigchld, SIGCHLD, things_sighdlr, ps);
	signal_add(&ps->ps_evsigchld, NULL);

	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");
}

int
things_dispatch_parent(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep		*ps = p->p_ps;
	struct thing		*thing, nei;
	int			 res = 0, cmd = 0, verbose;
	unsigned int		 mode;
	size_t			 n;

	switch (imsg->hdr.type) {
	case IMSG_ADD_THING:
		IMSG_SIZE_CHECK(imsg, &nei);

		memcpy(&nei, imsg->data, sizeof(nei));

		thing = calloc(1, sizeof(*thing));

		thing->exists = nei.exists;
		thing->hw_ctl = nei.hw_ctl;
		thing->persist = nei.persist;

		n = strlcpy(thing->iface, nei.iface, sizeof(thing->iface));
		if (n >= sizeof(thing->iface))
			fatalx("%s: thing->iface too long", __func__);

		n = strlcpy(thing->ipaddr, nei.ipaddr, sizeof(thing->ipaddr));
		if (n >= sizeof(thing->ipaddr))
			fatalx("%s: thing->ipaddr too long", __func__);

		n = strlcpy(thing->parity, nei.parity, sizeof(thing->parity));
		if (n >= sizeof(thing->parity))
			fatalx("%s: thing->parity name too long", __func__);

		n = strlcpy(thing->name, nei.name, sizeof(thing->name));
		if (n >= sizeof(thing->name))
			fatalx("%s: thing->name too long", __func__);

		n = strlcpy(thing->password, nei.password,
		    sizeof(thing->password));
		if (n >= sizeof(thing->password))
			fatalx("%s: thing->password too long", __func__);

		n = strlcpy(thing->location, nei.location,
		    sizeof(thing->location));
		if (n >= sizeof(thing->location))
			fatalx("%s: thing->location too long", __func__);

		n = strlcpy(thing->udp, nei.udp, sizeof(thing->udp));
		if (n >= sizeof(thing->udp))
			fatalx("%s: thing->name too long", __func__);

		thing->fd = nei.fd;
		thing->baud = nei.baud;
		thing->conn_port = nei.conn_port;
		thing->rcv_port = nei.rcv_port;
		thing->data_bits = nei.data_bits;
		thing->max_clients = nei.max_clients;
		thing->port = nei.port;
		thing->stop_bits = nei.stop_bits;
		thing->type = nei.type;
		thing->client_cnt = nei.client_cnt;

		thing->tls = nei.tls;
		n = strlcpy(thing->tls_cert_file, nei.tls_cert_file,
		    sizeof(thing->tls_cert_file));
		if (n >= sizeof(thing->tls_cert_file))
			fatalx("%s: thing->tls_cert_file too long", __func__);

		n = strlcpy(thing->tls_key_file, nei.tls_key_file,
		    sizeof(thing->tls_key_file));
		if (n >= sizeof(thing->tls_key_file))
			fatalx("%s: thing->tls_key_file too long", __func__);

		n = strlcpy(thing->tls_ca_file, nei.tls_ca_file,
		    sizeof(thing->tls_ca_file));
		if (n >= sizeof(thing->tls_ca_file))
			fatalx("%s: thing->tls_ca_file too long", __func__);

		n = strlcpy(thing->tls_crl_file, nei.tls_crl_file,
		    sizeof(thing->tls_crl_file));
		if (n >= sizeof(thing->tls_crl_file))
			fatalx("%s: thing->tls_crl_file too long", __func__);

		n = strlcpy(thing->tls_ocsp_staple_file,
		    nei.tls_ocsp_staple_file,
		    sizeof(thing->tls_ocsp_staple_file));
		if (n >= sizeof(thing->tls_ocsp_staple_file))
			fatalx("%s: thing->tls_ocsp_staple_file too long",
			    __func__);

		TAILQ_INSERT_TAIL(thingsd_env->things, thing, entry);

		break;
	case IMSG_GET_INFO_THINGS_REQUEST:
	case IMSG_GET_INFO_THINGS_REQUEST_ROOT:
		things_show_info(ps, imsg);
		cmd = IMSG_GET_INFO_THINGS_END_DATA;
		break;
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &mode);
		memcpy(&mode, imsg->data, sizeof(mode));

		config_getreset(thingsd_env, imsg);
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		break;
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	case IMSG_GET_INFO_THINGS_END_DATA:
		if (proc_compose_imsg(ps, PROC_PARENT, -1, cmd,
		    imsg->hdr.peerid, -1, &mode, sizeof(mode)) == -1)
			return (-1);
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
things_sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	default:
		fatalx("unexpected signal");
	}
}

void
things_reset(void)
{
	struct thing		*thing, *tthing;
	struct socket		*sock, *tsock;
	struct client		*client, *tclient;

	/* clean up clients */
	TAILQ_FOREACH_SAFE(client, thingsd_env->clients, entry, tclient) {
		close(client->fd);
		TAILQ_REMOVE(thingsd_env->clients, client, entry);
	}

	/* clean up sockets */
	TAILQ_FOREACH_SAFE(sock, thingsd_env->sockets, entry, tsock) {
		if (sock->tls) {
			tls_config_free(sock->tls_config);
			tls_free(sock->tls_ctx);
		}
		close(sock->fd);
		TAILQ_REMOVE(thingsd_env->sockets, sock, entry);
	}

	/* clean up things */
	TAILQ_FOREACH_SAFE(thing, thingsd_env->things, entry, tthing) {
		close(thing->fd);
		TAILQ_REMOVE(thingsd_env->things, thing, entry);
	}

}

void
things_shutdown(void)
{
	struct thing		*thing, *tthing;
	struct socket		*sock, *tsock;
	struct client		*client, *tclient;
	struct dead_thing	*dead_thing, *dead_tthing;

	/* clean up things */
	TAILQ_FOREACH_SAFE(thing, thingsd_env->things, entry, tthing) {
		close(thing->fd);
		TAILQ_REMOVE(thingsd_env->things, thing, entry);
		free(thing);
	}

	/* clean up dead things */
	TAILQ_FOREACH_SAFE(dead_thing,
	    thingsd_env->dead_things->dead_things_list, entry, dead_tthing) {
		TAILQ_REMOVE(thingsd_env->dead_things->dead_things_list,
		    dead_thing, entry);
		free(dead_thing);
	}

	/* clean up sockets */
	TAILQ_FOREACH_SAFE(sock, thingsd_env->sockets, entry, tsock) {
		if (sock->tls) {
			tls_config_free(sock->tls_config);
			tls_free(sock->tls_ctx);
		}
		close(sock->fd);
		free(sock->ev);
		TAILQ_REMOVE(thingsd_env->sockets, sock, entry);
		free(sock);
	}

	/* clean up clients */
	TAILQ_FOREACH_SAFE(client, thingsd_env->clients, entry, tclient) {
		close(client->fd);
		free(client->sub_names);
		TAILQ_REMOVE(thingsd_env->clients, client, entry);
		free(client);
	}
}

void
things_show_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[THINGSD_MAXTHINGNAME];
	struct thing *thing, nei;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_THINGS_REQUEST:
	case IMSG_GET_INFO_THINGS_REQUEST_ROOT:

		memcpy(filter, imsg->data, sizeof(filter));

		TAILQ_FOREACH(thing, thingsd_env->things, entry) {
			if (filter[0] == '\0' || memcmp(filter,
			    thing->name, sizeof(filter)) == 0) {
				nei = compose_thing(thing, imsg->hdr.type);

				if (proc_compose_imsg(ps, PROC_PARENT, -1,
				    IMSG_GET_INFO_THINGS_DATA,
				    imsg->hdr.peerid, -1, &nei,
				    sizeof(nei)) == -1)
					return;

			}
		}

		if (proc_compose_imsg(ps, PROC_PARENT, -1,
		    IMSG_GET_INFO_THINGS_END_DATA, imsg->hdr.peerid,
			    -1, &nei, sizeof(nei)) == -1)
				return;

		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}

struct thing
compose_thing(struct thing *thing, enum imsg_type type)
{
	struct thing		 nei;
	char			 blank[9] = "********";
	size_t			 n;

	memset(&nei, 0, sizeof(nei));
	nei.exists = thing->exists;
	nei.hw_ctl = thing->hw_ctl;
	nei.persist = thing->persist;

	n = strlcpy(nei.iface, thing->iface, sizeof(nei.iface));
	if (n >= sizeof(nei.iface))
		fatalx("%s: nei.iface too long", __func__);

	n = strlcpy(nei.ipaddr, thing->ipaddr, sizeof(nei.ipaddr));
	if (n >= sizeof(nei.ipaddr))
		fatalx("%s: nei.ipaddr too long", __func__);

	n = strlcpy(nei.parity, thing->parity, sizeof(nei.parity));
	if (n >= sizeof(nei.parity))
		fatalx("%s: nei.parity too long", __func__);

	n = strlcpy(nei.name, thing->name, sizeof(nei.name));
	if (n >= sizeof(nei.name))
		fatalx("%s: nei.name too long", __func__);

	nei.password[0] = '\0';
	if (type == IMSG_GET_INFO_THINGS_REQUEST)
		n = strlcpy(nei.password, blank, sizeof(nei.password));
	else
		n = strlcpy(nei.password, thing->password,
		    sizeof(nei.password));
	if (n >= sizeof(nei.password))
		fatalx("%s: nei.password too long", __func__);

	n = strlcpy(nei.location, thing->location, sizeof(nei.location));
	if (n >= sizeof(nei.location))
		fatalx("%s: nei.location too long", __func__);

	n = strlcpy(nei.udp, thing->udp, sizeof(nei.udp));
	if (n >= sizeof(nei.udp))
		fatalx("%s: nei.udp too long", __func__);

	nei.fd = thing->fd;
	nei.baud = thing->baud;
	nei.conn_port = thing->conn_port;
	nei.rcv_port = thing->rcv_port;
	nei.data_bits = thing->data_bits;
	nei.max_clients = thing->max_clients;
	nei.port = thing->port;
	nei.stop_bits = thing->stop_bits;
	nei.type = thing->type;
	nei.client_cnt = thing->client_cnt;

	nei.tls = thing->tls;
	n = strlcpy(nei.tls_cert_file, thing->tls_cert_file,
	    sizeof(nei.tls_cert_file));
	if (n >= sizeof(nei.tls_cert_file))
		fatalx("%s: nei.tls_cert_file too long", __func__);

	n = strlcpy(nei.tls_key_file, thing->tls_key_file,
	    sizeof(nei.tls_key_file));
	if (n >= sizeof(nei.tls_key_file))
		fatalx("%s: nei.tls_key_file too long", __func__);

	n = strlcpy(nei.tls_ca_file, thing->tls_ca_file,
	    sizeof(nei.tls_ca_file));
	if (n >= sizeof(nei.tls_ca_file))
		fatalx("%s: nei.tls_ca_file too long", __func__);

	n = strlcpy(nei.tls_crl_file, thing->tls_crl_file,
	    sizeof(nei.tls_crl_file));
	if (n >= sizeof(nei.tls_crl_file))
		fatalx("%s: nei.tls_crl_file too long", __func__);

	n = strlcpy(nei.tls_ocsp_staple_file, thing->tls_ocsp_staple_file,
	    sizeof(nei.tls_ocsp_staple_file));
	if (n >= sizeof(nei.tls_ocsp_staple_file))
		fatalx("%s: nei.tls_ocsp_staple_file too long", __func__);

	return nei;
}

void
add_reconn(struct thing *thing)
{
	struct dead_thing	*dead_thing;

	dead_thing = new_dead_thing(thing);

	thingsd_env->exists = true;
	thingsd_env->dcount++;

	TAILQ_INSERT_TAIL(thingsd_env->dead_things->dead_things_list,
	    dead_thing, entry);

}

struct dead_thing
*new_dead_thing(struct thing *thing)
{
	struct dead_thing	*dead_thing;
	size_t			 n;

	if ((dead_thing = calloc(1, sizeof(*dead_thing))) == NULL)
		fatalx("no calloc dead_thing");

	log_debug("%s: adding detached thing, %s", __func__, thing->name);

	n = strlcpy(dead_thing->name, thing->name, sizeof(dead_thing->name));
	if (n >= sizeof(dead_thing->name))
		fatalx("%s: dead_thing->name too long", __func__);

	dead_thing->type = thing->type;
	dead_thing->dtime = time(NULL);

	return dead_thing;
}

void
do_reconn(void)
{
	struct dead_thing	*dead_thing, *tdead_thing;
	struct thing		*thing;

	TAILQ_FOREACH_SAFE(dead_thing,
	    thingsd_env->dead_things->dead_things_list, entry, tdead_thing) {
		if ((size_t)(time(NULL) - dead_thing->dtime) >
		    thingsd_env->conn_retry) {
			dead_thing->dtime = time(NULL);

			log_info("attempting to reconnect %s",
			    dead_thing->name);

			switch (dead_thing->type) {
			case DEV:
				open_things(thingsd_env, true);
				break;
			case TCP:
				create_sockets(thingsd_env, true);
				break;
			}
		}
	}

	TAILQ_FOREACH_SAFE(dead_thing,
	    thingsd_env->dead_things->dead_things_list, entry, tdead_thing) {
		TAILQ_FOREACH(thing, thingsd_env->things, entry) {
			if (strcmp(thing->name, dead_thing->name) == 0 &&
			    thing->exists) {
				TAILQ_REMOVE(thingsd_env->dead_things->
				    dead_things_list,
				    dead_thing, entry);
				thingsd_env->dcount--;

				free(dead_thing);

				return;
			}
		}
	}

	if (thingsd_env->dcount == 0)
		thingsd_env->exists = false;
}
