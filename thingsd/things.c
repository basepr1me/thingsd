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
	struct thing		*thing, nti;
	int			 res = 0, cmd = 0, verbose;
	unsigned int		 mode;
	size_t			 n;

	switch (imsg->hdr.type) {
	case IMSG_ADD_THING:
		IMSG_SIZE_CHECK(imsg, &nti);

		memcpy(&nti, imsg->data, sizeof(nti));

		thing = calloc(1, sizeof(*thing));

		thing->exists = nti.exists;
		thing->hw_ctl = nti.hw_ctl;
		thing->persist = nti.persist;

		n = strlcpy(thing->iface, nti.iface, sizeof(thing->iface));
		if (n >= sizeof(thing->iface))
			fatalx("%s: thing->iface too long", __func__);

		n = strlcpy(thing->ipaddr, nti.ipaddr, sizeof(thing->ipaddr));
		if (n >= sizeof(thing->ipaddr))
			fatalx("%s: thing->ipaddr too long", __func__);

		n = strlcpy(thing->parity, nti.parity, sizeof(thing->parity));
		if (n >= sizeof(thing->parity))
			fatalx("%s: thing->parity name too long", __func__);

		n = strlcpy(thing->name, nti.name, sizeof(thing->name));
		if (n >= sizeof(thing->name))
			fatalx("%s: thing->name too long", __func__);

		n = strlcpy(thing->password, nti.password,
		    sizeof(thing->password));
		if (n >= sizeof(thing->password))
			fatalx("%s: thing->password too long", __func__);

		n = strlcpy(thing->location, nti.location,
		    sizeof(thing->location));
		if (n >= sizeof(thing->location))
			fatalx("%s: thing->location too long", __func__);

		n = strlcpy(thing->udp, nti.udp, sizeof(thing->udp));
		if (n >= sizeof(thing->udp))
			fatalx("%s: thing->name too long", __func__);

		thing->fd = nti.fd;
		thing->baud = nti.baud;
		thing->conn_port = nti.conn_port;
		thing->rcv_port = nti.rcv_port;
		thing->data_bits = nti.data_bits;
		thing->max_clients = nti.max_clients;
		thing->port = nti.port;
		thing->stop_bits = nti.stop_bits;
		thing->type = nti.type;
		thing->client_cnt = nti.client_cnt;

		thing->tls = nti.tls;
		n = strlcpy(thing->tls_cert_file, nti.tls_cert_file,
		    sizeof(thing->tls_cert_file));
		if (n >= sizeof(thing->tls_cert_file))
			fatalx("%s: thing->tls_cert_file too long", __func__);

		n = strlcpy(thing->tls_key_file, nti.tls_key_file,
		    sizeof(thing->tls_key_file));
		if (n >= sizeof(thing->tls_key_file))
			fatalx("%s: thing->tls_key_file too long", __func__);

		n = strlcpy(thing->tls_ca_file, nti.tls_ca_file,
		    sizeof(thing->tls_ca_file));
		if (n >= sizeof(thing->tls_ca_file))
			fatalx("%s: thing->tls_ca_file too long", __func__);

		n = strlcpy(thing->tls_crl_file, nti.tls_crl_file,
		    sizeof(thing->tls_crl_file));
		if (n >= sizeof(thing->tls_crl_file))
			fatalx("%s: thing->tls_crl_file too long", __func__);

		n = strlcpy(thing->tls_ocsp_staple_file,
		    nti.tls_ocsp_staple_file,
		    sizeof(thing->tls_ocsp_staple_file));
		if (n >= sizeof(thing->tls_ocsp_staple_file))
			fatalx("%s: thing->tls_ocsp_staple_file too long",
			    __func__);

		TAILQ_INSERT_TAIL(thingsd_env->things, thing, entry);

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
things_echo_pkt(struct privsep *ps, struct imsg *imsg)
{
	if (thingsd_env->thing_pkt.exists)
		return;
	thingsd_env->thing_pkt.ps = *ps;
	thingsd_env->thing_pkt.imsg = *imsg;
	memcpy(thingsd_env->thing_pkt.name, imsg->data,
	    sizeof(thingsd_env->thing_pkt.name));
	thingsd_env->thing_pkt.exists = true;
}

void
things_stop_pkt(void)
{
	/* memset(thingsd_env->thing_pkt.name, 0, */
	/*     sizeof(thingsd_env->thing_pkt.name)); */
	thingsd_env->thing_pkt.exists = false;
}

void
things_show_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[THINGSD_MAXNAME];
	struct thing *thing, nti;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_THINGS_REQUEST:
	case IMSG_GET_INFO_THINGS_REQUEST_ROOT:

		memcpy(filter, imsg->data, sizeof(filter));

		TAILQ_FOREACH(thing, thingsd_env->things, entry) {
			if (filter[0] == '\0' || memcmp(filter,
			    thing->name, sizeof(filter)) == 0) {
				nti = compose_thing(thing, imsg->hdr.type);

				if (proc_compose_imsg(ps, PROC_CONTROL, -1,
				    IMSG_GET_INFO_THINGS_DATA,
				    imsg->hdr.peerid, -1, &nti,
				    sizeof(nti)) == -1)
					return;

			}
		}

		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_GET_INFO_THINGS_END_DATA, imsg->hdr.peerid,
			    -1, &nti, sizeof(nti)) == -1)
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
	struct thing		 nti;
	char			 blank[9] = "********";
	size_t			 n;

	memset(&nti, 0, sizeof(nti));
	nti.exists = thing->exists;
	nti.hw_ctl = thing->hw_ctl;
	nti.persist = thing->persist;

	n = strlcpy(nti.iface, thing->iface, sizeof(nti.iface));
	if (n >= sizeof(nti.iface))
		fatalx("%s: nti.iface too long", __func__);

	n = strlcpy(nti.ipaddr, thing->ipaddr, sizeof(nti.ipaddr));
	if (n >= sizeof(nti.ipaddr))
		fatalx("%s: nti.ipaddr too long", __func__);

	n = strlcpy(nti.parity, thing->parity, sizeof(nti.parity));
	if (n >= sizeof(nti.parity))
		fatalx("%s: nti.parity too long", __func__);

	n = strlcpy(nti.name, thing->name, sizeof(nti.name));
	if (n >= sizeof(nti.name))
		fatalx("%s: nti.name too long", __func__);

	nti.password[0] = '\0';
	if (type == IMSG_GET_INFO_THINGS_REQUEST)
		n = strlcpy(nti.password, blank, sizeof(nti.password));
	else
		n = strlcpy(nti.password, thing->password,
		    sizeof(nti.password));
	if (n >= sizeof(nti.password))
		fatalx("%s: nti.password too long", __func__);

	n = strlcpy(nti.location, thing->location, sizeof(nti.location));
	if (n >= sizeof(nti.location))
		fatalx("%s: nti.location too long", __func__);

	n = strlcpy(nti.udp, thing->udp, sizeof(nti.udp));
	if (n >= sizeof(nti.udp))
		fatalx("%s: nti.udp too long", __func__);

	nti.fd = thing->fd;
	nti.baud = thing->baud;
	nti.conn_port = thing->conn_port;
	nti.rcv_port = thing->rcv_port;
	nti.data_bits = thing->data_bits;
	nti.max_clients = thing->max_clients;
	nti.port = thing->port;
	nti.stop_bits = thing->stop_bits;
	nti.type = thing->type;
	nti.client_cnt = thing->client_cnt;

	nti.tls = thing->tls;
	n = strlcpy(nti.tls_cert_file, thing->tls_cert_file,
	    sizeof(nti.tls_cert_file));
	if (n >= sizeof(nti.tls_cert_file))
		fatalx("%s: nti.tls_cert_file too long", __func__);

	n = strlcpy(nti.tls_key_file, thing->tls_key_file,
	    sizeof(nti.tls_key_file));
	if (n >= sizeof(nti.tls_key_file))
		fatalx("%s: nti.tls_key_file too long", __func__);

	n = strlcpy(nti.tls_ca_file, thing->tls_ca_file,
	    sizeof(nti.tls_ca_file));
	if (n >= sizeof(nti.tls_ca_file))
		fatalx("%s: nti.tls_ca_file too long", __func__);

	n = strlcpy(nti.tls_crl_file, thing->tls_crl_file,
	    sizeof(nti.tls_crl_file));
	if (n >= sizeof(nti.tls_crl_file))
		fatalx("%s: nti.tls_crl_file too long", __func__);

	n = strlcpy(nti.tls_ocsp_staple_file, thing->tls_ocsp_staple_file,
	    sizeof(nti.tls_ocsp_staple_file));
	if (n >= sizeof(nti.tls_ocsp_staple_file))
		fatalx("%s: nti.tls_ocsp_staple_file too long", __func__);

	return nti;
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

void
send_thing_pkt(struct privsep *ps, struct imsg *imsg, char *name, char *pkt,
    int len)
{
	if (proc_compose_imsg(ps, PROC_CONTROL, -1,
	    IMSG_SHOW_PACKETS_DATA, imsg->hdr.peerid, -1, pkt, len) == -1)
		return;
}
