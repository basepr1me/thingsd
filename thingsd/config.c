/*
 * Copyright (c) 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/tree.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <event.h>
#include <fcntl.h>
#include <util.h>
#include <errno.h>
#include <imsg.h>

#include "proc.h"
#include "thingsd.h"

extern enum privsep_procid privsep_process;

int
config_init(struct thingsd *env)
{
	struct privsep		*ps = env->thingsd_ps;
	unsigned int		 what;

	/* Global configuration. */
	if (privsep_process == PROC_PARENT)
		env->prefork_socks = SOCKS_NUMPROC;

	ps->ps_what[PROC_PARENT] = CONFIG_ALL;
	ps->ps_what[PROC_SOCKS] = CONFIG_SOCKS;

	/* Other configuration. */
	what = ps->ps_what[privsep_process];
	if (what & CONFIG_SOCKS) {
		if ((env->things = calloc(1, sizeof(*env->things))) == NULL)
			return (-1);
		if ((env->sockets = calloc(1, sizeof(*env->sockets))) == NULL)
			return (-1);
		if ((env->packages = calloc(1, sizeof(*env->packages))) == NULL)
			return (-1);
		if ((env->dead_things = calloc(1,
		    sizeof(*env->dead_things))) == NULL)
			return (-1);
		env->packet_clients = calloc(1, sizeof(*env->packet_clients));
		if (env->packet_clients == NULL)
			return (-1);
		TAILQ_INIT(env->things);
		TAILQ_INIT(env->sockets);
		TAILQ_INIT(env->packages);
		TAILQ_INIT(env->dead_things);
		TAILQ_INIT(env->packet_clients);
	}
	return (0);
}

int
config_getcfg(struct thingsd *env, struct imsg *imsg)
{
	/* nothing to do but tell parent configuration is done */
	if (privsep_process != PROC_PARENT)
		proc_compose(env->thingsd_ps, PROC_PARENT,
		    IMSG_CFG_DONE, NULL, 0);

	return (0);
}

int
config_getsocks(struct thingsd *env, struct imsg *imsg)
{
	struct socket		*sock = NULL;
	struct socket_config	 sock_conf;
	uint8_t			*p = imsg->data;

	IMSG_SIZE_CHECK(imsg, &sock_conf);
	memcpy(&sock_conf, p, sizeof(sock_conf));

	if (IMSG_DATA_SIZE(imsg) != sizeof(sock_conf)) {
		log_debug("%s: imsg size error", __func__);
		return (-1);
	}

	/* create a new socket */
	if ((sock = calloc(1, sizeof(*sock))) == NULL) {
		if (imsg->fd != -1)
			close(imsg->fd);
		return (-1);
	}

	memcpy(&sock->conf, &sock_conf, sizeof(sock->conf));
	sock->fd = imsg->fd;

	TAILQ_INSERT_TAIL(env->sockets, sock, entry);

	return (0);
}

int
config_setsocks(struct thingsd *env, struct socket *ts)
{
	struct privsep		*ps = env->thingsd_ps;
	struct socket_config	 u;
	int			 fd = -1, n, m;
	struct iovec		 iov[6];
	size_t			 c;
	unsigned int		 id, what;

	/* setup socket in priv process */
	if (sockets_privinit(ts) == -1)
		return (-1);

	for (id = 0; id < PROC_MAX; id++) {
		what = ps->ps_what[id];

		if ((what & CONFIG_SOCKS) == 0 || id == privsep_process)
			continue;

		memcpy(&u, &ts->conf, sizeof(u));

		c = 0;
		iov[c].iov_base = &u;
		iov[c++].iov_len = sizeof(u);
		if (id == PROC_SOCKS) {
			/* XXX imsg code will close the fd after 1st call */
			n = -1;
			proc_range(ps, id, &n, &m);
			for (n = 0; n < m; n++) {
				/* send thing fd */
				if (ts->fd == -1)
					fd = -1;
				else if ((fd = dup(ts->fd)) == -1)
					return (-1);
				if (proc_composev_imsg(ps, id, n,
				    IMSG_CFG_SOCKS, -1, fd, iov,
				    c) != 0) {
					log_warn("%s: failed to compose "
					    "IMSG_CFG_SOCKS imsg",
					    __func__);
					return (-1);
				}
				if (proc_flush_imsg(ps, id, n) == -1) {
					log_warn("%s: failed to flush "
					    "IMSG_CFG_SOCKS imsg",
					    __func__);
					return (-1);
				}
			}
		}
	}

	/* Close thing socket early to prevent fd exhaustion in thingsd. */
	if (ts->fd != -1) {
		close(ts->fd);
		ts->fd = -1;
	}
	return (0);
}

void
config_purge(struct thingsd *env, unsigned int reset)
{
	struct privsep		*ps = env->thingsd_ps;
	struct thing		*thing;
	unsigned int		 what;

	what = ps->ps_what[privsep_process];
	if (what & CONFIG_SOCKS) {
		while ((thing = TAILQ_FIRST(env->things)) != NULL) {
			TAILQ_REMOVE(env->things, thing, entry);
			free(thing);
		}
	}
}

int
config_setreset(struct thingsd *env, unsigned int reset)
{
	struct privsep	*ps = env->thingsd_ps;
	unsigned int	 id;

	for (id = 0; id < PROC_MAX; id++) {
		if (id == privsep_process)
			continue;
		proc_compose(ps, id, IMSG_CTL_RESET, &reset, sizeof(reset));
	}

	return (0);
}

int
config_getreset(struct thingsd *env, struct imsg *imsg)
{
	unsigned int	 mode;

	IMSG_SIZE_CHECK(imsg, &mode);
	memcpy(&mode, imsg->data, sizeof(mode));

	config_purge(env, mode);

	return (0);
}
