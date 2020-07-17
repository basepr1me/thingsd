/*
 * Copyright (c) 2020 Tracey Emery <tracey@traceyemery.net>
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

#include <net/if.h>
#include <netinet/in.h>

#include <stdbool.h>
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

int
config_init(struct thingsd *env)
{
	struct privsep *ps = &env->thingsd_ps;
	unsigned int	 what;

	/* Global configuration. */
	if (privsep_process == PROC_PARENT)
		env->prefork_things = THINGS_NUMPROC;

	ps->ps_what[PROC_PARENT] = CONFIG_ALL;
	ps->ps_what[PROC_THINGS] = CONFIG_THINGS;

	/* Other configuration. */
	what = ps->ps_what[privsep_process];
	if (what & CONFIG_THINGS) {
		env->things = calloc(1, sizeof(*env->things));
		if (env->things == NULL)
			return (-1);
		env->sockets = calloc(1, sizeof(*env->sockets));
		if (env->sockets == NULL)
			return (-1);
		env->clients = calloc(1, sizeof(*env->clients));
		if (env->clients == NULL)
			return (-1);
		env->dead_things = calloc(1, sizeof(*env->dead_things));
		if (env->dead_things == NULL)
			return (-1);
		env->dead_things->dead_things_list = calloc(1,
		    sizeof(*env->dead_things->dead_things_list));
		if (env->dead_things->dead_things_list == NULL)
			return (-1);
		TAILQ_INIT(env->things);
		TAILQ_INIT(env->sockets);
		TAILQ_INIT(env->clients);
		TAILQ_INIT(env->dead_things->dead_things_list);
	}
	return (0);
}

void
config_purge(struct thingsd *env, unsigned int reset)
{
	struct privsep		*ps = &env->thingsd_ps;
	struct thing		*thing;
	unsigned int		 what;

	what = ps->ps_what[privsep_process];
	if (what & CONFIG_THINGS) {
		while ((thing = TAILQ_FIRST(env->things)) != NULL) {
			TAILQ_REMOVE(env->things, thing, entry);
			free(thing);
		}
	}
}

int
config_setreset(struct thingsd *env, unsigned int reset)
{
	struct privsep	*ps = &env->thingsd_ps;
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
