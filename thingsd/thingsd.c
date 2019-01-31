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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "thingsd.h"

__dead void		 usage(void);
int			 main(int, char *[]);
void			 do_reconn(void);
void			 thingsd_sighdlr(int, short, void *);
void			 thingsd_shutdown(struct dthgs *);

struct thgsd		*pthgsd;
struct dthgs		*pdthgs;

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dv]\n", getprogname());
	exit(1);
}

void
thingsd_sighdlr(int sig, short event, void *arg)
{
	struct dthgs		*zdthgs = (struct dthgs *)arg;

	switch (sig) {
	case SIGQUIT:
	case SIGTERM:
	case SIGINT:
	case SIGHUP:
		thingsd_shutdown(zdthgs);
		break;
	case SIGPIPE:
		/* ignore */
		break;
	default:
		fatalx("unexpected signal");
	}
}

int
main(int argc, char *argv[])
{
	int			 ch;
	struct timeval		 eb_timeout;

	if ((pthgsd = calloc(1, sizeof(*pthgsd))) == NULL)
		fatalx("no thgsd calloc");
	if ((pdthgs = calloc(1, sizeof(*pdthgs))) == NULL)
		fatalx("no dthgs calloc");

	while ((ch = getopt(argc, argv, "dv")) != -1) {
		switch (ch) {
		case 'd':
			pthgsd->debug++;
			break;
		case 'v':
			pthgsd->verbose++;
			break;
		default:
			usage();
		}
	}

	/* log to stderr until daemonized */
	log_init(pthgsd->debug ? pthgsd->debug : 1, LOG_DAEMON);
	argc -= optind;
	if (argc > 0)
		usage();

	if (parse_conf(PATH_CONF))
		fatalx("config parsing failed");
	if (geteuid())
		fatalx("need root privileges");

	log_init(pthgsd->debug, LOG_DAEMON);
	log_setverbose(pthgsd->verbose);

	/* make parent daemon */
	log_procinit("parent");
	if (!pthgsd->debug && daemon(1, 0) == -1)
			fatalx("daemon");

	log_info("%s started", getprogname());

	pthgsd->eb = event_init();
	pdthgs->run = 1;

	open_thgs(pthgsd, false);
	create_socks(pthgsd, false);

	signal_set(&pthgsd->evsigquit, SIGQUIT, thingsd_sighdlr, pdthgs);
	signal_set(&pthgsd->evsigterm, SIGTERM, thingsd_sighdlr, pdthgs);
	signal_set(&pthgsd->evsigint, SIGINT, thingsd_sighdlr, pdthgs);
	signal_set(&pthgsd->evsighup, SIGHUP, thingsd_sighdlr, pdthgs);

	signal_add(&pthgsd->evsigquit, NULL);
	signal_add(&pthgsd->evsigterm, NULL);
	signal_add(&pthgsd->evsigint, NULL);
	signal_add(&pthgsd->evsighup, NULL);

	if ((pthgsd->pw = getpwnam(TH_USER)) != NULL) {
		if(setuid(pthgsd->pw->pw_uid) != 0)
			err(1, "unable to set user id of %s: %s", TH_USER,
			    strerror(errno));
	} else
		log_info("running as root. %s user not found", TH_USER);

	if (unveil("/dev", "rw") == -1)
		err(1, "unveil");
	if (pledge("stdio rpath wpath inet proc tty dns", NULL) == -1)
		err(1, "pledge");

	/* begin thing watchdog */
	eb_timeout.tv_sec = EB_TIMEOUT;
	eb_timeout.tv_usec = 0;

	while (pdthgs->run) {
		if (pthgsd->exists) {
			do_reconn();
		}
		event_base_loopexit(pthgsd->eb, &eb_timeout);
		event_base_dispatch(pthgsd->eb);
	}

	thingsd_shutdown(pdthgs);
	return EXIT_SUCCESS;
}

struct dthg
*new_dthg(struct thg *pthg)
{
	struct dthg		*dthg;

	if ((dthg = calloc(1, sizeof(*dthg))) == NULL)
		fatalx("no calloc dthg");
	dthg->name = pthg->name;
	dthg->type = pthg->type;
	dthg->dtime = time(NULL);
	return dthg;
}

void
add_reconn(struct thg *pthg)
{
	struct dthg		*dthg;

	dthg = new_dthg(pthg);
	pthgsd->exists = true;
	pthgsd->dcount++;
	TAILQ_INSERT_TAIL(&pdthgs->zthgs, dthg, entry);
}

void
do_reconn(void)
{
	struct dthg		*dthg, *tdthg;
	struct thg		*thg;

	TAILQ_FOREACH_SAFE(dthg, &pdthgs->zthgs, entry, tdthg) {
		if ((size_t)(time(NULL) - dthg->dtime) >
		    pthgsd->conn_rtry) {
			dthg->dtime = time(NULL);
			log_info("attempting to reconnect %s", dthg->name);
			switch (dthg->type) {
			case DEV:
				open_thgs(pthgsd, true);
				break;
			case TCP:
				create_socks(pthgsd, true);
				break;
			}
		}
	}
	TAILQ_FOREACH_SAFE(dthg, &pdthgs->zthgs, entry, tdthg) {
		TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
			if (strcmp(thg->name, dthg->name) == 0 && thg->exists) {
				TAILQ_REMOVE(&pdthgs->zthgs, dthg, entry);
				pthgsd->dcount--;
				free(dthg);
				return;
			}
		}
	}
	if (pthgsd->dcount == 0)
		pthgsd->exists = false;
}

void
thingsd_shutdown(struct dthgs *zdthgs)
{
	struct thg		*thg, *tthg;
	struct sock		*sock, *tsock;
	struct clt		*clt, *tclt;
	struct dthg		*dthg, *tdthg;
	const char		*progname = getprogname();

	zdthgs->run = 0;
	/* clean up things */
	TAILQ_FOREACH_SAFE(thg, &pthgsd->thgs, entry, tthg) {
		close(thg->fd);
		TAILQ_REMOVE(&pthgsd->thgs, thg, entry);
		free(thg);
	}
	/*  clean up dead things */
	TAILQ_FOREACH_SAFE(dthg, &pdthgs->zthgs, entry, tdthg) {
		TAILQ_REMOVE(&pdthgs->zthgs, dthg, entry);
		free(dthg);
	}
	/* clean up sockets */
	TAILQ_FOREACH_SAFE(sock, &pthgsd->socks, entry, tsock) {
		if (sock->tls) {
			tls_config_free(sock->tls_config);
			tls_free(sock->tls_ctx);
		}
		close(sock->fd);
		free(sock->ev);
		TAILQ_REMOVE(&pthgsd->socks, sock, entry);
		free(sock);
	}
	/* clean up clts */
	TAILQ_FOREACH_SAFE(clt, &pthgsd->clts, entry, tclt) {
		close(clt->fd);
		free(clt->sub_names);
		TAILQ_REMOVE(&pthgsd->clts, clt, entry);
		free(clt);
	}
	log_info("%s terminated", progname);
	/* event_base_free(pthgsd->eb); */
	free(pdthgs);
	free(pthgsd);
	exit(0);
}
