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

#include <err.h>
#include <errno.h>
#include <event.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "thingsd.h"
#include "ctl.h"
#include "control.h"

extern struct thgsd	*pthgsd;
extern struct dthgs	*pdthgs;
struct imsgev		*iev_main;

void
ctl_sighdlr(int sig, short event, void *bula)
{
	struct dthgs		*zdthgs = (struct dthgs *)bula;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		ctl_shutdown(zdthgs);
	default:
		fatalx("unexpected signal");
	}
}

void
thgs_ctl(int debug, int verbose, char *ctl_sock)
{
	struct passwd		*pw;
	int			 ctl_fd;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	thgsd_process = PROC_CTL;
	setproctitle("%s", log_procnames[thgsd_process]);
	log_procinit(log_procnames[thgsd_process]);

	if ((ctl_fd = control_init(ctl_sock)) == -1)
		fatalx("ctl_sock failed");
	control_state.fd = ctl_fd;
	if ((pw = getpwnam(TH_USER)) != NULL) {
		if(setuid(pthgsd->pw->pw_uid) != 0)
			err(1, "unable to set user id of %s: %s", TH_USER,
			    strerror(errno));
		else
			log_info("running as root. %s user not found", TH_USER);
	}

	if (pledge("stdio unix recvfd", NULL) == -1)
		fatal("pledge");

	pthgsd->ctl_eb = event_init();

	signal_set(&pthgsd->ctl_evsigquit, SIGQUIT, ctl_sighdlr, pdthgs);
	signal_set(&pthgsd->ctl_evsigterm, SIGTERM, ctl_sighdlr, pdthgs);
	signal_set(&pthgsd->ctl_evsigint, SIGINT, ctl_sighdlr, pdthgs);

	signal_add(&pthgsd->ctl_evsigquit, NULL);
	signal_add(&pthgsd->ctl_evsigterm, NULL);
	signal_add(&pthgsd->ctl_evsigint, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the parent process. */
	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_main->ibuf, 3);
	iev_main->handler = ctl_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	TAILQ_INIT(&ctl_conns);
	control_listen();
	event_dispatch();
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, void *data, uint16_t datalen)
{
	int			ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid,
	    pid, fd, data, datalen)) != -1)
		imsg_event_add(iev);
	return (ret);
}

void
ctl_dispatch_main(int fd, short event, void *bula)
{
	struct imsg		 imsg;
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	int			 n, shut = 0, verbose;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get error");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_LIST_CLTS:
		case IMSG_LIST_THGS:
		case IMSG_LIST_SOCKS:
		case IMSG_CTL_END:
			control_imsg_relay(&imsg);
			break;
		case IMSG_CTL_LOG_VERBOSE:
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_setverbose(verbose);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
ctl_shutdown(struct dthgs *zdthgs)
{
	/* Close pipes. */
	msgbuf_write(&iev_main->ibuf.w);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);
	free(iev_main);
	log_debug("%s control exiting", getprogname());
	exit(0);
}

int
ctl_imsg_compose_main(int type, pid_t pid, void *data, uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data, datalen));
}
