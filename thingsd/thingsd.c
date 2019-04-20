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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
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
#include "control.h"

__dead void		 usage(void);
int			 main(int, char *[]);
void			 thgsd_sighdlr(int, short, void *);
void			 thgsd_shutdown(void);
static pid_t		 start_child(int, char *, int, int, int);
static void		 main_dispatch_thgs(int, short, void *);

bool			 thgs_chld = false;
struct event		 evsigquit;
struct event		 evsigterm;
struct event		 evsigint;
struct event		 evsighup;

pid_t			 thgs_pid;
static struct imsgev	*iev_thgs;

uint32_t	 v_opts;

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dv]\n", getprogname());
	exit(1);
}

void
thgsd_sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGQUIT:
	case SIGTERM:
	case SIGINT:
	case SIGHUP:
		thgsd_shutdown();
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
	char			*thgs_sock, *saved_argv0;
	int			 pipe_thgs[2], debug = 0;
	int			 control_fd;

	thgs_sock = THINGSD_SOCK;

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	saved_argv0 = argv[0];

	if (saved_argv0 == NULL)
		saved_argv0 = "thingsd";

	while ((ch = getopt(argc, argv, "dvC")) != -1) {
		switch (ch) {
		case 'C':
			thgs_chld = true;
			break;
		case 'd':
			debug = 1;
			break;
		case 'v':
			if (v_opts & L_VERBOSE1)
				v_opts |= L_VERBOSE2;
			v_opts |= L_VERBOSE1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;

	if (argc > 0)
		usage();
	if (thgs_chld)
		thgs_main(debug, v_opts & (L_VERBOSE1 | L_VERBOSE2), thgs_sock);
	if (geteuid())
		fatalx("need root privileges");
	if ((control_fd = control_init(thgs_sock)) == -1)
		fatalx("thgs_sock failed");

	control_state.fd = control_fd;

	log_init(debug, LOG_DAEMON);
	log_setverbose(v_opts & L_VERBOSE1);

	/* make parent daemon */
	thgsd_process = PROC_MAIN;
	log_procinit(log_procnames[thgsd_process]);

	if (!debug && daemon(1, 0) == -1)
		fatalx("daemon");

	log_info("%s started", getprogname());

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_thgs) == -1)
		fatalx("thgs socketpair");

	thgs_pid = start_child(PROC_THGS, saved_argv0, pipe_thgs[1], debug,
	    v_opts & (L_VERBOSE1 | L_VERBOSE2));

	event_init();

	signal_set(&evsigquit, SIGQUIT, thgsd_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, thgsd_sighdlr, NULL);
	signal_set(&evsigint, SIGINT, thgsd_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, thgsd_sighdlr, NULL);

	signal_add(&evsigquit, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsigint, NULL);
	signal_add(&evsighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	/* setup thgs child pipe */
	if ((iev_thgs = malloc(sizeof(struct imsgev))) == NULL)
		fatalx("iev_thgs malloc");

	imsg_init(&iev_thgs->ibuf, pipe_thgs[0]);
	iev_thgs->handler = main_dispatch_thgs;

	/* setup event handler */
	iev_thgs->events = EV_READ;
	event_set(&iev_thgs->ev, pipe_thgs[0], iev_thgs->events,
	    iev_thgs->handler, iev_thgs);
	event_add(&iev_thgs->ev, NULL);

	if (getpwnam(TH_USER) == NULL)
		log_info("running as root. %s user not found", TH_USER);
	if (pledge("stdio unix recvfd", NULL) == -1)
		fatal("pledge");

	TAILQ_INIT(&ctl_conns);
	control_listen();

	event_dispatch();

	thgsd_shutdown();
	return EXIT_SUCCESS;
}

void
thgsd_shutdown()
{
	pid_t		 pid;
	int		 status;

	/* close pipe */
	msgbuf_write(&iev_thgs->ibuf.w);
	msgbuf_clear(&iev_thgs->ibuf.w);
	close(iev_thgs->ibuf.fd);
	free(iev_thgs);
	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d", "things",
			    WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));
	log_info("%s terminated", getprogname());
	exit(0);
}

static pid_t
start_child(int p, char *argv0, int fd, int debug, int verbose)
{
	int			 argc = 0, argvc = 10;
	char			*argv[argvc];
	pid_t			 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return (pid);
	}

	if (fd != PARENT_SOCK_FD) {
		if (dup2(fd, PARENT_SOCK_FD) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(fd, F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = argv0;
	switch (p) {
	case PROC_MAIN:
		fatalx("Can not start main process");
	case PROC_THGS:
		argv[argc++] = "-C";
		break;
	}
	if (debug)
		argv[argc++] = "-d";
	if (verbose & L_VERBOSE1)
		argv[argc++] = "-v";
	if (verbose & L_VERBOSE2)
		argv[argc++] = "-v";
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
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

static void
main_dispatch_thgs(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 shut = 0;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_SHOW_PKTS:
		case IMSG_LIST_CLTS:
		case IMSG_LIST_THGS:
		case IMSG_LIST_SOCKS:
		case IMSG_CTL_END:
			control_imsg_relay(&imsg);
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
		/* this pipe is dead, so remove the event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
main_imsg_compose_thgs(int type, pid_t pid, void *data, uint16_t datalen)
{
	return (imsg_compose_event(iev_thgs, type, 0, pid, -1, data, datalen));
}
