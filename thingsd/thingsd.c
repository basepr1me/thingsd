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

__dead void		 usage(void);
int			 main(int, char *[]);
void			 do_reconn(void);
void			 thingsd_sighdlr(int, short, void *);
void			 thingsd_shutdown(struct dthgs *);
static pid_t		 start_child(int, char *, int, int, int);
static void		 main_dispatch_ctl(int, short, void *);
int		 	 main_imsg_compose_ctl(int, pid_t, void *, uint16_t);
void			 show_list(enum ctl_list_type, pid_t);

struct thgsd		*pthgsd;
struct dthgs		*pdthgs;
struct thg_imsg		*compose_thgs(struct thg *);
struct clt_imsg		*compose_clts(struct clt *);
struct sock_imsg	*compose_socks(struct sock *);

bool			 ctl_chld = false;

pid_t			 ctl_pid;
static struct imsgev	*iev_ctl;

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
	char			*ctl_sock, *saved_argv0;
	int			 pipe_ctl[2];

	ctl_sock = THINGSD_SOCK;

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	if ((pthgsd = calloc(1, sizeof(*pthgsd))) == NULL)
		fatalx("no thgsd calloc");
	if ((pdthgs = calloc(1, sizeof(*pdthgs))) == NULL)
		fatalx("no dthgs calloc");

	saved_argv0 = argv[0];
	if (saved_argv0 == NULL)
		saved_argv0 = "thingsd";

	while ((ch = getopt(argc, argv, "dvC")) != -1) {
		switch (ch) {
		case 'C':
			ctl_chld = true;
			break;
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

	argc -= optind;
	if (argc > 0)
		usage();

	if (ctl_chld)
		thgs_ctl(pthgsd->debug, pthgsd->verbose, ctl_sock);
	if (parse_conf(PATH_CONF))
		fatalx("config parsing failed");
	if (geteuid())
		fatalx("need root privileges");

	log_init(pthgsd->debug, LOG_DAEMON);
	log_setverbose(pthgsd->verbose);

	/* make parent daemon */
	thgsd_process = PROC_MAIN;
	setproctitle("%s", log_procnames[thgsd_process]);
	log_procinit(log_procnames[thgsd_process]);

	if (!pthgsd->debug && daemon(1, 0) == -1)
		fatalx("daemon");

	log_info("%s started", getprogname());

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_ctl) == -1)
		fatalx("ctl socketpair");

	ctl_pid = start_child(PROC_CTL, saved_argv0, pipe_ctl[1], pthgsd->debug,
	    pthgsd->verbose);

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
	signal(SIGPIPE, SIG_IGN);

	/* setup ctl child pipe */
	if ((iev_ctl = malloc(sizeof(struct imsgev))) == NULL)
		fatalx("iev_ctl malloc");
	imsg_init(&iev_ctl->ibuf, pipe_ctl[0]);
	iev_ctl->handler = main_dispatch_ctl;

	/* setup event handler */
	iev_ctl->events = EV_READ;
	event_set(&iev_ctl->ev, pipe_ctl[0], iev_ctl->events, iev_ctl->handler,
	    iev_ctl);
	event_add(&iev_ctl->ev, NULL);

	if ((pthgsd->pw = getpwnam(TH_USER)) != NULL) {
		if(setuid(pthgsd->pw->pw_uid) != 0)
			errx(1, "unable to set user id of %s: %s", TH_USER,
			    strerror(errno));
	} else
		log_info("running as root. %s user not found", TH_USER);

	if (unveil("/dev", "rw") == -1)
		errx(1, "unveil");
	if (pledge("stdio rpath wpath inet proc tty dns", NULL) == -1)
		errx(1, "pledge");

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
	log_debug("%s: adding detached thing, %s", __func__, pthg->name);
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

	/* close pipe */
	msgbuf_write(&iev_ctl->ibuf.w);
	msgbuf_clear(&iev_ctl->ibuf.w);
	close(iev_ctl->ibuf.fd);
	free(iev_ctl);
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

static pid_t
start_child(int p, char *argv0, int fd, int debug, int verbose)
{
	int			 argc = 0, argvc = 10, ac;
	char			*argv[argvc], bufa[argvc], bufb[argvc];
	pid_t			 pid;
	const char		*dash = "-";

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return (pid);
	}

	if (fd != 3) {
		if (dup2(fd, 3) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(fd, F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = argv0;
	switch (p) {
	case PROC_MAIN:
		fatalx("Can not start main process");
	case PROC_CTL:
		argv[argc++] = "-C";
		break;
	}
	memset(bufa, 0, sizeof(bufa));
	memset(bufb, 0, sizeof(bufb));
	if (debug) {
		strlcpy(bufa, dash, sizeof(bufa));
		for (ac = 0; ac < debug; ac++) {
			if (ac >= argvc)
				continue;
			strlcat(bufa, "d", sizeof(bufa));
		}
		argv[argc++] = bufa;
	}
	if (verbose) {
		strlcpy(bufb, dash, sizeof(bufb));
		for (ac = 0; ac < verbose; ac++) {
			if (ac >= argvc)
				continue;
			strlcat(bufb, "v", sizeof(bufb));
		}
		argv[argc++] = bufb;
	}
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
}

static void
main_dispatch_ctl(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	enum ctl_list_type	 type;
	ssize_t			 n;
	int			 shut = 0, verbose;

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
		case IMSG_CTL_LIST:
			if (IMSG_DATA_SIZE(imsg) != sizeof(type))
				fatalx("%s: IMSG_CTL_STATUS wrong length: %lu",
				    __func__, IMSG_DATA_SIZE(imsg));
			memcpy(&type, imsg.data, sizeof(type));
			show_list(type, imsg.hdr.pid);
			break;
		case IMSG_CTL_LOG_VERBOSE:
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_setverbose(verbose);
			main_imsg_compose_ctl(imsg.hdr.type, 0,
			    imsg.data, imsg.hdr.len - IMSG_HEADER_SIZE);
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
		log_warnx("%s: ctl pipe dead, event deleted", __func__);
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
main_imsg_compose_ctl(int type, pid_t pid, void *data, uint16_t datalen)
{
	return (imsg_compose_event(iev_ctl, type, 0, pid, -1, data, datalen));
}

void
show_list(enum ctl_list_type type, pid_t pid)
{
	struct clt		*clt;
	struct thg		*thg;
	struct sock		*sock;
	struct clt_imsg		*clt_imsg;
	struct thg_imsg		*thg_imsg;
	struct sock_imsg	*sock_imsg;

	switch(type) {
	case CTL_LIST_CLTS:
		TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
			clt_imsg = compose_clts(clt);
			main_imsg_compose_ctl(IMSG_LIST_CLTS, pid, clt_imsg,
			    sizeof(*clt_imsg));
			free(clt_imsg);
		}
		break;
	case CTL_LIST_THGS:
		TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
			thg_imsg = compose_thgs(thg);
			main_imsg_compose_ctl(IMSG_LIST_THGS, pid, thg_imsg,
			    sizeof(*thg_imsg));
			free(thg_imsg);
		}
		break;
	case CTL_LIST_SOCKS:
		TAILQ_FOREACH(sock, &pthgsd->socks, entry) {
			sock_imsg = compose_socks(sock);
			main_imsg_compose_ctl(IMSG_LIST_SOCKS, pid, sock_imsg,
			    sizeof(*sock_imsg));
			free(sock_imsg);
		}
		break;
	default:
		fatalx("unknown resolver type %d", type);
		break;
	}
	main_imsg_compose_ctl(IMSG_CTL_END, pid, NULL, 0);
}

struct clt_imsg *
compose_clts(struct clt *pclt)
{
	struct clt_imsg		*comp_clt;

	if ((comp_clt = calloc(1, sizeof(*comp_clt))) == NULL)
		fatalx("no com_clt calloc");

	comp_clt->subscribed = pclt->subscribed;

	if (pclt->name != NULL)
		strlcpy(comp_clt->name, pclt->name, BUFF);

	comp_clt->fd = pclt->fd;
	comp_clt->port = pclt->port;
	comp_clt->subs = pclt->subs;
	comp_clt->tls = pclt->tls;
	return(comp_clt);
};

struct thg_imsg *
compose_thgs(struct thg *pthg)
{
	struct thg_imsg		*comp_thg;

	if ((comp_thg = calloc(1, sizeof(*comp_thg))) == NULL)
		fatalx("no com_thg calloc");
	comp_thg->exists = pthg->exists;
	comp_thg->hw_ctl = pthg->hw_ctl;
	comp_thg->persist = pthg->persist;
	comp_thg->sw_ctl = pthg->sw_ctl;

	if (pthg->iface != NULL)
		strlcpy(comp_thg->iface, pthg->iface, BUFF);
	if (pthg->ipaddr != NULL)
		strlcpy(comp_thg->ipaddr, pthg->ipaddr, BUFF);
	if (pthg->name != NULL)
		strlcpy(comp_thg->name, pthg->name, BUFF);
	if (pthg->parity != NULL)
		strlcpy(comp_thg->parity, pthg->parity, BUFF);
	if (pthg->password != NULL)
		strlcpy(comp_thg->password, pthg->password, BUFF);
	if (pthg->location != NULL)
		strlcpy(comp_thg->location, pthg->location, BUFF);
	if (pthg->udp != NULL)
		strlcpy(comp_thg->udp, pthg->udp, BUFF);

	comp_thg->fd = pthg->fd;
	comp_thg->baud = pthg->baud;
	comp_thg->conn_port = pthg->conn_port;
	comp_thg->data_bits = pthg->data_bits;
	comp_thg->max_clt = pthg->max_clt;
	comp_thg->port = pthg->port;
	comp_thg->stop_bits = pthg->stop_bits;
	comp_thg->type = pthg->type;
	comp_thg->clt_cnt = pthg->clt_cnt;

	comp_thg->tls = pthg->tls;

	if (pthg->tls_cert_file != NULL)
		strlcpy(comp_thg->tls_cert_file, pthg->tls_cert_file, BUFF);
	if (pthg->tls_key_file != NULL)
		strlcpy(comp_thg->tls_key_file, pthg->tls_key_file, BUFF);
	if (pthg->tls_ca_file != NULL)
		strlcpy(comp_thg->tls_ca_file, pthg->tls_ca_file, BUFF);
	if (pthg->tls_crl_file != NULL)
		strlcpy(comp_thg->tls_crl_file, pthg->tls_crl_file, BUFF);
	if (pthg->tls_ocsp_staple_file != NULL)
		strlcpy(comp_thg->tls_ocsp_staple_file,
		    pthg->tls_ocsp_staple_file, BUFF);
	return(comp_thg);
};

struct sock_imsg *
compose_socks(struct sock *psock)
{
	struct sock_imsg	*comp_sock;

	if ((comp_sock = calloc(1, sizeof(*comp_sock))) == NULL)
		fatalx("no com_sock calloc");

	if (psock->name != NULL)
		strlcpy(comp_sock->name, psock->name, BUFF);

	comp_sock->fd = psock->fd;
	comp_sock->port = psock->port;
	comp_sock->clt_cnt = psock->clt_cnt;
	comp_sock->max_clts = psock->max_clts;
	comp_sock->tls = psock->tls;
	return(comp_sock);
};
