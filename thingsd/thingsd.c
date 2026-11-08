/*
 * Copyright (c) 2016, 2019-2026 Tracey Emery <tracey@openbsd.org>
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/cdefs.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <util.h>

#include "thingsd.h"

__dead void usage(void);

int	 main(int, char **);

int	 thingsd_configure(struct thingsd *);
void	 thingsd_dispatch_control(int, short, void *);
void	 thingsd_dispatch_sockets(int, short, void *);

void	 thingsd_sighdlr(int sig, short event, void *arg);
__dead void
	 thingsd_shutdown(struct thingsd *);
void	 thingsd_parent_shutdown(struct thingsd *);
void	 thingsd_configure_done(struct thingsd *);
int	 thingsd_thing_serial_open(struct thing *);
int	 thingsd_thing_connect(struct thingsd *, struct thing *, int);
void	 thingsd_thing_disconnect(struct thing *);
void	 thingsd_show_info(struct imsg *);
void	 thingsd_show_thing_info(struct imsg *);
void	 thingsd_thing_udp_event(int, short, void *);
void	 thingsd_thing_read(struct bufferevent *, void *);
void	 thingsd_thing_write(struct bufferevent *, void *);
void	 thingsd_thing_err(struct bufferevent *, short, void *);
void	 thingsd_oneshot_cb(int, short, void *);
void	 thingsd_add_reconn(struct thing *);
void	 thingsd_do_reconn(struct thingsd *);
void	 thingsd_write_to_socks(struct packages *);
void	 thingsd_write_to_things(struct package *);
void	 thingsd_echo_pkt(struct imsg *);
void	 thingsd_stop_pkt(struct imsg *);

struct thing
	 thingsd_compose_thing(struct thing *, enum imsg_type);

/* a packet on its way to a non-persistent thing */
struct oneshot {
	struct event		 ev;
	int			 fd;
	int			 len;
	char			 pkt[PKT_BUFF];
	char			 name[THINGSD_MAXNAME];
};

struct thingsd	*thingsd_env;
int		 thing_id;

struct imsgev	*parent_iev_control;
struct imsgev	*parent_iev_socks;

static struct event	 ev_sigint;
static struct event	 ev_sigterm;
static struct event	 ev_sighup;
static struct event	 ev_sigpipe;
static struct event	 ev_sigusr1;

void
imsg_event_init(struct imsgev *iev, int fd, void (*handler)(int, short,
    void *))
{
	if (imsgbuf_init(&iev->ibuf, fd) == -1)
		fatal("%s: imsgbuf_init", __func__);
	imsgbuf_allow_fdpass(&iev->ibuf);
	iev->handler = handler;
	iev->events = EV_READ;
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (imsgbuf_queuelen(&iev->ibuf) > 0)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint32_t type, uint32_t peerid,
    pid_t pid, int fd, void *data, size_t datalen)
{
	int	 ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data,
	    datalen)) == -1)
		return (ret);
	imsg_event_add(iev);
	return (ret);
}

int
imsg_composev_event(struct imsgev *iev, uint32_t type, uint32_t peerid,
    pid_t pid, int fd, const struct iovec *iov, int iovcnt)
{
	int	 ret;

	if ((ret = imsg_composev(&iev->ibuf, type, peerid, pid, fd, iov,
	    iovcnt)) == -1)
		return (ret);
	imsg_event_add(iev);
	return (ret);
}

int
imsg_forward_event(struct imsgev *iev, struct imsg *imsg)
{
	return (imsg_compose_event(iev, imsg->hdr.type, imsg->hdr.peerid,
	    imsg->hdr.pid, -1, imsg->data, IMSG_DATA_SIZE(imsg)));
}

/*
 * Copy a string payload out of an imsg, bounded by both the payload and
 * the destination so a short or unterminated message can't over-read.
 */
void
imsg_get_string(struct imsg *imsg, char *buf, size_t len)
{
	size_t	 n = IMSG_DATA_SIZE(imsg);

	if (n >= len)
		n = len - 1;
	if (n > 0)
		memcpy(buf, imsg->data, n);
	buf[n] = '\0';
}

void
thingsd_dispatch_control(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	struct thing	*thing;
	int		 i, n, res = 0, verbose, exists;
	unsigned int	 v;
	char		 thing_name[THINGSD_MAXNAME];
	char		 client_name[THINGSD_MAXNAME];

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			log_warnx("%s: lost control process", __func__);
			thingsd_shutdown(thingsd_env);
		}
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				log_warnx("%s: lost control process", __func__);
				thingsd_shutdown(thingsd_env);
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_SHOW_PACKETS_END_DATA:
			IMSG_SIZE_CHECK(&imsg, &v);
			if (imsg.data == NULL)
				break;
			thingsd_stop_pkt(&imsg);
			break;
		case IMSG_SHOW_PACKETS_REQUEST:
			exists = 0;
			imsg_get_string(&imsg, thing_name, sizeof(thing_name));
			TAILQ_FOREACH(thing, thingsd_env->things, entry) {
				if (strcmp(thing->conf.name, thing_name) == 0) {
					thingsd_echo_pkt(&imsg);
					exists = 1;
					break;
				}
			}
			if (!exists)
				imsg_compose_event(parent_iev_control,
				    IMSG_BAD_THING, imsg.hdr.peerid, 0, -1,
				    &res, sizeof(res));
			break;
		case IMSG_KILL_CLIENT:
			imsg_get_string(&imsg, client_name,
			    sizeof(client_name));
			if (client_name[0] == '\0')
				break;
			/* FALLTHROUGH */
		case IMSG_GET_INFO_CLIENTS_REQUEST:
		case IMSG_GET_INFO_SOCKETS_REQUEST:
			for (i = 0; i < thingsd_env->prefork_socks; i++)
				imsg_forward_event(&parent_iev_socks[i], &imsg);
			break;
		case IMSG_GET_INFO_THINGS_REQUEST:
		case IMSG_GET_INFO_THINGS_REQUEST_ROOT:
			thingsd_show_thing_info(&imsg);
			break;
		case IMSG_GET_INFO_THINGSD_REQUEST:
			thingsd_show_info(&imsg);
			break;
		case IMSG_CTL_VERBOSE:
			IMSG_SIZE_CHECK(&imsg, &verbose);
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_setverbose(verbose);
			for (i = 0; i < thingsd_env->prefork_socks; i++)
				imsg_forward_event(&parent_iev_socks[i], &imsg);
			break;
		default:
			log_warnx("%s: unexpected imsg %d from control",
			    __func__, imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
thingsd_dispatch_sockets(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	struct package	*package;
	int		 n;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			log_warnx("%s: lost sockets process", __func__);
			thingsd_shutdown(thingsd_env);
		}
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				log_warnx("%s: lost sockets process", __func__);
				thingsd_shutdown(thingsd_env);
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_DIST_CLIENT_PACKAGE:
			IMSG_SIZE_CHECK(&imsg, package);
			package = (struct package *)imsg.data;
			if (package->len < 0 ||
			    (size_t)package->len > sizeof(package->pkt))
				fatalx("%s: bad package length", __func__);
			thingsd_write_to_things(package);
			break;
		case IMSG_CFG_DONE:
			thingsd_configure_done(thingsd_env);
			break;
		default:
			log_warnx("%s: unexpected imsg %d from sockets",
			    __func__, imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

void
thingsd_sighdlr(int sig, short event, void *arg)
{
	struct thingsd	*env = arg;

	switch (sig) {
	case SIGHUP:
		log_info("%s: ignoring SIGHUP", __func__);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		thingsd_shutdown(env);
		break;
	default:
		fatalx("unexpected signal");
	}
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dnv] [-D macro=value] [-f file]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct thingsd		*env;
	struct timeval		 eb_timeout;
	const char		*conffile = THINGSD_CONF;
	int			 ch, i, n;
	int			 pipe_control[2];
	int			 pipe_socks[THINGSD_MAX_PREFORK][2];
	int			 pipe_control_socks[THINGSD_MAX_PREFORK][2];
	int			 fd_socks[THINGSD_MAX_PREFORK];

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("%s: calloc", __func__);

	while ((ch = getopt(argc, argv, "D:df:vn")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'd':
			env->thingsd_debug = 2;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'v':
			env->thingsd_verbose++;
			break;
		case 'n':
			env->thingsd_debug = 2;
			env->thingsd_noaction = 1;
			break;
		default:
			usage();
		}
	}

	/* log to stderr until daemonized */
	log_init(env->thingsd_debug ? env->thingsd_debug : 1, LOG_DAEMON);

	argc -= optind;
	if (argc > 0)
		usage();

	thingsd_env = env;
	env->thingsd_conffile = conffile;

	if (parse_config(env->thingsd_conffile, env) == -1)
		exit(1);

	if (env->thingsd_noaction && !env->thingsd_debug)
		env->thingsd_debug = 1;

	/* check for root privileges */
	if (env->thingsd_noaction == 0) {
		if (geteuid())
			fatalx("need root privileges");
	}

	if (getpwnam(THINGSD_USER) == NULL)
		fatal("unknown user %s", THINGSD_USER);

	if (env->thingsd_noaction) {
		fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	log_init(env->thingsd_debug, LOG_DAEMON);
	log_setverbose(env->thingsd_verbose);
	log_procinit("thingsd");

	if (!env->thingsd_debug && daemon(0, 0) == -1)
		fatal("can't daemonize");

	log_info("%s startup", getprogname());

	/*
	 * All pipes are created before forking so the children inherit
	 * them and no descriptor passing is needed to wire the processes
	 * together.  Each child closes the ends it does not own.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC,
	    pipe_control) == -1)
		fatal("%s: socketpair", __func__);
	for (i = 0; i < env->prefork_socks; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC,
		    pipe_socks[i]) == -1)
			fatal("%s: socketpair", __func__);
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, PF_UNSPEC,
		    pipe_control_socks[i]) == -1)
			fatal("%s: socketpair", __func__);
	}

	switch (fork()) {
	case -1:
		fatal("%s: fork", __func__);
	case 0:
		close(pipe_control[0]);
		for (i = 0; i < env->prefork_socks; i++) {
			close(pipe_socks[i][0]);
			close(pipe_socks[i][1]);
			close(pipe_control_socks[i][1]);
			fd_socks[i] = pipe_control_socks[i][0];
		}
		control(pipe_control[1], fd_socks);
		/* NOTREACHED */
	}

	for (n = 0; n < env->prefork_socks; n++) {
		switch (fork()) {
		case -1:
			fatal("%s: fork", __func__);
		case 0:
			close(pipe_control[0]);
			close(pipe_control[1]);
			for (i = 0; i < env->prefork_socks; i++) {
				close(pipe_socks[i][0]);
				close(pipe_control_socks[i][0]);
				if (i == n)
					continue;
				close(pipe_socks[i][1]);
				close(pipe_control_socks[i][1]);
			}
			sockets(pipe_socks[n][1], pipe_control_socks[n][1]);
			/* NOTREACHED */
		}
	}

	close(pipe_control[1]);
	for (i = 0; i < env->prefork_socks; i++) {
		close(pipe_socks[i][1]);
		close(pipe_control_socks[i][0]);
		close(pipe_control_socks[i][1]);
	}

	env->thingsd_eb = event_init();

	signal_set(&ev_sigint, SIGINT, thingsd_sighdlr, env);
	signal_set(&ev_sigterm, SIGTERM, thingsd_sighdlr, env);
	signal_set(&ev_sighup, SIGHUP, thingsd_sighdlr, env);
	signal_set(&ev_sigpipe, SIGPIPE, thingsd_sighdlr, env);
	signal_set(&ev_sigusr1, SIGUSR1, thingsd_sighdlr, env);

	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigpipe, NULL);
	signal_add(&ev_sigusr1, NULL);

	if ((parent_iev_control = calloc(1, sizeof(*parent_iev_control)))
	    == NULL)
		fatal("%s: calloc", __func__);
	imsg_event_init(parent_iev_control, pipe_control[0],
	    thingsd_dispatch_control);

	if ((parent_iev_socks = calloc(env->prefork_socks,
	    sizeof(*parent_iev_socks))) == NULL)
		fatal("%s: calloc", __func__);
	for (i = 0; i < env->prefork_socks; i++)
		imsg_event_init(&parent_iev_socks[i], pipe_socks[i][0],
		    thingsd_dispatch_sockets);

	if (thingsd_configure(env) == -1)
		fatalx("configuration failed");

	/* begin thing watchdog */
	eb_timeout.tv_sec = EB_TIMEOUT;
	eb_timeout.tv_usec = 0;

	/* serial things are reopened from here on, nothing else is */
	if (unveil("/dev", "rw") == -1)
		err(1, "unveil");
	if (unveil(NULL, NULL) != 0)
		err(1, "unveil");

	if (pledge("stdio rpath wpath inet proc tty dns", NULL) == -1)
		err(1, "pledge");

	env->run = 1;
	while (env->run) {
		if (!TAILQ_EMPTY(env->dead_things))
			thingsd_do_reconn(env);
		event_base_loopexit(env->thingsd_eb, &eb_timeout);
		event_base_dispatch(env->thingsd_eb);
	}

	log_debug("%s thingsd exiting", getprogname());

	return (0);
}

int
thingsd_configure(struct thingsd *env)
{
	struct thing		*thing;
	struct socket		*sock;
	int			 n;

	env->socks_reload = env->prefork_socks;

	/* setup our things, which run privileged */
	TAILQ_FOREACH(thing, env->things, entry)
		thingsd_thing_connect(env, thing, 0);

	TAILQ_FOREACH(sock, env->sockets, entry) {
		socket_tls_load(sock);
		if (config_setsocks(env, sock) == -1)
			fatalx("%s: send socket error", __func__);
	}

	imsg_compose_event(parent_iev_control, IMSG_CFG_DONE, 0, 0, -1,
	    NULL, 0);
	for (n = 0; n < env->prefork_socks; n++)
		imsg_compose_event(&parent_iev_socks[n], IMSG_CFG_DONE, 0, 0,
		    -1, NULL, 0);

	return (0);
}

void
thingsd_configure_done(struct thingsd *env)
{
	int	 n;

	if (env->socks_reload == 0) {
		log_warnx("%s: configuration already finished", __func__);
		return;
	}

	env->socks_reload--;
	if (env->socks_reload == 0) {
		imsg_compose_event(parent_iev_control, IMSG_CTL_START, 0, 0,
		    -1, NULL, 0);
		for (n = 0; n < env->prefork_socks; n++)
			imsg_compose_event(&parent_iev_socks[n],
			    IMSG_CTL_START, 0, 0, -1, NULL, 0);
	}
}

__dead void
thingsd_shutdown(struct thingsd *env)
{
	pid_t	 pid;
	int	 n, status;

	/* closing the pipes tells the children to exit */
	event_del(&parent_iev_control->ev);
	imsgbuf_clear(&parent_iev_control->ibuf);
	close(parent_iev_control->ibuf.fd);
	for (n = 0; n < env->prefork_socks; n++) {
		event_del(&parent_iev_socks[n].ev);
		imsgbuf_clear(&parent_iev_socks[n].ibuf);
		close(parent_iev_socks[n].ibuf.fd);
	}
	free(parent_iev_control);
	free(parent_iev_socks);

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("lost child: pid %d terminated; signal %d",
			    pid, WTERMSIG(status));
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			log_warnx("lost child: pid %d exited abnormally", pid);
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	thingsd_parent_shutdown(env);

	log_warnx("thingsd terminating");
	exit(0);
}

void
thingsd_show_info(struct imsg *imsg)
{
	struct thingsd_thingsd_info	npi;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_THINGSD_REQUEST:
		npi.verbose = log_getverbose();
		if (imsg_compose_event(parent_iev_control,
		    IMSG_GET_INFO_THINGSD_DATA, imsg->hdr.peerid, 0, -1,
		    &npi, sizeof(npi)) == -1)
			return;
		if (imsg_compose_event(parent_iev_control,
		    IMSG_GET_INFO_THINGSD_END_DATA, imsg->hdr.peerid, 0, -1,
		    &npi, sizeof(npi)) == -1)
			return;
		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}

void
thingsd_parent_shutdown(struct thingsd *env)
{
	struct thing		*thing, *tthing;
	struct socket		*sock, *tsock;
	struct package		*package, *tpkg;
	struct dead_thing	*dead_thing, *tdead_thing;
	struct packet_client	*pclt, *tpclt;
	int			 n;

	log_debug("thingsd parent shutting down");

	/* clean up packet clients */
	TAILQ_FOREACH_SAFE(pclt, env->packet_clients, entry, tpclt) {
		TAILQ_REMOVE(env->packet_clients, pclt, entry);
		free(pclt);
	}

	/* clean up dead things */
	TAILQ_FOREACH_SAFE(dead_thing, env->dead_things, entry, tdead_thing) {
		TAILQ_REMOVE(env->dead_things, dead_thing, entry);
		free(dead_thing);
	}

	/*  clean up packages */
	TAILQ_FOREACH_SAFE(package, env->packages, entry, tpkg) {
		TAILQ_REMOVE(env->packages, package, entry);
		free(package);
	}

	/* clean up sockets */
	TAILQ_FOREACH_SAFE(sock, env->sockets, entry, tsock) {
		if (sock->conf.tls) {
			free(sock->conf.tls_cert);
			free(sock->conf.tls_cert_file);
			free(sock->conf.tls_key);
			free(sock->conf.tls_key_file);
			free(sock->conf.tls_ca);
			free(sock->conf.tls_ca_file);
			free(sock->conf.tls_crl);
			free(sock->conf.tls_crl_file);
			free(sock->conf.tls_ocsp_staple);
			free(sock->conf.tls_ocsp_staple_file);
		}
		if (event_initialized(&sock->ev))
			event_del(&sock->ev);
		if (sock->fd != -1)
			close(sock->fd);
		TAILQ_REMOVE(env->sockets, sock, entry);
		free(sock);
	}
	free(env->sockets);

	/* clean up things */
	TAILQ_FOREACH_SAFE(thing, env->things, entry, tthing) {
		if (thing->conf.tls) {
			free(thing->conf.tls_cert);
			free(thing->conf.tls_cert_file);
			free(thing->conf.tls_key);
			free(thing->conf.tls_key_file);
			free(thing->conf.tls_ca);
			free(thing->conf.tls_ca_file);
			free(thing->conf.tls_crl);
			free(thing->conf.tls_crl_file);
			free(thing->conf.tls_ocsp_staple);
			free(thing->conf.tls_ocsp_staple_file);
		}

		for (n = 0; n < thing->udp_nfd; n++) {
			event_del(&thing->udp_ev[n]);
			close(thing->udp_fd[n]);
		}

		if (thing->bev != NULL)
			bufferevent_free(thing->bev);

		if (thing->fd != -1)
			close(thing->fd);
		TAILQ_REMOVE(env->things, thing, entry);
		free(thing);
	}

	env->run = 0;
	free(env->things);
	free(env);
}

struct thing *
thingsd_conf_new_thing(struct thingsd *env, struct thing *p_thing, char *name,
    int id)
{
	struct thing	*thing;

	/* duplicate names are a config error */
	TAILQ_FOREACH(thing, env->things, entry) {
		if (strcmp(name, thing->conf.name) == 0)
			return (NULL);
	}

	if ((thing = calloc(1, sizeof(*thing))) == NULL)
		fatal("%s: calloc", __func__);

	thing->conf.ipv4 = 1;
	thing->conf.id = id;
	thing->fd = -1;

	TAILQ_INSERT_TAIL(env->things, thing, entry);

	return (thing);
}

int
thingsd_thing_serial_open(struct thing *thing)
{
	struct termios		 s_opts;
	int			 baudrate = 0, csize = 0;

	/*
	 * Just a reminder to set the ownership of your serial
	 * devices to _thingsd. Otherwise, a thing will not be
	 * able to successfully open(2) the file descriptor.
	 */
	if ((thing->fd = open(thing->conf.location, O_RDWR |
	    O_NONBLOCK | O_NOCTTY | O_NDELAY)) == -1) {
		log_warn("failed to open %s", thing->conf.location);
		return (-1);
	}

	if (tcgetattr(thing->fd, &s_opts) == -1) {
		log_warn("%s: tcgetattr %s", __func__, thing->conf.location);
		close(thing->fd);
		thing->fd = -1;
		return (-1);
	}

	switch (thing->conf.baud) {
	case 50:
		baudrate = B50;
		break;
	case 75:
		baudrate = B75;
		break;
	case 110:
		baudrate = B110;
		break;
	case 134:
		baudrate = B134;
		break;
	case 150:
		baudrate = B150;
		break;
	case 200:
		baudrate = B200;
		break;
	case 300:
		baudrate = B300;
		break;
	case 600:
		baudrate = B600;
		break;
	case 1200:
		baudrate = B1200;
		break;
	case 1800:
		baudrate = B1800;
		break;
	case 2400:
		baudrate = B2400;
		break;
	case 4800:
		baudrate = B4800;
		break;
	case 9600:
		baudrate = B9600;
		break;
	case 19200:
		baudrate = B19200;
		break;
	case 38400:
		baudrate = B38400;
		break;
	case 57600:
		baudrate = B57600;
		break;
	case 76800:
		baudrate = B76800;
		break;
	case 115200:
		baudrate = B115200;
		break;
	}

	cfsetispeed(&s_opts, baudrate);
	cfsetospeed(&s_opts, baudrate);

	/* enable and set local */
	s_opts.c_cflag |= (CLOCAL | CREAD);

	if (thing->conf.data_bits != -1) {
		s_opts.c_cflag &= ~CSIZE;
		switch (thing->conf.data_bits) {
		case 5:
			csize = CS5;
			break;
		case 6:
			csize = CS6;
			break;
		case 7:
			csize = CS7;
			break;
		case 8:
			csize = CS8;
			break;
		}
		s_opts.c_cflag |= csize;
	}

	if (strlen(thing->conf.parity) != 0) {
		s_opts.c_cflag &= ~PARENB;

		if (strcmp(thing->conf.parity, "odd") == 0) {
			s_opts.c_cflag |= PARENB;
			s_opts.c_cflag |= PARODD;
			s_opts.c_iflag |= (INPCK | ISTRIP);
		} else if (strcmp(thing->conf.parity, "even") == 0) {
			s_opts.c_cflag |= PARENB;
			s_opts.c_cflag &= ~PARODD;
			s_opts.c_iflag |= (INPCK | ISTRIP);
		}
	}

	if (thing->conf.stop_bits != -1) {
		if (thing->conf.stop_bits == 2)
			s_opts.c_cflag |= CSTOPB;
		else
			s_opts.c_cflag &= ~CSTOPB;
	}

	if (thing->conf.hw_ctl == 0)
		s_opts.c_cflag &= ~CRTSCTS;
	else
		s_opts.c_cflag |= CRTSCTS;

	if (thing->conf.sw_ctl == 0)
		s_opts.c_iflag &= ~(IXON | IXOFF | IXANY);
	else
		s_opts.c_iflag |= (IXON | IXOFF | IXANY);

	/* raw input/output */
	s_opts.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	s_opts.c_oflag &= ~OPOST;

	if (tcsetattr(thing->fd, TCSANOW, &s_opts) == -1) {
		log_warn("%s: tcsetattr %s", __func__, thing->conf.location);
		close(thing->fd);
		thing->fd = -1;
		return (-1);
	}

	return (0);
}

/*
 * Open the thing's descriptor(s) and hook them into the event loop.
 * On failure the thing is queued for a retry unless this already is one.
 */
int
thingsd_thing_connect(struct thingsd *env, struct thing *thing, int reconn)
{
	struct address		*a;
	int			 fd, n;

	thing->conf.env = env;

	switch (thing->conf.type) {
	case S_DEV:
		if (thingsd_thing_serial_open(thing) == -1)
			goto fail;
		break;
	case S_TCP:
		if (thing->conf.persist == 0) {
			/* connections are made per packet */
			thing->fd = -1;
			thing->exists = 1;
			return (0);
		}
		if ((thing->fd = sockets_open_client(thing->conf.ipaddr,
		    thing->conf.tcp_conn_port)) == -1) {
			log_warnx("%s: ipaddr connection failed for %s",
			    __func__, thing->conf.name);
			goto fail;
		}
		thing->connecting = 1;
		break;
	case S_UDP:
		/* udp things never go away, so this only runs at startup */
		n = 0;
		TAILQ_FOREACH(a, thing->conf.udp_al, entry) {
			if (n >= THINGSD_MAXIFACE) {
				log_warnx("%s: too many udp addresses for %s",
				    __func__, thing->conf.name);
				break;
			}
			if ((fd = sockets_create_socket(&a->ss,
			    thing->conf.udp_rcv_port, S_UDP)) == -1)
				fatalx("%s: create udp socket failed for %s",
				    __func__, thing->conf.name);
			thing->udp_fd[n] = fd;
			event_set(&thing->udp_ev[n], fd, EV_READ | EV_PERSIST,
			    thingsd_thing_udp_event, thing);
			if (event_add(&thing->udp_ev[n], NULL))
				fatalx("%s: udp ev error", __func__);
			n++;
		}
		if (n == 0)
			fatalx("%s: no udp address for %s", __func__,
			    thing->conf.name);
		thing->udp_nfd = n;
		thing->exists = 1;
		log_debug("%s: running udp thing %s", __func__,
		    thing->conf.name);
		return (0);
	default:
		fatalx("%s: unknown thing type %d", __func__,
		    thing->conf.type);
	}

	log_debug("%s: configuring thing %s (%d)", __func__, thing->conf.name,
	    thing->fd);

	thing->bev = bufferevent_new(thing->fd, thingsd_thing_read,
	    thingsd_thing_write, thingsd_thing_err, thing);
	if (thing->bev == NULL)
		fatalx("%s: bufferevent_new", __func__);

	/* never buffer more than one package worth of input */
	bufferevent_setwatermark(thing->bev, EV_READ, 0, PKT_BUFF);
	bufferevent_enable(thing->bev, EV_READ | EV_WRITE);

	thing->exists = 1;

	if (thing->conf.type == S_DEV)
		log_info("%s: %s", reconn ? "reconnected" : "connected",
		    thing->conf.name);

	return (0);

fail:
	if (!reconn)
		thingsd_add_reconn(thing);
	return (-1);
}

void
thingsd_thing_disconnect(struct thing *thing)
{
	if (thing->bev != NULL) {
		bufferevent_free(thing->bev);
		thing->bev = NULL;
	}
	if (thing->fd != -1) {
		close(thing->fd);
		thing->fd = -1;
	}
	thing->connecting = 0;
	thingsd_add_reconn(thing);
}

void
thingsd_oneshot_cb(int fd, short event, void *arg)
{
	struct oneshot	*os = arg;
	socklen_t	 len = sizeof(int);
	int		 error = 0;

	if (event & EV_TIMEOUT)
		log_warnx("%s: connection to %s timed out", __func__,
		    os->name);
	else if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 ||
	    error != 0) {
		errno = error ? error : errno;
		log_warn("%s: connection to %s failed", __func__, os->name);
	} else if (write(fd, os->pkt, os->len) == -1)
		log_warn("%s: write to %s failed", __func__, os->name);

	close(fd);
	free(os);
}

void
thingsd_write_to_things(struct package *package)
{
	struct thing		*thing = NULL;
	struct oneshot		*os;
	struct timeval		 tv;

	TAILQ_FOREACH(thing, thingsd_env->things, entry)
		if (thing->conf.id == package->thing_id)
			break;

	if (thing == NULL)
		return;

	if (thing->conf.type == S_UDP) {
		/* udp things are receive only */
		log_debug("%s: dropping packet for udp thing %s", __func__,
		    thing->conf.name);
		return;
	}

	if (thing->conf.type == S_DEV || thing->conf.persist) {
		if (thing->bev != NULL)
			bufferevent_write(thing->bev, package->pkt,
			    package->len);
		return;
	}

	if ((os = calloc(1, sizeof(*os))) == NULL) {
		log_warn("%s: calloc", __func__);
		return;
	}
	if ((os->fd = sockets_open_client(thing->conf.ipaddr,
	    thing->conf.tcp_conn_port)) == -1) {
		free(os);
		return;
	}
	memcpy(os->pkt, package->pkt, package->len);
	os->len = package->len;
	strlcpy(os->name, thing->conf.name, sizeof(os->name));

	/* fires once the non-blocking connect has settled */
	tv.tv_sec = ONESHOT_TIMEOUT;
	tv.tv_usec = 0;
	event_set(&os->ev, os->fd, EV_WRITE, thingsd_oneshot_cb, os);
	if (event_add(&os->ev, &tv) == -1) {
		log_warn("%s: event_add", __func__);
		close(os->fd);
		free(os);
	}
}

void
thingsd_write_to_socks(struct packages *packages)
{
	struct package		*package, *tpkg, p;
	struct packet_client	*packet_client;
	struct thing		*thing = NULL;
	int			 n;

	TAILQ_FOREACH_SAFE(package, packages, entry, tpkg) {
		memcpy(&p, package, sizeof(p));

		for (n = 0; n < thingsd_env->prefork_socks; n++) {
			if (imsg_compose_event(&parent_iev_socks[n],
			    IMSG_DIST_THING_PACKAGE, 0, 0, -1, &p,
			    sizeof(p)) == -1) {
				log_warn("%s: failed to compose "
				    "IMSG_DIST_THING_PACKAGE imsg", __func__);
				return;
			}
		}

		TAILQ_FOREACH(thing, thingsd_env->things, entry) {
			if (thing->conf.id == package->thing_id)
				break;
		}

		if (thing == NULL)
			goto free;

		TAILQ_FOREACH(packet_client, thingsd_env->packet_clients,
		    entry) {
			if (strlen(packet_client->name) == 0)
				continue;
			if (strcmp(thing->conf.name, packet_client->name) != 0)
				continue;
			if (imsg_compose_event(parent_iev_control,
			    IMSG_SHOW_PACKETS_DATA, packet_client->peerid, 0,
			    -1, package->pkt, package->len) == -1)
				break;
		}
free:
		TAILQ_REMOVE(packages, package, entry);
		free(package);
	}
}

void
thingsd_thing_udp_event(int fd, short event, void *arg)
{
	struct thing		*thing = (struct thing *)arg;
	struct package		*package = NULL;
	struct sockaddr		*addr = NULL;
	socklen_t		*addrlen = NULL;

	if ((package = calloc(1, sizeof(*package))) == NULL)
		fatalx("%s: calloc", __func__);

	package->len = recvfrom(fd, package->pkt, sizeof(package->pkt),
	    0, addr, addrlen);
	package->thing_id = thing->conf.id;

	if (package->len == -1) {
		free(package);
		return;
	}

	TAILQ_INSERT_TAIL(thingsd_env->packages, package, entry);
	thingsd_write_to_socks(thingsd_env->packages);
}

void
thingsd_thing_read(struct bufferevent *bev, void *arg)
{
	struct thing		*thing = (struct thing *)arg;
	struct evbuffer		*evb = EVBUFFER_INPUT(bev);
	struct package		*package;
	size_t			 len;

	while ((len = EVBUFFER_LENGTH(evb)) > 0) {
		if ((package = calloc(1, sizeof(*package))) == NULL)
			fatalx("%s: calloc", __func__);

		if (len > sizeof(package->pkt))
			len = sizeof(package->pkt);
		evbuffer_remove(evb, package->pkt, len);
		package->len = len;
		package->thing_id = thing->conf.id;

		TAILQ_INSERT_TAIL(thingsd_env->packages, package, entry);
	}

	thingsd_write_to_socks(thingsd_env->packages);
}

void
thingsd_thing_write(struct bufferevent *bev, void *arg)
{
	struct thing	*thing = (struct thing *)arg;
	socklen_t	 len = sizeof(int);
	int		 error = 0;

	if (!thing->connecting)
		return;

	/* first writable event after a non-blocking connect */
	thing->connecting = 0;
	if (getsockopt(thing->fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 ||
	    error != 0) {
		errno = error ? error : errno;
		log_warn("thing %s: connection failed", thing->conf.name);
		thingsd_thing_disconnect(thing);
		return;
	}

	log_info("connected: %s", thing->conf.name);
}

void
thingsd_thing_err(struct bufferevent *bev, short error, void *arg)
{
	struct thing	*thing = (struct thing *)arg;

	if (error & EVBUFFER_EOF)
		log_warnx("thing %s disconnected", thing->conf.name);
	else if (error & EVBUFFER_TIMEOUT)
		log_warnx("thing %s timed out", thing->conf.name);
	else
		log_warnx("thing %s error, disconnecting", thing->conf.name);

	thingsd_thing_disconnect(thing);
}

void
thingsd_add_reconn(struct thing *thing)
{
	struct dead_thing	*dead_thing;

	thing->exists = 0;

	/* already waiting for a retry */
	TAILQ_FOREACH(dead_thing, thingsd_env->dead_things, entry)
		if (strcmp(dead_thing->name, thing->conf.name) == 0)
			return;

	if ((dead_thing = calloc(1, sizeof(*dead_thing))) == NULL)
		fatal("%s: calloc", __func__);

	log_debug("%s: adding detached thing, %s", __func__, thing->conf.name);

	if (strlcpy(dead_thing->name, thing->conf.name,
	    sizeof(dead_thing->name)) >= sizeof(dead_thing->name))
		fatalx("%s: strlcpy", __func__);

	dead_thing->type = thing->conf.type;
	dead_thing->dtime = time(NULL);

	TAILQ_INSERT_TAIL(thingsd_env->dead_things, dead_thing, entry);
}

void
thingsd_do_reconn(struct thingsd *env)
{
	struct dead_thing	*dead_thing, *tdead;
	struct thing		*thing;
	time_t			 now = time(NULL);

	TAILQ_FOREACH_SAFE(dead_thing, env->dead_things, entry, tdead) {
		if ((size_t)(now - dead_thing->dtime) <= env->conn_retry)
			continue;

		TAILQ_FOREACH(thing, env->things, entry)
			if (strcmp(thing->conf.name, dead_thing->name) == 0)
				break;

		if (thing == NULL || thing->exists) {
			TAILQ_REMOVE(env->dead_things, dead_thing, entry);
			free(dead_thing);
			continue;
		}

		log_debug("attempting to reconnect %s", dead_thing->name);
		dead_thing->dtime = now;

		if (thingsd_thing_connect(env, thing, 1) == 0) {
			TAILQ_REMOVE(env->dead_things, dead_thing, entry);
			free(dead_thing);
		}
	}
}

void
thingsd_echo_pkt(struct imsg *imsg)
{
	struct packet_client	*packet_client;

	packet_client = calloc(1, sizeof(*packet_client));
	if (packet_client == NULL)
		fatal("%s: calloc", __func__);

	thingsd_env->packet_client_count++;

	packet_client->peerid = imsg->hdr.peerid;

	imsg_get_string(imsg, packet_client->name,
	    sizeof(packet_client->name));

	log_debug("control packet echo request for %s", packet_client->name);

	TAILQ_INSERT_TAIL(thingsd_env->packet_clients, packet_client, entry);
}

void
thingsd_stop_pkt(struct imsg *imsg)
{
	struct packet_client	*packet_client, *tpacket_client;
	uint32_t		 fd;

	memcpy(&fd, imsg->data, sizeof(fd));

	TAILQ_FOREACH_SAFE(packet_client, thingsd_env->packet_clients, entry,
	    tpacket_client) {
		if (fd == packet_client->peerid) {
			TAILQ_REMOVE(thingsd_env->packet_clients,
			    packet_client, entry);
			log_debug("control packet echo request stopping for %s",
			    packet_client->name);
			thingsd_env->packet_client_count--;
			free(packet_client);
			return;
		}
	}

}

void
thingsd_show_thing_info(struct imsg *imsg)
{
	struct thing	*thing, nti;
	char		 filter[THINGSD_MAXNAME];

	memset(&nti, 0, sizeof(nti));
	imsg_get_string(imsg, filter, sizeof(filter));

	TAILQ_FOREACH(thing, thingsd_env->things, entry) {
		if (filter[0] == '\0' || strcmp(filter,
		    thing->conf.name) == 0) {
			nti = thingsd_compose_thing(thing, imsg->hdr.type);

			if (imsg_compose_event(parent_iev_control,
			    IMSG_GET_INFO_THINGS_DATA, imsg->hdr.peerid, 0,
			    -1, &nti, sizeof(nti)) == -1)
				return;
		}
	}

	imsg_compose_event(parent_iev_control, IMSG_GET_INFO_THINGS_END_DATA,
	    imsg->hdr.peerid, 0, -1, &nti, sizeof(nti));
}

struct thing
thingsd_compose_thing(struct thing *thing, enum imsg_type type)
{
	struct thing		 nti;
	char			 blank[9] = "********";

	memset(&nti, 0, sizeof(nti));
	nti.exists = thing->exists;
	nti.conf.hw_ctl = thing->conf.hw_ctl;
	nti.conf.persist = thing->conf.persist;

	memcpy(&nti.conf.tcp_iface, thing->conf.tcp_iface,
	    sizeof(nti.conf.tcp_iface));

	memcpy(&nti.conf.ipaddr, thing->conf.ipaddr, sizeof(nti.conf.ipaddr));

	memcpy(&nti.conf.parity, thing->conf.parity, sizeof(nti.conf.parity));

	memcpy(&nti.conf.name, thing->conf.name, sizeof(nti.conf.name));

	nti.conf.password[0] = '\0';
	if (type == IMSG_GET_INFO_THINGS_REQUEST)
		memcpy(&nti.conf.password, blank, sizeof(nti.conf.password));
	else
		memcpy(&nti.conf.password, thing->conf.password,
		    sizeof(nti.conf.password));

	memcpy(&nti.conf.location, thing->conf.location,
	    sizeof(nti.conf.location));

	memcpy(&nti.conf.udp, thing->conf.udp, sizeof(nti.conf.udp));
	memcpy(&nti.conf.udp_iface, thing->conf.udp_iface,
	    sizeof(nti.conf.udp_iface));

	nti.fd = thing->fd;
	nti.conf.baud = thing->conf.baud;
	nti.conf.tcp_conn_port = thing->conf.tcp_conn_port;
	nti.conf.udp_rcv_port = thing->conf.udp_rcv_port;
	nti.conf.data_bits = thing->conf.data_bits;
	nti.conf.max_clients = thing->conf.max_clients;
	nti.conf.tcp_listen_port = thing->conf.tcp_listen_port;
	nti.conf.stop_bits = thing->conf.stop_bits;
	nti.conf.type = thing->conf.type;
	nti.conf.tls = thing->conf.tls;

	return nti;
}

