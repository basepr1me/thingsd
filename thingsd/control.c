/*
 * Copyright (c) 2020-2026 Tracey Emery <tracey@openbsd.org>
 * Copyright (c) 2010-2015 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/tree.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "thingsd.h"

#define CONTROL_BACKLOG 5

struct control_sock {
	const char	*cs_name;
	struct event	 cs_ev;
	struct event	 cs_evt;
	int		 cs_fd;
	int		 cs_restricted;
};

struct ctl_conn {
	TAILQ_ENTRY(ctl_conn)	 entry;
	uint8_t			 flags;
#define CTL_CONN_NOTIFY		 0x01
	struct imsgev		 iev;
	struct sockpeercred	 peercred;

	/* sockets processes still to answer this conn's list request */
	int			 pending_sockets;
	int			 pending_clients;
};
TAILQ_HEAD(ctl_connlist, ctl_conn);

static struct ctl_connlist	 ctl_conns;
static struct control_sock	 control_cs;
static struct imsgev		*control_iev_parent;
static struct imsgev		*control_iev_socks;
static struct event		 ev_sigint;
static struct event		 ev_sigterm;
static struct event		 ev_sighup;
static struct event		 ev_sigpipe;
static struct event		 ev_sigusr1;

struct ctl_conn *control_connbyfd(int);
int	 control_init(struct control_sock *);
int	 control_listen(struct control_sock *);
void	 control_cleanup(struct control_sock *);
void	 control_accept(int, short, void *);
void	 control_close(int, struct control_sock *);
void	 control_dispatch_imsg(int, short, void *);
void	 control_dispatch_thingsd(int, short, void *);
void	 control_dispatch_sockets(int, short, void *);
void	 control_imsg_forward(struct imsg *);
void	 control_sighdlr(int, short, void *);
__dead void
	 control_shutdown(void);

__dead void
control(int fd_parent, int *fd_socks)
{
	struct passwd	*pw;
	int		 n;

	log_procinit("control");

	/* the socket is bound as root, before the chroot */
	control_cs.cs_name = THINGSD_SOCKET;
	if (control_init(&control_cs) == -1)
		fatalx("%s: control_init", __func__);

	if ((pw = getpwnam(THINGSD_USER)) == NULL)
		fatal("unknown user %s", THINGSD_USER);

	if (chroot(pw->pw_dir) == -1)
		fatal("%s: chroot", __func__);
	if (chdir("/") == -1)
		fatal("%s: chdir(\"/\")", __func__);

	setproctitle("%s", "control");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("%s: cannot drop privileges", __func__);

	event_init();

	signal_set(&ev_sigint, SIGINT, control_sighdlr, NULL);
	signal_set(&ev_sigterm, SIGTERM, control_sighdlr, NULL);
	signal_set(&ev_sighup, SIGHUP, control_sighdlr, NULL);
	signal_set(&ev_sigpipe, SIGPIPE, control_sighdlr, NULL);
	signal_set(&ev_sigusr1, SIGUSR1, control_sighdlr, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal_add(&ev_sigpipe, NULL);
	signal_add(&ev_sigusr1, NULL);

	if ((control_iev_parent = calloc(1, sizeof(*control_iev_parent)))
	    == NULL)
		fatal("%s: calloc", __func__);
	imsg_event_init(control_iev_parent, fd_parent,
	    control_dispatch_thingsd);

	if ((control_iev_socks = calloc(thingsd_env->prefork_socks,
	    sizeof(*control_iev_socks))) == NULL)
		fatal("%s: calloc", __func__);
	for (n = 0; n < thingsd_env->prefork_socks; n++)
		imsg_event_init(&control_iev_socks[n], fd_socks[n],
		    control_dispatch_sockets);

	TAILQ_INIT(&ctl_conns);
	if (control_listen(&control_cs) == -1)
		fatalx("%s: control_listen", __func__);

	if (pledge("stdio cpath unix", NULL) == -1)
		fatal("pledge");

	event_dispatch();

	control_shutdown();
}

void
control_sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		control_shutdown();
		break;
	case SIGHUP:
	case SIGPIPE:
	case SIGUSR1:
		/* ignore */
		break;
	default:
		fatalx("%s: unexpected signal", __func__);
	}
}

__dead void
control_shutdown(void)
{
	struct ctl_conn	*c;
	int		 n;

	control_cleanup(&control_cs);

	while ((c = TAILQ_FIRST(&ctl_conns)) != NULL) {
		TAILQ_REMOVE(&ctl_conns, c, entry);
		event_del(&c->iev.ev);
		imsgbuf_clear(&c->iev.ibuf);
		close(c->iev.ibuf.fd);
		free(c);
	}

	event_del(&control_iev_parent->ev);
	imsgbuf_clear(&control_iev_parent->ibuf);
	close(control_iev_parent->ibuf.fd);
	free(control_iev_parent);
	for (n = 0; n < thingsd_env->prefork_socks; n++) {
		event_del(&control_iev_socks[n].ev);
		imsgbuf_clear(&control_iev_socks[n].ibuf);
		close(control_iev_socks[n].ibuf.fd);
	}
	free(control_iev_socks);

	log_info("control exiting, pid %d", getpid());
	exit(0);
}

void
control_dispatch_sockets(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	struct ctl_conn	*c;
	int		 n;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			log_warnx("%s: lost sockets process", __func__);
			control_shutdown();
		}
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				log_warnx("%s: lost sockets process", __func__);
				control_shutdown();
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
		case IMSG_GET_INFO_SOCKETS_END_DATA:
		case IMSG_GET_INFO_CLIENTS_END_DATA:
		case IMSG_GET_INFO_SOCKETS_DATA:
		case IMSG_GET_INFO_CLIENTS_DATA:
			c = control_connbyfd(imsg.hdr.peerid);
			if (c == NULL) {
				log_warnx("%s: fd %d: not found",
				    __func__, imsg.hdr.peerid);
				break;
			}

			/*
			 * Every sockets process answers the request, so the
			 * end marker is only passed on once all have replied.
			 */
			if (imsg.hdr.type == IMSG_GET_INFO_SOCKETS_END_DATA &&
			    --c->pending_sockets > 0)
				break;
			if (imsg.hdr.type == IMSG_GET_INFO_CLIENTS_END_DATA &&
			    --c->pending_clients > 0)
				break;

			imsg_compose_event(&c->iev, imsg.hdr.type,
			    0, 0, -1, imsg.data, IMSG_DATA_SIZE(&imsg));
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
control_dispatch_thingsd(int fd, short event, void *arg)
{
	struct imsgev	*iev = arg;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	struct ctl_conn	*c;
	int		 n, bad;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0) {
			log_warnx("%s: lost parent process", __func__);
			control_shutdown();
		}
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE) {
				log_warnx("%s: lost parent process", __func__);
				control_shutdown();
			}
			fatal("%s: imsgbuf_write", __func__);
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("%s: imsgbuf_get", __func__);
		if (n == 0)
			break;

		bad = 0;
		switch (imsg.hdr.type) {
		case IMSG_BAD_THING:
			bad = 1;
			/* FALLTHROUGH */
		case IMSG_SHOW_PACKETS_DATA:
		case IMSG_SHOW_PACKETS_END_DATA:
		case IMSG_GET_INFO_THINGSD_DATA:
		case IMSG_GET_INFO_THINGSD_END_DATA:
		case IMSG_GET_INFO_THINGS_DATA:
		case IMSG_GET_INFO_THINGS_END_DATA:
			c = control_connbyfd(imsg.hdr.peerid);
			if (c == NULL) {
				log_warnx("%s: fd %d: not found",
				    __func__, imsg.hdr.peerid);
				break;
			}

			if (bad) {
				control_close(imsg.hdr.peerid, &control_cs);
				break;
			}

			imsg_compose_event(&c->iev, imsg.hdr.type,
			    0, 0, -1, imsg.data, IMSG_DATA_SIZE(&imsg));
			break;
		case IMSG_CFG_DONE:
		case IMSG_CTL_START:
			/* don't do anything */
			break;
		default:
			log_warnx("%s: unexpected imsg %d from parent",
			    __func__, imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

int
control_init(struct control_sock *cs)
{
	struct sockaddr_un	 sun;
	int			 fd;
	mode_t			 old_umask, mode;

	if (cs->cs_name == NULL)
		return (0);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, cs->cs_name, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		log_warnx("%s: socket path too long: %s", __func__,
		    cs->cs_name);
		close(fd);
		return (-1);
	}

	if (unlink(cs->cs_name) == -1)
		if (errno != ENOENT) {
			log_warn("%s: unlink %s", __func__, cs->cs_name);
			close(fd);
			return (-1);
		}

	if (cs->cs_restricted) {
		old_umask = umask(S_IXUSR|S_IXGRP|S_IXOTH);
		mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
	} else {
		old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
		mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP;
	}

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("%s: bind: %s", __func__, cs->cs_name);
		close(fd);
		(void)umask(old_umask);
		return (-1);
	}

	(void)umask(old_umask);

	if (chmod(cs->cs_name, mode) == -1) {
		log_warn("%s: chmod", __func__);
		close(fd);
		(void)unlink(cs->cs_name);
		return (-1);
	}

	cs->cs_fd = fd;

	return (0);
}

int
control_listen(struct control_sock *cs)
{
	if (cs->cs_name == NULL)
		return (0);

	if (listen(cs->cs_fd, CONTROL_BACKLOG) == -1) {
		log_warn("%s: listen", __func__);
		return (-1);
	}

	event_set(&cs->cs_ev, cs->cs_fd, EV_READ,
	    control_accept, cs);
	event_add(&cs->cs_ev, NULL);
	evtimer_set(&cs->cs_evt, control_accept, cs);

	return (0);
}

void
control_cleanup(struct control_sock *cs)
{
	if (cs->cs_name == NULL)
		return;

	event_del(&cs->cs_ev);
	event_del(&cs->cs_evt);
	close(cs->cs_fd);
}

/* ARGSUSED */
void
control_accept(int listenfd, short event, void *arg)
{
	struct control_sock	*cs = arg;
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_un	 sun;
	struct ctl_conn		*c;

	event_add(&cs->cs_ev, NULL);
	if (event & EV_TIMEOUT)
		return;

	len = sizeof(sun);
	connfd = accept4(listenfd, (struct sockaddr *)&sun, &len,
	    SOCK_NONBLOCK);
	if (connfd == -1) {
		/*
		 * Pause accept if we are out of file descriptors, or
		 * libevent will haunt us here too.
		 */
		if (errno == ENFILE || errno == EMFILE) {
			struct timeval evtpause = { 1, 0 };

			event_del(&cs->cs_ev);
			evtimer_add(&cs->cs_evt, &evtpause);
		} else if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("%s: accept", __func__);
		return;
	}

	c = calloc(1, sizeof(struct ctl_conn));
	if (c == NULL) {
		log_warn("%s", __func__);
		close(connfd);
		return;
	}

	len = sizeof(c->peercred);
	if (getsockopt(connfd, SOL_SOCKET, SO_PEERCRED,
	    &c->peercred, &len) != 0) {
		log_warn("%s: failed to get peer credentials", __func__);
		close(connfd);
		free(c);
		return;
	}

	if (imsgbuf_init(&c->iev.ibuf, connfd) == -1) {
		log_warn("%s: failed to init imsgbuf", __func__);
		close(connfd);
		free(c);
		return;
	}

	c->iev.handler = control_dispatch_imsg;
	c->iev.events = EV_READ;

	event_set(&c->iev.ev, c->iev.ibuf.fd, c->iev.events,
	    c->iev.handler, &c->iev);
	event_add(&c->iev.ev, NULL);

	TAILQ_INSERT_TAIL(&ctl_conns, c, entry);
}

struct ctl_conn *
control_connbyfd(int fd)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (c->iev.ibuf.fd == fd)
			break;
	}

	return (c);
}

void
control_close(int fd, struct control_sock *cs)
{
	struct ctl_conn	*c;

	c = control_connbyfd(fd);
	if (c == NULL) {
		log_warn("%s: fd %d: not found", __func__, fd);
		return;
	}

	/* let the parent drop any packet echo registered for this conn */
	if (imsg_compose_event(control_iev_parent, IMSG_SHOW_PACKETS_END_DATA,
	    0, 0, -1, &fd, sizeof(fd)) == -1)
		log_warn("fd not sent to thingsd to close");

	imsgbuf_clear(&c->iev.ibuf);
	TAILQ_REMOVE(&ctl_conns, c, entry);

	event_del(&c->iev.ev);
	close(c->iev.ibuf.fd);

	/* Some file descriptors are available again. */
	if (evtimer_pending(&cs->cs_evt, NULL)) {
		evtimer_del(&cs->cs_evt);
		event_add(&cs->cs_ev, NULL);
	}

	free(c);
}

/* ARGSUSED */
void
control_dispatch_imsg(int fd, short event, void *arg)
{
	struct thingsd_control_info	 nci;
	struct control_sock		*cs = &control_cs;
	struct ctl_conn			*c;
	struct imsg			 imsg;
	int				 n, v, ret = 0;
	uid_t				 euid;
	gid_t				 egid;

	if (getpeereid(fd, &euid, &egid) == -1)
		return;

	c = control_connbyfd(fd);
	if (c == NULL) {
		log_warn("%s: fd %d: not found", __func__, fd);
		return;
	}

	if (event & EV_READ) {
		n = imsgbuf_read(&c->iev.ibuf);
		if (n == -1 || n == 0) {
			control_close(fd, cs);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (imsgbuf_write(&c->iev.ibuf) == -1) {
			control_close(fd, cs);
			return;
		}
	}

	for (;;) {
		n = imsgbuf_get(&c->iev.ibuf, &imsg);
		if (n == -1) {
			control_close(fd, cs);
			return;
		}

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_GET_INFO_THINGSD_REQUEST:
		case IMSG_GET_INFO_THINGS_REQUEST:
		case IMSG_GET_INFO_CLIENTS_REQUEST:
		case IMSG_GET_INFO_SOCKETS_REQUEST:
		case IMSG_GET_INFO_CONTROL_REQUEST:
			break;
		default:
			if (c->peercred.uid != 0) {
				log_warnx("denied request %d from uid %d",
				    imsg.hdr.type, c->peercred.uid);
				ret = EPERM;
				goto fail;
			}
			break;
		}

		control_imsg_forward(&imsg);

		switch (imsg.hdr.type) {
		case IMSG_CTL_NOTIFY:
			if (c->flags & CTL_CONN_NOTIFY) {
				log_debug("%s: "
				    "client requested notify more than once",
				    __func__);
				ret = EINVAL;
				goto fail;
			}
			c->flags |= CTL_CONN_NOTIFY;
			break;
		case IMSG_CTL_VERBOSE:
			IMSG_SIZE_CHECK(&imsg, &v);
			memcpy(&v, imsg.data, sizeof(v));
			log_setverbose(v);
			imsg_forward_event(control_iev_parent, &imsg);
			break;
		case IMSG_GET_INFO_CONTROL_REQUEST:
			nci.verbose = log_getverbose();
			imsg_compose_event(&c->iev,
			    IMSG_GET_INFO_CONTROL_DATA, 0, 0, -1,
			    &nci, sizeof(struct thingsd_control_info));
			imsg_compose_event(&c->iev,
			    IMSG_GET_INFO_CONTROL_END_DATA, 0, 0, -1,
			    &nci, sizeof(struct thingsd_control_info));
			break;
		case IMSG_KILL_CLIENT:
		case IMSG_SHOW_PACKETS_REQUEST:
		case IMSG_GET_INFO_THINGSD_REQUEST:
		case IMSG_GET_INFO_THINGS_REQUEST:
		case IMSG_GET_INFO_CLIENTS_REQUEST:
		case IMSG_GET_INFO_SOCKETS_REQUEST:
			/* the conn fd is the peerid replies are routed by */
			imsg.hdr.peerid = fd;

			if (euid == 0 &&
			    imsg.hdr.type == IMSG_GET_INFO_THINGS_REQUEST)
				imsg.hdr.type = IMSG_GET_INFO_THINGS_REQUEST_ROOT;

			if (imsg.hdr.type == IMSG_GET_INFO_SOCKETS_REQUEST)
				c->pending_sockets = thingsd_env->prefork_socks;
			if (imsg.hdr.type == IMSG_GET_INFO_CLIENTS_REQUEST)
				c->pending_clients = thingsd_env->prefork_socks;

			if (imsg_forward_event(control_iev_parent,
			    &imsg) == -1) {
				imsg_free(&imsg);
				control_close(fd, cs);
				return;
			}
			break;
		default:
			log_debug("%s: error handling imsg %d",
			    __func__, imsg.hdr.type);
			imsg_free(&imsg);
			control_close(fd, cs);
			return;
		}
		imsg_free(&imsg);
	}

	imsg_event_add(&c->iev);
	return;

fail:
	imsg_free(&imsg);
	imsg_compose_event(&c->iev, IMSG_CTL_FAIL,
	    0, 0, -1, &ret, sizeof(ret));
	imsgbuf_flush(&c->iev.ibuf);
	control_close(fd, cs);
}

void
control_imsg_forward(struct imsg *imsg)
{
	struct ctl_conn *c;

	TAILQ_FOREACH(c, &ctl_conns, entry)
		if (c->flags & CTL_CONN_NOTIFY)
			imsg_compose_event(&c->iev, imsg->hdr.type,
			    imsg->hdr.peerid, imsg->hdr.pid, -1, imsg->data,
			    imsg->hdr.len - IMSG_HEADER_SIZE);
}
