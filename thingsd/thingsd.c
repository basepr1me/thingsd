/*
 * Copyright (c) 2016, 2019-2021 Tracey Emery <tracey@traceyemery.net>
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

#include "proc.h"
#include "thingsd.h"

__dead void usage(void);

int	 main(int, char **);

int	 thingsd_configure(struct thingsd *);
int	 thingsd_control_run(void);
int	 thingsd_dispatch_control(int, struct privsep_proc *, struct imsg *);
int	 thingsd_dispatch_sockets(int, struct privsep_proc *, struct imsg *);

void	 thingsd_sighdlr(int sig, short event, void *arg);
void	 thingsd_shutdown(struct thingsd *);
void	 thingsd_parent_shutdown(struct thingsd *);
void	 thingsd_configure_done(struct thingsd *);
void	 thingsd_thing_serial_open(struct thing *, int);
void	 thingsd_thing_setup(struct thingsd *, struct thing *, int);
void	 thingsd_show_info(struct privsep *, struct imsg *);
void	 thingsd_show_thing_info(struct privsep *, struct imsg *);
void	 thingsd_thing_udp_event(int, short, void *);
void	 thingsd_thing_read(struct bufferevent *, void *);
void	 thingsd_thing_write(struct bufferevent *, void *);
void	 thingsd_thing_err(struct bufferevent *, short, void *);
void	 thingsd_add_reconn(struct thing *);
void	 thingsd_do_reconn(struct thingsd *);
void	 thingsd_write_to_socks(struct packages *);
void	 thingsd_write_to_things(struct package *);
void	 thingsd_echo_pkt(struct privsep *, struct imsg *);
void	 thingsd_stop_pkt(struct privsep *, struct imsg *);

struct thing
	 thingsd_compose_thing(struct thing *, enum imsg_type);
struct	 dead_thing 
	*thingsd_new_dead_thing(struct thing *);

extern enum privsep_procid privsep_process;

struct thingsd	*thingsd_env;
int		 thing_id;


static struct privsep_proc procs[] = {
	{ "control",	PROC_CONTROL,	thingsd_dispatch_control, control },
	{ "sockets",	PROC_SOCKS,	thingsd_dispatch_sockets, sockets,
	    sockets_shutdown },
};

/* For the privileged process */
static struct privsep_proc *proc_priv = &procs[0];
static struct passwd proc_privpw;

int
thingsd_dispatch_control(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep	*ps = p->p_ps;
	int		 res = 0, cmd = 0, verbose, exists = 0;
	unsigned int	 v = 0;
	char		 thing_name[THINGSD_MAXNAME];
	struct thing	*thing;

	switch (imsg->hdr.type) {
	case IMSG_SHOW_PACKETS_END_DATA:
		IMSG_SIZE_CHECK(imsg, &v);
		if (imsg->data == NULL)
			break;
		thingsd_stop_pkt(ps, imsg);
		break;
	case IMSG_SHOW_PACKETS_REQUEST:
		IMSG_SIZE_CHECK(imsg, &v);
		if (imsg->data == NULL)
			break;
		memcpy(thing_name, imsg->data, sizeof(thing_name));
		TAILQ_FOREACH(thing, thingsd_env->things, entry) {
			if (strcmp(thing->conf.name, thing_name) == 0) {
				thingsd_echo_pkt(ps, imsg);
				exists = 1;
				break;
			}
		}
		if (!exists)
			if (proc_compose_imsg(ps, PROC_CONTROL, -1,
			    IMSG_BAD_THING,
			    imsg->hdr.peerid, -1, &res, sizeof(res)) == -1)
				return (-1);
		break;
	case IMSG_KILL_CLIENT:
		IMSG_SIZE_CHECK(imsg, &v);
		if (imsg->data == NULL)
			break;
		proc_forward_imsg(ps, imsg, PROC_SOCKS, -1);
		break;
	case IMSG_GET_INFO_CLIENTS_REQUEST:
		proc_forward_imsg(ps, imsg, PROC_SOCKS, -1);
		break;
	case IMSG_GET_INFO_SOCKETS_REQUEST:
		proc_forward_imsg(ps, imsg, PROC_SOCKS, -1);
		break;
	case IMSG_GET_INFO_THINGS_REQUEST:
	case IMSG_GET_INFO_THINGS_REQUEST_ROOT:
		thingsd_show_thing_info(ps, imsg);
		break;
	case IMSG_GET_INFO_THINGSD_REQUEST:
		thingsd_show_info(ps, imsg);
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		proc_forward_imsg(ps, imsg, PROC_SOCKS, -1);
		break;
	default:
		return (-1);
	}

	switch (cmd) {
	case 0:
		break;
	default:
		if (proc_compose_imsg(ps, PROC_CONTROL, -1, cmd,
		    imsg->hdr.peerid, -1, &res, sizeof(res)) == -1)
			return (-1);
		break;
	}

	return (0);
}

int
thingsd_dispatch_sockets(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct package		*package = NULL;
	struct privsep		*ps = p->p_ps;
	struct thingsd		*env = ps->ps_env;

	switch (imsg->hdr.type) {
	case  IMSG_DIST_CLIENT_PACKAGE:
		IMSG_SIZE_CHECK(imsg, package);
		package = (struct package *)imsg->data;
		thingsd_write_to_things(package);
		break;
	case IMSG_CFG_DONE:
		thingsd_configure_done(env);
		break;
	default:
		return (-1);
	}

	return (0);
}

void
thingsd_sighdlr(int sig, short event, void *arg)
{
	struct privsep	*ps = arg;

	if (privsep_process != PROC_PARENT)
		return;

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
		thingsd_shutdown(ps->ps_env);
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
	struct privsep		*ps;
	struct timeval		 eb_timeout;
	const char		*errp, *title = NULL;
	const char		*conffile = THINGSD_CONF;
	int			 proc_instance = 0;
	int			 ch;
	int			 argc0 = argc;
	enum privsep_procid	 proc_id = PROC_PARENT;

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("%s: calloc", __func__);

	while ((ch = getopt(argc, argv, "D:P:I:df:vn")) != -1) {
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
		case 'P':
			title = optarg;
			proc_id = proc_getid(procs, nitems(procs), title);
			if (proc_id == PROC_MAX)
				fatalx("invalid process name");
			break;
		case 'I':
			proc_instance = strtonum(optarg, 0,
			    PROC_MAX_INSTANCES, &errp);
			if (errp)
				fatalx("invalid process instance");
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

	if ((ps = calloc(1, sizeof(*ps))) == NULL)
		fatal("%s: calloc", __func__);

	thingsd_env = env;
	env->thingsd_ps = ps;
	ps->ps_env = env;
	TAILQ_INIT(&ps->ps_rcsocks);
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

	if ((ps->ps_pw = getpwnam(THINGSD_USER)) == NULL)
		fatal("unknown user %s", THINGSD_USER);


	/* First proc runs as root without pledge but in default chroot */
	proc_priv->p_pw = &proc_privpw; /* initialized to all 0 */
	proc_priv->p_chroot = ps->ps_pw->pw_dir; /* from THINGSD_USER */

	/* Configure the control socket */
	ps->ps_csock.cs_name = THINGSD_SOCKET;

	log_init(env->thingsd_debug, LOG_DAEMON);
	log_setverbose(env->thingsd_verbose);

	if (env->thingsd_noaction)
		ps->ps_noaction = 1;

	ps->ps_instances[PROC_SOCKS] = env->prefork_socks;
	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;

	/* only the thingsd returns */
	proc_init(ps, procs, nitems(procs), env->thingsd_debug, argc0,
	    argv, proc_id);

	log_procinit("thingsd");
	if (!env->thingsd_debug && daemon(0, 0) == -1)
		fatal("can't daemonize");

	if (ps->ps_noaction == 0)
		log_info("%s startup", getprogname());

	env->thingsd_eb = event_init();

	signal_set(&ps->ps_evsigint, SIGINT, thingsd_sighdlr, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, thingsd_sighdlr, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, thingsd_sighdlr, ps);
	signal_set(&ps->ps_evsigpipe, SIGPIPE, thingsd_sighdlr, ps);
	signal_set(&ps->ps_evsigusr1, SIGUSR1, thingsd_sighdlr, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsighup, NULL);
	signal_add(&ps->ps_evsigpipe, NULL);
	signal_add(&ps->ps_evsigusr1, NULL);

	if (!env->thingsd_noaction)
		proc_connect(ps);

	if (thingsd_configure(env) == -1)
		fatalx("configuration failed");

	/* begin thing watchdog */
	eb_timeout.tv_sec = EB_TIMEOUT;
	eb_timeout.tv_usec = 0;

	if (unveil(THINGSD_CONF, "r") == -1)
		err(1, "unveil");
	if (unveil("/dev", "rw") == -1)
		err(1, "unveil");
	if (unveil(NULL, NULL) != 0)
		err(1, "unveil");

	if (pledge("stdio rpath wpath inet proc tty dns", NULL) == -1)
		err(1, "pledge");

	env->run = 1;
	while (env->run) {
		if (env->exists)
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
	unsigned int		 id;

	if (env->thingsd_noaction) {
		fprintf(stderr, "configuration OK\n");
		proc_kill(env->thingsd_ps);
		exit(0);
	}

	env->socks_reload = env->prefork_socks;

	/* setup our things, which run privileged */
	TAILQ_FOREACH(thing, env->things, entry) {
		/* setup serial things */
		thingsd_thing_serial_open(thing, 0);

		/* setup udp/tcp things */
		thingsd_thing_setup(env, thing, 0);
	}


	TAILQ_FOREACH(sock, env->sockets, entry) {
		if (config_setsocks(env, sock) == -1)
			fatalx("%s: send socket error", __func__);
	}

	for (id = 0; id < PROC_MAX; id++) {
		if (id == privsep_process)
			continue;
		proc_compose(env->thingsd_ps, id, IMSG_CFG_DONE, NULL, 0);
	}

	return (0);
}

void
thingsd_configure_done(struct thingsd *env)
{
	unsigned int	 id;
	if (env->socks_reload == 0) {
		log_warnx("%s: configuration already finished", __func__);
		return;
	}

	env->socks_reload--;
	if (env->socks_reload == 0) {
		for (id = 0; id < PROC_MAX; id++) {
			if (id == privsep_process)
				continue;
			proc_compose(env->thingsd_ps, id, IMSG_CTL_START,
			    NULL, 0);
		}
	}
}

void
thingsd_shutdown(struct thingsd *env)
{
	proc_kill(env->thingsd_ps);
	control_cleanup(&env->thingsd_ps->ps_csock);

	thingsd_parent_shutdown(env);

	log_warnx("thingsd terminating");
	exit(0);
}

void
thingsd_show_info(struct privsep *ps, struct imsg *imsg)
{
	struct thingsd_thingsd_info	npi;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_THINGSD_REQUEST:
		npi.verbose = log_getverbose();
		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_GET_INFO_THINGSD_DATA, imsg->hdr.peerid,
		    -1, &npi, sizeof(npi)) == -1)
			return;
		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_GET_INFO_THINGSD_END_DATA, imsg->hdr.peerid,
		    -1, &npi, sizeof(npi)) == -1)
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

		if (event_initialized(&thing->udp_ev))
			event_del(&thing->udp_ev);

		if (thing->bev != NULL)
			bufferevent_disable(thing->bev, EV_READ | EV_WRITE);
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

	/* check if thing already exists */
	TAILQ_FOREACH(thing, env->things, entry) {
		if (strcmp(name, thing->conf.name) == 0)
			return (thing);
	}

	if ((thing = calloc(1, sizeof(*thing))) == NULL)
		fatal("%s: calloc", __func__);

	thing->conf.ipv4 = 1;
	thing->conf.id = id;

	TAILQ_INSERT_TAIL(env->things, thing, entry);

	return (thing);
}

void
thingsd_thing_serial_open(struct thing *thing, int reconn)
{
	struct dead_thing	*dead_thing;
	struct termios		 s_opts;
	int			 baudrate = 0, stop = 0;

	if (thing->conf.type == S_DEV) {

		/*
		 * Just a reminder to set the ownership of your serial
		 * devices to _thingsd. Otherwise, a thing will not be
		 * able to successfully open(2) the file descriptor.
		 */
		if ((thing->fd = open(thing->conf.location, O_RDWR |
		    O_NONBLOCK | O_NOCTTY | O_NDELAY)) == -1) {
			log_warnx("failed to open %s", thing->conf.location);

			if (reconn)
				return;

			dead_thing = thingsd_new_dead_thing(thing);

			thingsd_env->exists = 1;
			thingsd_env->dcount++;

			TAILQ_INSERT_TAIL(thingsd_env->dead_things,
			    dead_thing, entry);

			return;
		} else {
			/* load current s_opts */
			tcgetattr(thing->fd, &s_opts);

			/* set baud */
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

			/* set data bits */
			if (thing->conf.data_bits != -1) {
				s_opts.c_cflag &= ~CSIZE;
				switch(thing->conf.data_bits) {
				case 5:
					stop = CS5;
					break;
				case 6:
					stop = CS6;
					break;
				case 7:
					stop = CS7;
					break;
				case 8:
					stop = CS8;
					break;
				}
				s_opts.c_cflag |= stop;
			}

			/* set parity */
			if (strlen(thing->conf.parity) != 0) {
				s_opts.c_cflag &= ~PARENB;

				/* enable parity checking */
				if (strcmp(thing->conf.parity, "odd") == 0) {
					s_opts.c_cflag |= PARENB;
					s_opts.c_cflag |= PARODD;
					s_opts.c_iflag |= (INPCK |
					    ISTRIP);
				} else if (strcmp(thing->conf.parity,
				    "even") == 0) {
					s_opts.c_cflag |= PARENB;
					s_opts.c_cflag &= ~PARODD;
					s_opts.c_iflag |= (INPCK |
					    ISTRIP);
				}

			}

			/* set stop bits */
			if (thing->conf.stop_bits != -1) {
				if (thing->conf.stop_bits == 2)
					s_opts.c_cflag |= CSTOPB;
				else
					s_opts.c_cflag &= ~CSTOPB;
			}

			/* set hardware control */
			if (thing->conf.hw_ctl == 0) {
				s_opts.c_cflag &= ~CRTSCTS;
			} else {
				s_opts.c_cflag |= CRTSCTS;
			}

			/* set software control */
			if (thing->conf.sw_ctl == 0) {
				s_opts.c_iflag &= ~(IXON | IXOFF |
				    IXANY);
			} else {
				s_opts.c_iflag |= (IXON | IXOFF |
				    IXANY);
			}

			/* set input/output as raw */
			s_opts.c_lflag &= ~(ICANON | ECHO | ECHOE |
			    ISIG);

			s_opts.c_oflag &= ~OPOST;

			/* Set the new options for the port */
			tcsetattr(thing->fd, TCSANOW, &s_opts);

			if (thing->fd == '\0') {
				log_warnx("serial device not opened");
				if (reconn)
					return;
				thingsd_add_reconn(thing);
				return;
			}
			thing->exists = 1;
		}

		if (reconn && thing->exists)
			log_info("reconnected: %s", thing->conf.name);
	}
}

void
thingsd_thing_setup(struct thingsd *env, struct thing *thing, int reconn)
{
	evbuffercb		 thingrd = thingsd_thing_read;
	evbuffercb		 thingwr = thingsd_thing_write;

	if (thing->conf.type == S_TCP) {
		if (thing->conf.persist == 1) {
			if ((thing->fd = sockets_open_client(thing->conf.ipaddr,
			    &thing->conf.tcp_conn_port)) == -1) {
				log_warnx("%s: ipaddr connection failed",
				    __func__);
				if (reconn)
					return;
				thingsd_add_reconn(thing);
				return;
			}
		} else
			/* 0 indicates non-persistent socket */
			thing->fd = 0;
	}

	if (thing->conf.type == S_UDP) {
		if ((thing->fd = sockets_create_socket(thing->conf.udp_al,
		    thing->conf.udp_rcv_port, S_UDP)) == -1)
			fatalx("%s: create udp socket failed", __func__);
	}

	log_debug("%s: configuring thing %s (%d)", __func__, thing->conf.name,
	    thing->fd);

	if (thing->conf.type == S_UDP) {
		event_set(&thing->udp_ev, thing->fd, EV_READ |
		    EV_PERSIST, thingsd_thing_udp_event, thing);

		if (event_add(&thing->udp_ev, NULL))
			fatalx("%s: udp ev error", __func__);
	} else {
		thing->bev = bufferevent_new(thing->fd,
		    thingrd, thingwr, thingsd_thing_err, thing);

		if (thing->bev == NULL)
			fatalx("%s: ipaddr bev error", __func__);

		thing->evb = evbuffer_new();

		if (thing->evb == NULL)
			fatalx("ipaddr evb error");

		bufferevent_enable(thing->bev, EV_READ | EV_WRITE);
	}

	log_debug("%s: running thing %s", __func__, thing->conf.name);

	thing->conf.env = env;
	thing->exists = 1;

	if (reconn)
		log_info("reconnected: %s", thing->conf.name);
}

void
thingsd_write_to_things(struct package *package)
{
	struct thing		*thing = NULL;

	TAILQ_FOREACH(thing, thingsd_env->things, entry)
		if (thing->conf.id == package->thing_id)
			break;

	if (thing == NULL)
		return;

	switch (thing->conf.type) {
	case S_TCP:
	case S_DEV:
		if (thing->conf.persist == 0) {
			if ((thing->fd = sockets_open_client(thing->conf.ipaddr,
			    &thing->conf.tcp_conn_port)) == -1) {
				log_warnx("%s: temporary ipaddr connection"
				    " failed", __func__);
				return;
			}
			write(thing->fd, package->pkt, package->len);
			close(thing->fd);
			thing->fd = -1;
		} else {
			if (thing->fd != -1) {
				bufferevent_write(thing->bev, package->pkt,
				    package->len);
			}
		}
		break;
	case S_UDP:
	default:
		log_info("write %d bytes: %s", package->len, package->pkt);
		write(thing->fd, package->pkt, package->len);
		break;
	}
}

void
thingsd_write_to_socks(struct packages *packages)
{
	struct privsep		*ps = thingsd_env->thingsd_ps;
	struct package		*package, *tpkg, p;
	struct packet_client	*packet_client;
	struct thing		*thing = NULL;
	unsigned int		 id, what;
	int			 fd = -1, n, m;
	struct iovec		 iov[6];
	size_t			 c;

	TAILQ_FOREACH_SAFE(package, packages, entry, tpkg) {
		for (id = 0; id < PROC_MAX; id++) {
			what = ps->ps_what[id];

			if ((what & CONFIG_SOCKS) == 0 || id == privsep_process)
				continue;

			memcpy(&p, package, sizeof(p));

			c = 0;
			iov[c].iov_base = &p;
			iov[c++].iov_len = sizeof(p);
			if (id == PROC_SOCKS) {
			/* XXX imsg code will close the fd after 1st call */
				n = -1;
				proc_range(ps, id, &n, &m);
				for (n = 0; n < m; n++) {
					/* send thing fd */
					if (proc_composev_imsg(ps, id, n,
					    IMSG_DIST_THING_PACKAGE, -1, fd,
					    iov, c) != 0) {
						log_warn("%s: failed to compose"
						    " IMSG_DIST_THING_PACKAGE"
						    " imsg",
					    __func__);
					return;
					}
					if (proc_flush_imsg(ps, id, n) == -1) {
						log_warn("%s: failed to flush "
						    "IMSG_DIST_THING_PACKAGE "
						    "imsg",
						    __func__);
						return;
					}
				}
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
			if (strlen(packet_client->name) != 0) {
				if (strcmp(thing->conf.name,
				    packet_client->name) == 0)
					if (proc_compose_imsg(
					    &packet_client->ps,
					    PROC_CONTROL, -1,
					    IMSG_SHOW_PACKETS_DATA,
					    packet_client->imsg.hdr.peerid, -1,
					    package->pkt, package->len) == -1)
					break;
			}
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
	struct package		*package = NULL;


	if ((package = calloc(1, sizeof(*package))) == NULL)
		fatalx("%s: calloc", __func__);

	thing->evb = EVBUFFER_INPUT(bev);
	package->len = EVBUFFER_LENGTH(thing->evb);

	evbuffer_remove(thing->evb, package->pkt, package->len);
	package->thing_id = thing->conf.id;

	TAILQ_INSERT_TAIL(thingsd_env->packages, package, entry);
	thingsd_write_to_socks(thingsd_env->packages);
}

void
thingsd_thing_write(struct bufferevent *bev, void *arg)
{
}

void
thingsd_thing_err(struct bufferevent *bev, short error, void *arg)
{
	struct thing	*thing = (struct thing *)arg;

	if ((error & EVBUFFER_ERROR) == 0 || error & EVBUFFER_TIMEOUT) {
		if (thing->fd != -1) {
			if (thing->bev != NULL)
				bufferevent_disable(thing->bev,
				    EV_READ | EV_WRITE);
			if (thing->bev != NULL)
				bufferevent_free(thing->bev);

			thing->evb = NULL;
			thing->bev = NULL;

			close(thing->fd);
			thing->fd = -1;

			thingsd_add_reconn(thing);

			log_warnx("thing error: %s disconnected",
			    thing->conf.name);
		}
	}
}

void
thingsd_add_reconn(struct thing *thing)
{
	struct dead_thing	*dead_thing;

	dead_thing = thingsd_new_dead_thing(thing);

	thingsd_env->exists = 1;
	thingsd_env->dcount++;

	TAILQ_INSERT_TAIL(thingsd_env->dead_things, dead_thing, entry);

}

struct dead_thing
*thingsd_new_dead_thing(struct thing *thing)
{
	struct dead_thing	*dead_thing;

	dead_thing = calloc(1, sizeof(*dead_thing));
	if (dead_thing == NULL)
		fatal("%s: calloc", __func__);

	log_debug("%s: adding detached thing, %s", __func__, thing->conf.name);

	if (strlcpy(dead_thing->name, thing->conf.name,
	    sizeof(dead_thing->name)) >= sizeof(dead_thing->name))
		fatalx("%s: strlcpy", __func__);

	dead_thing->type = thing->conf.type;
	dead_thing->dtime = time(NULL);

	thing->exists = 0;

	return dead_thing;
}

void
thingsd_do_reconn(struct thingsd *env)
{
	struct dead_thing	*dead_thing = NULL;
	struct thing		*thing = NULL;
	int			 found = 0;

	TAILQ_FOREACH(thing, env->things, entry) {
		TAILQ_FOREACH(dead_thing, env->dead_things, entry)
			if (strcmp(thing->conf.name, dead_thing->name) == 0) {
				found = 1;
				break;
			}
		if (found)
			break;
	}

	if (thing == NULL || dead_thing == NULL)
		return;

	if ((size_t)(time(NULL) - dead_thing->dtime) > env->conn_retry) {
		dead_thing->dtime = time(NULL);

		log_debug("attempting to reconnect %s", dead_thing->name);

		if (dead_thing->type == S_DEV)
			thingsd_thing_serial_open(thing, 1);

		thingsd_thing_setup(env, thing, 1);
	}

	if (thing->exists) {
		TAILQ_REMOVE(env->dead_things, dead_thing, entry);
		env->dcount--;
		free(dead_thing);
	}

	if (env->dcount == 0)
		env->exists = 0;
}

void
thingsd_echo_pkt(struct privsep *ps, struct imsg *imsg)
{
	struct packet_client	*packet_client;

	packet_client = calloc(1, sizeof(*packet_client));
	if (packet_client == NULL)
		fatal("%s: calloc", __func__);

	thingsd_env->packet_client_count++;

	packet_client->ps = *ps;
	packet_client->imsg = *imsg;

	memcpy(packet_client->name, imsg->data,  sizeof(packet_client->name));

	log_debug("control packet echo request for %s", packet_client->name);

	TAILQ_INSERT_TAIL(thingsd_env->packet_clients, packet_client, entry);
}

void
thingsd_stop_pkt(struct privsep *ps, struct imsg *imsg)
{
	struct packet_client	*packet_client, *tpacket_client;
	uint32_t		 fd;

	memcpy(&fd, imsg->data, sizeof(fd));

	TAILQ_FOREACH_SAFE(packet_client, thingsd_env->packet_clients, entry,
	    tpacket_client) {
		if (fd == packet_client->imsg.hdr.peerid) {
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
thingsd_show_thing_info(struct privsep *ps, struct imsg *imsg)
{
	char filter[THINGSD_MAXNAME];
	struct thing *thing, nti;

	memcpy(filter, imsg->data, sizeof(filter));

	TAILQ_FOREACH(thing, thingsd_env->things, entry) {
		if (filter[0] == '\0' || strcmp(filter,
		    thing->conf.name) == 0) {
			nti = thingsd_compose_thing(thing,
			    imsg->hdr.type);

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

