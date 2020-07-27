/*
 * Copyright (c) 2016, 2019, 2020 Tracey Emery <tracey@traceyemery.net>
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
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <util.h>

#include "proc.h"
#include "thingsd.h"

__dead void usage(void);

int	 main(int, char **);
int	 thingsd_configure(struct privsep *);
void	 thingsd_sighdlr(int sig, short event, void *arg);
void	 thingsd_shutdown(void);
int	 thingsd_control_run(void);
int	 thingsd_dispatch_control(int, struct privsep_proc *, struct imsg *);
int	 thingsd_dispatch_things(int, struct privsep_proc *, struct imsg *);
void	 thingsd_configure_things(struct privsep *);

void	 thingsd_show_info(struct privsep *, struct imsg *);

struct thingsd	*thingsd_env;

static struct privsep_proc procs[] = {
	{ "control",	PROC_CONTROL,	thingsd_dispatch_control, control },
	{ "things",	PROC_THINGS,	thingsd_dispatch_things, things,
	    things_shutdown },
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
	char		 client_name[THINGSD_MAXNAME];
	char		 thing_name[THINGSD_MAXNAME];
	struct client	*client;
	struct thing	*thing;

	switch (imsg->hdr.type) {
	case IMSG_SHOW_PACKETS_END_DATA:
		IMSG_SIZE_CHECK(imsg, &v);
		if (imsg->data == NULL)
			break;
		things_stop_pkt(ps, imsg);
		break;
	case IMSG_SHOW_PACKETS_REQUEST:
		IMSG_SIZE_CHECK(imsg, &v);
		if (imsg->data == NULL)
			break;
		memcpy(thing_name, imsg->data, sizeof(thing_name));
		TAILQ_FOREACH(thing, thingsd_env->things, entry) {
			if (strcmp(thing->name, thing_name) == 0) {
				things_echo_pkt(ps, imsg);
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
		memcpy(client_name, imsg->data, sizeof(client_name));
		TAILQ_FOREACH(client, thingsd_env->clients, entry) {
			if (strcmp(client->name, client_name) == 0) {
				log_debug("Control killed client: %s",
				    client_name);
				client_del(thingsd_env, client);
				break;
			}
		}
		break;
	case IMSG_GET_INFO_CLIENTS_REQUEST:
		clients_show_info(ps, imsg);
		break;
	case IMSG_GET_INFO_SOCKETS_REQUEST:
		sockets_show_info(ps, imsg);
		break;
	case IMSG_GET_INFO_THINGS_REQUEST:
	case IMSG_GET_INFO_THINGS_REQUEST_ROOT:
		things_show_info(ps, imsg);
		break;
	case IMSG_GET_INFO_PARENT_REQUEST:
		thingsd_show_info(ps, imsg);
		break;
	case IMSG_CTL_RESET:
		IMSG_SIZE_CHECK(imsg, &v);
		memcpy(&v, imsg->data, sizeof(v));
		thingsd_reload(v);
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);

		proc_forward_imsg(ps, imsg, PROC_THINGS, -1);
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
thingsd_dispatch_things(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep		*ps = p->p_ps;

	switch (imsg->hdr.type) {
	case IMSG_ADD_THING:
		proc_forward_imsg(ps, imsg, PROC_CONTROL, -1);
		break;
	default:
		return (-1);
	}

	return (0);
}

void
thingsd_sighdlr(int sig, short event, void *arg)
{
	if (privsep_process != PROC_PARENT)
		return;

	switch (sig) {
	case SIGHUP:
		log_info("%s: reload requested with SIGHUP", __func__);

		/*
		 * This is safe because libevent uses async signal handlers
		 * that run in the event loop and not in signal context.
		 */
		thingsd_reload(0);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		thingsd_shutdown();
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
	int			 ch;
	const char		*conffile = THINGSD_CONF;
	enum privsep_procid	 proc_id = PROC_PARENT;
	int			 proc_instance = 0;
	const char		*errp, *title = NULL;
	int			 argc0 = argc;

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("%s: calloc", __func__);

	thingsd_env = env;

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

	argc -= optind;
	if (argc > 0)
		usage();

	if (env->thingsd_noaction && !env->thingsd_debug)
		env->thingsd_debug = 1;

	/* check for root privileges */
	if (env->thingsd_noaction == 0) {
		if (geteuid())
			fatalx("need root privileges");
	}

	ps = &env->thingsd_ps;
	ps->ps_env = env;

	if (config_init(env) == -1)
		fatal("failed to initialize configuration");

	if ((ps->ps_pw = getpwnam(THINGSD_USER)) == NULL)
		fatal("unknown user %s", THINGSD_USER);

	env->thingsd_conffile = conffile;

	if (parse_config(env->thingsd_conffile) == -1)
		exit(1);

	/* First proc runs as root without pledge but in default chroot */
	proc_priv->p_pw = &proc_privpw; /* initialized to all 0 */
	proc_priv->p_chroot = ps->ps_pw->pw_dir; /* from THINGSD_USER */

	/* Configure the control socket */
	ps->ps_csock.cs_name = THINGSD_SOCKET;
	TAILQ_INIT(&ps->ps_rcsocks);

	log_init(env->thingsd_debug, LOG_DAEMON);
	log_setverbose(env->thingsd_verbose);

	if (env->thingsd_noaction)
		ps->ps_noaction = 1;

	ps->ps_instances[PROC_THINGS] = env->prefork_things;
	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;

	/* only the parent returns */
	proc_init(ps, procs, nitems(procs), argc0, argv, proc_id);

	log_procinit("parent");
	if (!env->thingsd_debug && daemon(0, 0) == -1)
		fatal("can't daemonize");

	if (ps->ps_noaction == 0)
		log_info("%s startup", getprogname());

	env->things_eb = event_init();

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

	if (thingsd_configure(ps) == -1)
		fatalx("configuration failed");

	/* begin thing watchdog */
	eb_timeout.tv_sec = EB_TIMEOUT;
	eb_timeout.tv_usec = 0;

	while (env->dead_things->run) {
		if (env->exists) {
			do_reconn();
		}
		event_base_loopexit(env->things_eb, &eb_timeout);
		event_base_dispatch(env->things_eb);
	}

	log_debug("%s parent exiting", getprogname());

	return (0);
}

int
thingsd_configure(struct privsep *ps)
{
	if (unveil(THINGSD_CONF, "r") == -1)
		err(1, "unveil");
	if (unveil("/dev", "rw") == -1)
		err(1, "unveil");
	if (unveil(NULL, NULL) != 0)
		err(1, "unveil");

	if (pledge("stdio rpath wpath inet proc tty dns", NULL) == -1)
		err(1, "pledge");

	if (parse_config(thingsd_env->thingsd_conffile) == -1) {
		proc_kill(&thingsd_env->thingsd_ps);
		exit(1);
	}

	if (thingsd_env->thingsd_noaction) {
		fprintf(stderr, "configuration OK\n");
		proc_kill(&thingsd_env->thingsd_ps);
		exit(0);
	}

	thingsd_configure_things(ps);

	return (0);
}

void
thingsd_reload(int reset)
{
	const char *filename = thingsd_env->thingsd_conffile;

	log_warnx("%s: reload config file %s", __func__, filename);

	things_reset();

	/* Purge the existing configuration. */
	config_purge(thingsd_env, reset);
	config_setreset(thingsd_env, reset);

	if (parse_config(thingsd_env->thingsd_conffile) == -1) {
		log_warnx("%s: failed to reload config file %s",
		    __func__, filename);
	}

	thingsd_configure_things(&thingsd_env->thingsd_ps);
}

void
thingsd_shutdown(void)
{
	proc_kill(&thingsd_env->thingsd_ps);
	free(thingsd_env);

	log_warnx("parent terminating");
	exit(0);
}

void
thingsd_show_info(struct privsep *ps, struct imsg *imsg)
{
	struct thingsd_parent_info	npi;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_PARENT_REQUEST:
		npi.verbose = log_getverbose();
		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_GET_INFO_PARENT_DATA, imsg->hdr.peerid,
		    -1, &npi, sizeof(npi)) == -1)
			return;
		if (proc_compose_imsg(ps, PROC_CONTROL, -1,
		    IMSG_GET_INFO_PARENT_END_DATA, imsg->hdr.peerid,
		    -1, &npi, sizeof(npi)) == -1)
			return;
		break;
	default:
		log_debug("%s: error handling imsg", __func__);
		break;
	}
}

void
thingsd_configure_things(struct privsep *ps)
{
	struct thing	*thing, nti;
	size_t		 n;

	open_things(thingsd_env, false);
	create_sockets(thingsd_env, false);

	start_client_chk(thingsd_env);

	/* Send configured things to things. */
	TAILQ_FOREACH(thing, thingsd_env->things, entry) {
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
			fatalx("%s: nti.parity name too long", __func__);

		n = strlcpy(nti.name, thing->name, sizeof(nti.name));
		if (n >= sizeof(nti.name))
			fatalx("%s: nti.name too long", __func__);

		n = strlcpy(nti.password, thing->password,
		    sizeof(nti.password));
		if (n >= sizeof(nti.password))
			fatalx("%s: nti.password too long", __func__);

		n = strlcpy(nti.location, thing->location,
		    sizeof(nti.location));
		if (n >= sizeof(nti.location))
			fatalx("%s: nti.location too long", __func__);

		n = strlcpy(nti.udp, thing->udp, sizeof(nti.udp));
		if (n >= sizeof(nti.udp))
			fatalx("%s: nti.name too long", __func__);

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

		n = strlcpy(nti.tls_ocsp_staple_file,
		    thing->tls_ocsp_staple_file,
		    sizeof(nti.tls_ocsp_staple_file));
		if (n >= sizeof(nti.tls_ocsp_staple_file))
			fatalx("%s: nti.tls_ocsp_staple_file too long",
			    __func__);

		proc_compose(ps, PROC_THINGS, IMSG_ADD_THING,
		    &nti, sizeof(nti));
	}
}
