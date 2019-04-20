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

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "thingsd.h"
#include "things.h"

struct thgsd		*pthgsd;
struct dthgs		*pdthgs;
struct imsgev		*iev_main;
struct ctl_pkt		*ctl_pkt;

void
thgs_sighdlr(int sig, short event, void *bula)
{
	struct dthgs		*zdthgs = (struct dthgs *)bula;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		thgs_shutdown(zdthgs);
	default:
		fatalx("unexpected signal");
	}
}

void
thgs_main(int debug, int verbose, char *thgs_sock)
{
	struct timeval		 eb_timeout;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((pthgsd = calloc(1, sizeof(*pthgsd))) == NULL)
		fatalx("no thgsd calloc");
	if ((pdthgs = calloc(1, sizeof(*pdthgs))) == NULL)
		fatalx("no dthgs calloc");
	if ((ctl_pkt = calloc(1, sizeof(*ctl_pkt))) == NULL)
		fatalx("no ctl_pkt calloc");
	if (parse_conf(PATH_CONF))
		fatalx("config parsing failed");

	thgsd_process = PROC_THGS;
	setproctitle("%s", log_procnames[thgsd_process]);
	log_procinit(log_procnames[thgsd_process]);

	if ((pthgsd->pw = getpwnam(TH_USER)) != NULL) {
		if(setuid(pthgsd->pw->pw_uid) != 0)
			log_warn("unable to set user id of %s: %s", TH_USER,
			    strerror(errno));
	}

	ctl_pkt->exists = false;
	ctl_pkt->pid = getppid();
	ctl_pkt->cpid = -1;

	pthgsd->thgs_eb = event_init();

	open_thgs(pthgsd, false);
	create_socks(pthgsd, false);

	pdthgs->run = 1;

	if (unveil("/dev", "rw") == -1)
		errx(1, "unveil");
	if (pledge("stdio rpath wpath inet proc tty dns", NULL) == -1)
		errx(1, "pledge");

	signal_set(&pthgsd->thgs_evsigquit, SIGQUIT, thgs_sighdlr, pdthgs);
	signal_set(&pthgsd->thgs_evsigterm, SIGTERM, thgs_sighdlr, pdthgs);
	signal_set(&pthgsd->thgs_evsigint, SIGINT, thgs_sighdlr, pdthgs);

	signal_add(&pthgsd->thgs_evsigquit, NULL);
	signal_add(&pthgsd->thgs_evsigterm, NULL);
	signal_add(&pthgsd->thgs_evsigint, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the parent process. */
	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_main->ibuf, PARENT_SOCK_FD);
	iev_main->handler = thgs_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	/* begin thing watchdog */
	eb_timeout.tv_sec = EB_TIMEOUT;
	eb_timeout.tv_usec = 0;

	while (pdthgs->run) {
		if (pthgsd->exists) {
			do_reconn();
		}
		if (getppid() == 1)
			break;
		event_base_loopexit(pthgsd->thgs_eb, &eb_timeout);
		event_base_dispatch(pthgsd->thgs_eb);
	}

	thgs_shutdown(pdthgs);
}

void
thgs_dispatch_main(int fd, short event, void *bula)
{
	struct clt		*clt;
	struct thg		*thg;
	struct imsg		 imsg;
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	enum thgs_list_type	 type;
	int			 n, shut = 0, verbose;
	bool			 tchk = true;

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
		case IMSG_SHOW_PKTS:
			TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
				if (strncmp(thg->name, imsg.data,
				    sizeof(imsg.data)) == 0) {
					if ((ctl_pkt->name =
					    strdup(imsg.data)) == NULL)
						break;
					ctl_pkt->exists = true;
					ctl_pkt->cpid = imsg.hdr.pid;
					tchk = false;
					break;
				}
			}
			if (tchk)
				thgs_imsg_compose_main(IMSG_CTL_END,
				    ctl_pkt->pid, NULL, 0);
			break;
		case IMSG_KILL_CLT:
			TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
				if (imsg.data == NULL)
					break;
				if (strncmp(clt->name, imsg.data, BUFF) == 0) {
					log_debug("Control killed client: %s",
					    imsg.data);
					clt_del(pthgsd, clt);
					break;
				}
			}
			break;
		case IMSG_THGS_LIST:
			if (IMSG_DATA_SIZE(imsg) != sizeof(type))
				fatalx("%s: IMSG_THGS_STATUS wrong length: %lu",
				    __func__, IMSG_DATA_SIZE(imsg));
			memcpy(&type, imsg.data, sizeof(type));
			show_list(type, imsg.hdr.pid);
			break;
		case IMSG_THGS_LOG_VERBOSE:
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
		pdthgs->run = 0;
	}
}

void
thgs_shutdown(struct dthgs *zdthgs)
{
	struct thg		*thg, *tthg;
	struct sock		*sock, *tsock;
	struct clt		*clt, *tclt;
	struct dthg		*dthg, *tdthg;

	zdthgs->run = 0;

	/* Close pipes. */
	msgbuf_write(&iev_main->ibuf.w);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);
	free(iev_main);

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
	log_debug("%s child exiting", getprogname());
	free(pdthgs);
	free(pthgsd);
	free(ctl_pkt);
	exit(0);
}

int
thgs_imsg_compose_main(int type, pid_t pid, void *data, uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data, datalen));
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
show_list(enum thgs_list_type type, pid_t pid)
{
	struct clt		*clt;
	struct thg		*thg;
	struct sock		*sock;
	struct clt_imsg		*clt_imsg;
	struct thg_imsg		*thg_imsg;
	struct sock_imsg	*sock_imsg;

	switch(type) {
	case THGS_LIST_CLTS:
		TAILQ_FOREACH(clt, &pthgsd->clts, entry) {
			clt_imsg = compose_clts(clt);
			thgs_imsg_compose_main(IMSG_LIST_CLTS, pid, clt_imsg,
			    sizeof(*clt_imsg));
			free(clt_imsg);
		}
		break;
	case THGS_LIST_THGS_ROOT:
	case THGS_LIST_THGS:
		TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
			thg_imsg = compose_thgs(thg, type);
			thgs_imsg_compose_main(IMSG_LIST_THGS, pid, thg_imsg,
			    sizeof(*thg_imsg));
			free(thg_imsg);
		}
		break;
	case THGS_LIST_SOCKS:
		TAILQ_FOREACH(sock, &pthgsd->socks, entry) {
			sock_imsg = compose_socks(sock);
			thgs_imsg_compose_main(IMSG_LIST_SOCKS, pid, sock_imsg,
			    sizeof(*sock_imsg));
			free(sock_imsg);
		}
		break;
	default:
		fatalx("unknown resolver type %d", type);
		break;
	}
	thgs_imsg_compose_main(IMSG_CTL_END, pid, NULL, 0);
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
compose_thgs(struct thg *pthg, int type)
{
	struct thg_imsg		*comp_thg;
	char			*blank = "********";

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
	if (pthg->password != NULL) {
		switch (type) {
		case THGS_LIST_THGS_ROOT:
			strlcpy(comp_thg->password, pthg->password, BUFF);
			break;
		case THGS_LIST_THGS:
			strlcpy(comp_thg->password, blank, BUFF);
			break;
		}
	}
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
