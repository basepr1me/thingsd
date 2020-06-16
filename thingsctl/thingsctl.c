/*
 * Copyright (c) 2019 - 2020 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003 Henning Brauer <henning@openbsd.org>
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
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "thingsd.h"
#include "parser.h"

__dead void		 usage(void);
int			 show_list_msg(struct imsg *);
void			 print_clts(struct clt_imsg *);
void			 print_thgs(struct thg_imsg *);
void			 print_socks(struct sock_imsg *);

struct imsgbuf		*ibuf;

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-s socket] command [argument ...]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_un	 sun;
	struct parse_result	*res;
	struct imsg		 imsg;
	int			 ctl_sock;
	int			 done = 0;
	int			 n, verbose = 0;
	int			 ch;
	int			 type;
	char			*sockname, *ctl_pkt;

	sockname = strdup(THINGSD_SOCK);
	if (sockname == NULL)
		err(1, "strdup");
	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			sockname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Parse command line. */
	if ((res = parse(argc, argv)) == NULL)
		exit(1);

	/* Connect to control socket. */
	if ((ctl_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	strlcpy(sun.sun_path, sockname, sizeof(sun.sun_path));
	if (connect(ctl_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", sockname);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	if ((ibuf = malloc(sizeof(struct imsgbuf))) == NULL)
		err(1, NULL);
	imsg_init(ibuf, ctl_sock);
	done = 0;

	/* Check for root-only actions */
	switch (res->action) {
	case LOG_DEBUG:
	case LOG_VERBOSE:
	case LOG_BRIEF:
	case KILL_CLT:
	case SHOW_PKTS:
		if (geteuid() != 0)
			errx(1, "need root privileges");
		break;
	default:
		break;
	}

	/* Process user request. */
	switch (res->action) {
	case SHOW_PKTS:
		imsg_compose(ibuf, IMSG_SHOW_PKTS, 0, 0, -1,
		    res->thg_name, strlen(res->thg_name));
		free(res->thg_name);
		break;
	case KILL_CLT:
		imsg_compose(ibuf, IMSG_KILL_CLT, 0, 0, -1,
		    res->clt_name, strlen(res->clt_name));
		printf("kill request for client \"%s\" sent\n", res->clt_name);
		free(res->clt_name);
		done = 1;
		break;
	case LOG_DEBUG:
		verbose |= L_VERBOSE2;
		/* FALLTHROUGH */
	case LOG_VERBOSE:
		verbose |= L_VERBOSE1;
		/* FALLTHROUGH */
	case LOG_BRIEF:
		imsg_compose(ibuf, IMSG_THGS_LOG_VERBOSE, 0, 0, -1,
		    &verbose, sizeof(verbose));
		printf("logging request sent\n");
		done = 1;
		break;
	case LIST_CLTS:
		type = THGS_LIST_CLTS;
		imsg_compose(ibuf, IMSG_THGS_LIST, 0, 0, -1, &type,
		    sizeof(type));
		break;
	case LIST_THGS:
		type = THGS_LIST_THGS;
		imsg_compose(ibuf, IMSG_THGS_LIST, 0, 0, -1, &type,
		    sizeof(type));
		break;
	case LIST_SOCKS:
		type = THGS_LIST_SOCKS;
		imsg_compose(ibuf, IMSG_THGS_LIST, 0, 0, -1, &type,
		    sizeof(type));
		break;
	default:
		usage();
	}

	while (ibuf->w.queued)
		if (msgbuf_write(&ibuf->w) <= 0 && errno != EAGAIN)
			err(1, "write error");
	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			errx(1, "imsg_read error");
		if (n == 0)
			errx(1, "pipe closed");

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				errx(1, "imsg_get error");
			if (n == 0)
				break;

			switch (res->action) {
			case SHOW_PKTS:
				if (imsg.hdr.type == IMSG_CTL_END) {
					done = 1;
					break;
				}
				if ((ctl_pkt = calloc(IMSG_DATA_SIZE(imsg),
				    sizeof(*ctl_pkt))) == NULL)
					errx(1, "calloc ctl_pkt");
				if ((ctl_pkt = strndup(imsg.data,
				    IMSG_DATA_SIZE(imsg))) == NULL) {
					free(ctl_pkt);
					break;
				}
				printf("%s\n", ctl_pkt);
				free(ctl_pkt);
				break;
			case LIST_CLTS:
			case LIST_THGS:
			case LIST_SOCKS:
				done = show_list_msg(&imsg);
				break;
			default:
				break;
			}
			imsg_free(&imsg);
		}
	}
	close(ctl_sock);
	free(ibuf);
	free(sockname);

	return (0);
}

int
show_list_msg(struct imsg *imsg)
{
	struct clt_imsg		*comp_clt;
	struct thg_imsg		*comp_thg;
	struct sock_imsg	*comp_sock;

	switch (imsg->hdr.type) {
	case IMSG_LIST_CLTS:
		comp_clt = (struct clt_imsg *)imsg->data;
		print_clts(comp_clt);
		break;
	case IMSG_LIST_THGS:
		comp_thg = (struct thg_imsg *)imsg->data;
		print_thgs(comp_thg);
		break;
	case IMSG_LIST_SOCKS:
		comp_sock = (struct sock_imsg *)imsg->data;
		print_socks(comp_sock);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}
	return (0);
}

void
print_clts(struct clt_imsg *pclts)
{
	if (pclts->subscribed == false)
		return;

	printf("Client Name:\t\t\t%s\n", pclts->name);
	printf("\tfd:\t\t\t%d\n", pclts->fd);
	printf("\tPort:\t\t\t%d\n", pclts->port);
	if (pclts->tls == true)
		printf("\tTLS:\t\t\tyes\n");
	printf("\tSubscriptions:\t\t%zu\n", pclts->subs);
}

void
print_thgs(struct thg_imsg *pthgs)
{
	if (pthgs->exists == false)
		return;

	printf("Thing Name:\t\t\t%s\n", pthgs->name);
	switch(pthgs->type) {
	case TCP:
		printf("\tIP Addr:\t\t%s\n", pthgs->ipaddr);
		printf("\tConnect Port:\t\t%d\n", pthgs->conn_port);
		printf("\tPersists:\t\t%d\n", pthgs->persist);
		break;
	case UDP:
		printf("\tUDP Listener:\t\t%s\n", pthgs->udp);
		printf("\tConnect Port:\t\t%d\n", pthgs->conn_port);
		break;
	case DEV:
		printf("\tDevice:\t\t\t%s\n", pthgs->location);
		printf("\tBaud:\t\t\t%d\n", pthgs->baud);
		printf("\tData:\t\t\t%d\n", pthgs->data_bits);
		printf("\tStop:\t\t\t%d\n", pthgs->stop_bits);
		printf("\tHardware:\t\t%d\n", pthgs->hw_ctl);
		printf("\tSoftware:\t\t%d\n", pthgs->sw_ctl);
		printf("\tParity:\t\t\t%s\n", pthgs->parity);
		break;
	}
	if (strncmp(pthgs->iface, "", BUFF) == 0)
		printf("\tBind Interface:\t\tall\n");
	else
		printf("\tBind Interface:\t\t%s\n", pthgs->iface);
	printf("\tListen Port:\t\t%d\n", pthgs->port);
	if (pthgs->max_clt == 0)
		printf("\tMax Clients:\t\tunlimited\n");
	else
		printf("\tMax Clients:\t\t%d\n", pthgs->max_clt);
	printf("\tPassword:\t\t%s\n", pthgs->password);
	printf("\tClient Count:\t\t%zu\n", pthgs->clt_cnt);
	if (pthgs->tls == false)
		return;
	printf("\tTLS:\t\t\t%d\n", pthgs->tls);
	printf("\tCert:\t\t\t%s\n", pthgs->tls_cert_file);
	printf("\tKey:\t\t\t%s\n", pthgs->tls_key_file);
	printf("\tCA:\t\t\t%s\n", pthgs->tls_ca_file);
	printf("\tCRL:\t\t\t%s\n", pthgs->tls_crl_file);
	printf("\tOCSP:\t\t\t%s\n", pthgs->tls_ocsp_staple_file);
}

void
print_socks(struct sock_imsg *psocks)
{
	if (strcmp(psocks->name, "") == 0)
		printf("Socket Name:\t\t\tReceive socket\n");
	else
		printf("Socket Name:\t\t\t%s\n", psocks->name);
	printf("\tfd:\t\t\t%d\n", psocks->fd);
	printf("\tPort:\t\t\t%d\n", psocks->port);
	if (psocks->tls == true)
		printf("\tTLS:\t\t\tyes\n\n");
	printf("\tClient Count:\t\t%zu\n", psocks->clt_cnt);
	if (psocks->max_clts == 0)
		printf("\tMax Clients:\t\tunlimited\n");
	else
		printf("\tMax Clients:\t\t%zu\n", psocks->max_clts);
}
