/*
 * Copyright (c) 2019, 2020 Tracey Emery <tracey@traceyemery.net>
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
#include <net/if_media.h>
#include <net/if_types.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proc.h"
#include "thingsd.h"
#include "parser.h"

__dead void	 usage(void);
int		 list_things_msg(struct imsg *);
int		 list_clients_msg(struct imsg *);
int		 list_sockets_msg(struct imsg *);
int		 show_parent_msg(struct imsg *);
int		 show_control_msg(struct imsg *);

struct imsgbuf	*ibuf;

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
	int			 ch, v = 0;
	char			*sockname, *ctl_pkt = NULL;

	sockname = THINGSD_SOCKET;
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
		err(1, "%s: malloc", __func__);
	imsg_init(ibuf, ctl_sock);
	done = 0;

	/* Check for root only actions */
	switch (res->action) {
	case LOG_DEBUG:
	case LOG_VERBOSE:
	case LOG_BRIEF:
	case KILL_CLIENT:
	case SHOW_PACKETS:
		/* if (geteuid() != 0) */
		/* 	errx(1, "need root privileges"); */
		break;
	default:
		break;
	}

	/* Process user request. */
	switch (res->action) {
	case KILL_CLIENT:
		imsg_compose(ibuf, IMSG_KILL_CLIENT, 0, 0, -1,
		    res->name, strlen(res->name));
		printf("\nKill request sent for client '%s'.\n", res->name);
		done = 1;
		break;
	case LIST_CLIENTS:
		imsg_compose(ibuf, IMSG_GET_INFO_CLIENTS_REQUEST, 0,
		    0, -1, res->name, sizeof(res->name));
		break;
	case LIST_SOCKETS:
		imsg_compose(ibuf, IMSG_GET_INFO_SOCKETS_REQUEST, 0,
		    0, -1, res->name, sizeof(res->name));
		break;
	case LIST_THINGS:
		imsg_compose(ibuf, IMSG_GET_INFO_THINGS_REQUEST, 0,
		    0, -1, res->name, sizeof(res->name));
		break;
	case LOG_DEBUG:
		verbose++;
		/* FALLTHROUGH */
	case LOG_VERBOSE:
		verbose++;
		/* FALLTHROUGH */
	case LOG_BRIEF:
		imsg_compose(ibuf, IMSG_CTL_VERBOSE, 0, 0, -1,
		    &verbose, sizeof(verbose));
		printf("\nLogging request sent.\n");
		done = 1;
		break;
	case SHOW_CONTROL:
		imsg_compose(ibuf, IMSG_GET_INFO_CONTROL_REQUEST, 0,
		    0, -1, NULL, 0);
		break;
	case SHOW_PACKETS:
		printf("\nEchoing thing packets may have unexcpected ");
		printf("consequences!\n");
		printf("Are you sure you want to echo packets? (y|n) ");
		ch = getchar();
		if (ch == 'y' || ch == 'Y') {
			printf("Waiting for incoming packets\n");
			imsg_compose(ibuf, IMSG_SHOW_PACKETS_REQUEST, 0,
			    0, -1, res->name, sizeof(res->name));
		} else {
			printf("Echo packets ignored\n");
			done = 1;
		}
		printf("\n");
		break;
	case SHOW_PARENT:
		imsg_compose(ibuf, IMSG_GET_INFO_PARENT_REQUEST, 0,
		    0, -1, NULL, 0);
		break;
	case RELOAD:
		printf("\nAll things and sockets will be reset.\n");
		printf("This can have unintended consequences!\n");
		printf("For example, all clients will have to reconnect.\n\n");
		printf("Are you sure you want to reload the config? (y|n) ");
		ch = getchar();
		if (ch == 'y' || ch == 'Y') {
			imsg_compose(ibuf, IMSG_CTL_RESET, 0, 0, -1, &v,
			    sizeof(v));
			printf("Reload request sent\n");
		} else
			printf("Reload request ignored\n");
		printf("\n");
		done = 1;
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
		if (n == 0) {
			if (res->action == SHOW_PACKETS)
				errx(1, "Bad thing name request, or thingsd " \
				    "shutdown.\n");
			else
				errx(1, "pipe closed");
		}

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				errx(1, "imsg_get error");
			if (n == 0)
				break;

			switch (res->action) {
			case LIST_CLIENTS:
				done = list_clients_msg(&imsg);
				break;
			case LIST_SOCKETS:
				done = list_sockets_msg(&imsg);
				break;
			case LIST_THINGS:
				done = list_things_msg(&imsg);
				break;
			case SHOW_CONTROL:
				done = show_control_msg(&imsg);
				break;
			case SHOW_PACKETS:
				if (imsg.hdr.type ==
				    IMSG_SHOW_PACKETS_END_DATA) {
					done = 1;
					break;
				}
				if ((ctl_pkt = calloc(IMSG_DATA_SIZE(&imsg),
				    sizeof(*ctl_pkt))) == NULL)
					err(1, "%s: calloc", __func__);
				if ((ctl_pkt = strndup(imsg.data,
				    IMSG_DATA_SIZE(&imsg))) == NULL) {
					free(ctl_pkt);
					break;
				}
				printf("%s\n", ctl_pkt);
				free(ctl_pkt);
				ctl_pkt = NULL;
				break;
			case SHOW_PARENT:
				done = show_parent_msg(&imsg);
				break;
			default:
				break;
			}
			imsg_free(&imsg);
		}
	}
	printf("\n");
	close(ctl_sock);
	free(ctl_pkt);
	free(ibuf);

	return (0);
}

int
show_parent_msg(struct imsg *imsg)
{
	struct thingsd_parent_info *npi;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_PARENT_DATA:
		npi = imsg->data;
		printf("\nParent says: Logging level is ");
		if (npi->verbose == 2)
			printf("debug");
		else if (npi->verbose == 1)
			printf("verbose");
		else
			printf("brief");
		printf(" (%d).\n", npi->verbose);
		break;
	case IMSG_GET_INFO_PARENT_END_DATA:
		return (1);
	default:
		break;
	}

	return (0);
}

int
show_control_msg(struct imsg *imsg)
{
	struct thingsd_control_info *nci;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_CONTROL_DATA:
		nci = imsg->data;
		printf("\nControl says: Logging level is ");
		if (nci->verbose == 2)
			printf("debug");
		else if (nci->verbose == 1)
			printf("verbose");
		else
			printf("brief");
		printf(" (%d).\n", nci->verbose);
		break;
	case IMSG_GET_INFO_CONTROL_END_DATA:
		return (1);
	default:
		break;
	}

	return (0);
}

int
list_things_msg(struct imsg *imsg)
{
	struct thing	*nti;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_THINGS_DATA:
		nti = (struct thing *) imsg->data;

		printf("\nThing Name:\t\t\t%s\n", nti->name);
		switch(nti->type) {
		case TCP:
			printf("\tIP Addr:\t\t%s\n", nti->ipaddr);
			printf("\tConnect Port:\t\t%d\n", nti->conn_port);
			printf("\tPersists:\t\t%d\n", nti->persist);
			break;
		case UDP:
			printf("\tUDP Listener:\t\t%s\n", nti->udp);
			printf("\tConnect Port:\t\t%d\n", nti->rcv_port);
			break;
		case DEV:
			printf("\tDevice:\t\t\t%s\n", nti->location);
			printf("\tBaud:\t\t\t%d\n", nti->baud);
			printf("\tData:\t\t\t%d\n", nti->data_bits);
			printf("\tStop:\t\t\t%d\n", nti->stop_bits);
			printf("\tHardware:\t\t%d\n", nti->hw_ctl);
			printf("\tSoftware:\t\t%d\n", nti->sw_ctl);
			printf("\tParity:\t\t\t%s\n", nti->parity);
			break;
	}
		if (strncmp(nti->iface, "", PKT_BUFF) == 0)
			printf("\tBind Interface:\t\tall\n");
		else
			printf("\tBind Interface:\t\t%s\n", nti->iface);
		printf("\tListen Port:\t\t%d\n", nti->port);
		if (nti->max_clients == 0)
			printf("\tMax Clients:\t\tunlimited\n");
		else
			printf("\tMax Clients:\t\t%d\n", nti->max_clients);
		printf("\tPassword:\t\t%s\n", nti->password);
		printf("\tClient Count:\t\t%zu\n", nti->client_cnt);
		if (nti->tls == false)
			break;
		printf("\tTLS:\t\t\t%d\n", nti->tls);
		printf("\tCert:\t\t\t%s\n", nti->tls_cert_file);
		printf("\tKey:\t\t\t%s\n", nti->tls_key_file);
		printf("\tCA:\t\t\t%s\n", nti->tls_ca_file);
		printf("\tCRL:\t\t\t%s\n", nti->tls_crl_file);
		printf("\tOCSP:\t\t\t%s\n", nti->tls_ocsp_staple_file);

		break;
	case IMSG_GET_INFO_THINGS_END_DATA:
		return (1);
	default:
		break;
	}

	return (0);
}

int
list_clients_msg(struct imsg *imsg)
{
	struct client	*nci;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_CLIENTS_DATA:
		nci = (struct client *) imsg->data;

		if (nci->subscribed == false)
			break;

		printf("\nClient Name:\t\t\t%s\n", nci->name);
		printf("\tfd:\t\t\t%d\n", nci->fd);
		printf("\tPort:\t\t\t%d\n", nci->port);
		if (nci->tls == true)
			printf("\tTLS:\t\t\tyes\n");
		printf("\tSubscriptions:\t\t%zu\n", nci->subs);
		break;
	case IMSG_GET_INFO_CLIENTS_END_DATA:
		return (1);
	default:
		break;
	}

	return (0);
}

int
list_sockets_msg(struct imsg *imsg)
{
	struct socket	*nsi;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_SOCKETS_DATA:
		nsi = (struct socket *) imsg->data;

		printf("\n");
		if (strcmp(nsi->name, "") == 0)
			printf("Socket Name:\t\t\tReceive socket\n");
		else
			printf("Socket Name:\t\t\t%s\n", nsi->name);
		printf("\tfd:\t\t\t%d\n", nsi->fd);
		printf("\tPort:\t\t\t%d\n", nsi->port);
		if (nsi->tls == true)
			printf("\tTLS:\t\t\tyes\n\n");
		printf("\tClient Count:\t\t%zu\n", nsi->client_cnt);
		if (nsi->max_clients == 0)
			printf("\tMax Clients:\t\tunlimited\n");
		else
			printf("\tMax Clients:\t\t%zu\n", nsi->max_clients);
		break;
	case IMSG_GET_INFO_SOCKETS_END_DATA:
		return (1);
	default:
		break;
	}

	return (0);
}
