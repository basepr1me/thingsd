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
	char			*sockname;

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
		err(1, NULL);
	imsg_init(ibuf, ctl_sock);
	done = 0;

	/* Process user request. */
	switch (res->action) {
	case LIST_THINGS:
		imsg_compose(ibuf, IMSG_GET_INFO_THINGS_REQUEST, 0,
		    0, -1, res->name, sizeof(res->name));
		break;
	case LOG_BRIEF:
		imsg_compose(ibuf, IMSG_CTL_VERBOSE, 0, 0, -1,
		    &verbose, sizeof(verbose));
		printf("logging request sent.\n");
		done = 1;
		break;
	case LOG_VERBOSE:
		verbose = 1;
		/* FALLTHROUGH */
	case SHOW_CONTROL:
		imsg_compose(ibuf, IMSG_GET_INFO_CONTROL_REQUEST, 0,
		    0, -1, NULL, 0);
		break;
	case SHOW_PARENT:
		imsg_compose(ibuf, IMSG_GET_INFO_PARENT_REQUEST, 0,
		    0, -1, NULL, 0);
		break;
	case SHOW_THING:
		break;
	case RESET:
		imsg_compose(ibuf, IMSG_CTL_RESET, 0, 0, -1, &v, sizeof(v));
		printf("reset request sent.\n");
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
		if (n == 0)
			errx(1, "pipe closed");

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				errx(1, "imsg_get error");
			if (n == 0)
				break;

			switch (res->action) {
			case LIST_THINGS:
				done = list_things_msg(&imsg);
				break;
			case SHOW_PARENT:
				done = show_parent_msg(&imsg);
				break;
			case SHOW_CONTROL:
				done = show_control_msg(&imsg);
				break;
			default:
				break;
			}
			imsg_free(&imsg);
		}
	}
	close(ctl_sock);
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
		printf("parent says: '%s' (%s)\n", npi->text,
		    npi->verbose ? "verbose" : "brief");
		break;
	case IMSG_GET_INFO_PARENT_END_DATA:
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}

int
list_things_msg(struct imsg *imsg)
{
	struct thing *nei;

	switch (imsg->hdr.type) {
	case IMSG_GET_INFO_THINGS_DATA:
		nei = (struct thing *) imsg->data;
		printf("Thing: '%s'\n", nei->name);
		printf("\tPassword: %s\n", nei->password);
		printf("\n");
		break;
	case IMSG_GET_INFO_THINGS_END_DATA:
	case IMSG_CTL_END:
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
		printf("control says: '%s'",
		    nci->verbose ? "verbose" : "brief");
		printf("\n");
		break;
	case IMSG_GET_INFO_CONTROL_END_DATA:
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}

	return (0);
}
