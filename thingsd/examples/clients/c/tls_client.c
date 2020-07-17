/*
 * Copyright (c) 2015 Bob Beck <beck@obtuse.com>
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

/* client.c  - the "classic" example of a socket client */
/*  edited to work with thingsd */

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>



static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s ipaddress portnumber certhash\n", __progname);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_sa;
	char buffer[80], *ep;
	size_t maxread;
	ssize_t r, rc;
	u_short port;
	u_long p;
	int sd, i, w, written;
	struct tls_config *tls_cfg = NULL;
	struct tls *tls_ctx = NULL;
	char pkt[] = "~~~subscribe{{name,\"thgtstr\"},{things{thing{\"thing2\",\"Mother\"}}}}";
	if (argc != 4)
		usage();

        p = strtoul(argv[2], &ep, 10);
        if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	/* now safe to do this */
	port = p;

	/*
	 * first set up "server_sa" to be the location of the thing socket
	 */
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(argv[1]);
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		usage();
	}

	/* now set up TLS */
	if (tls_init() == -1)
		errx(1, "unable to initialize TLS");
	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, "thing.crt") == -1)
		errx(1, "unable to set root CA file thing.crt");

	/* ok now get a socket. we don't care where... */
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed");

	/* connect the socket to the thing socket described in "server_sa" */
	if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
		err(1, "connect failed");

	if ((tls_ctx = tls_client()) == NULL)
		errx(1, "tls client creation failed");
	tls_config_insecure_noverifyname(tls_cfg);
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "tls configuration failed (%s)",
		    tls_error(tls_ctx));
	if (tls_connect_socket(tls_ctx, sd, "name") == -1) {
		errx(1, "tls connection failed (%s)",
		    tls_error(tls_ctx));
	}
	do {
		if ((i = tls_handshake(tls_ctx)) == -1)
			errx(1, "tls handshake failed (%s)",
			    tls_error(tls_ctx));
	} while (i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
	if (strcmp(argv[3], tls_peer_cert_hash(tls_ctx)) != 0)
		printf("Peer certificate is not %s\n", argv[3]);
		/* errx(1, "Peer certificate is not %s", argv[3]); */

	/*
	 * finally, we are connected. find out what magnificent wisdom
	 * our thing is going to send to us - since we really don't know
	 * how much data the thing could send to us, we have decided
	 * we'll stop reading when either our buffer is full, or when
	 * we get an end of file condition from the read when we read
	 * 0 bytes - which means that we pretty much assume the thing
	 * is going to send us an entire message, then close the connection
	 * to us, so that we see an end-of-file condition on the read.
	 *
	 * we also make sure we handle EINTR in case we got interrupted
	 * by a signal.
	 */
	w = 0;
	written = 0;
	while (written < strlen(pkt)) {
		w = tls_write(tls_ctx, pkt + written,
		    strlen(pkt) - written);
		if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
			continue;
		if (w < 0)
			errx(1, "tls_write failed (%s)", tls_error(tls_ctx));
		else
			written += w;
	}
	/* start receiving packets from thing */
	for(;;) {
		i = 0;
		r = -1;
		rc = 0;
		maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
		while ((r != 0) && rc < maxread) {
			r = tls_read(tls_ctx, buffer + rc, maxread - rc);
			if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
				continue;
			if (r < 0) {
				errx(1, "tls_read failed (%s)", tls_error(tls_ctx));
			} else {
				rc += r;
				break;
			}
		}
		/*
		 * we must make absolutely sure buffer has a terminating 0 byte
		 * if we are to use it as a C string
		 */
		buffer[rc] = '\0';
		printf("Thing sent:  %s\n",buffer);
	}
	do {
		i = tls_close(tls_ctx);
	} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
	close(sd);
	exit(0);
	return(0);
}
