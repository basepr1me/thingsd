/*
 * Copyright (c) 2019 - 2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2006 - 2015 Reyk Floeter <reyk@openbsd.org>
 * 	(snippets from httpd functions)
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
#include <sys/wait.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <event.h>
#include <imsg.h>
#include <event.h>
#include <tls.h>

#include "proc.h"
#include "thingsd.h"

int
tls_load_keypair(struct socket *sock)
{
	if (sock->conf.tls == 0)
		return (0);

	sock->conf.tls_cert = tls_load_file(sock->conf.tls_cert_file,
	    &sock->conf.tls_cert_len, NULL);
	if (sock->conf.tls_cert == NULL)
		return (-1);

	log_debug("%s: using certificate %s", __func__,
	    sock->conf.tls_cert_file);

	/* XXX allow to specify password for encrypted key */
	sock->conf.tls_key = tls_load_file(sock->conf.tls_key_file,
	    &sock->conf.tls_key_len, NULL);
	if (sock->conf.tls_key == NULL)
		return (-1);

	log_debug("%s: using private key %s", __func__,
	    sock->conf.tls_key_file);

	return (0);
}

int
tls_load_ca(struct socket *sock)
{
	if ((sock->conf.tls_flags & TLSFLAG_CA) == 0 ||
	    sock->conf.tls_ca_file == NULL)
		return (0);

	sock->conf.tls_ca = tls_load_file(sock->conf.tls_ca_file,
	    &sock->conf.tls_ca_len, NULL);
	if (sock->conf.tls_ca == NULL)
		return (-1);

	log_debug("%s: using ca cert(s) from %s", __func__,
	    sock->conf.tls_ca_file);

	return (0);
}

int
tls_load_ocsp(struct socket *sock)
{
	if (sock->conf.tls == 0)
		return (0);

	if (sock->conf.tls_ocsp_staple_file == NULL)
		return (0);

	sock->conf.tls_ocsp_staple = tls_load_file(
	    sock->conf.tls_ocsp_staple_file,
	    &sock->conf.tls_ocsp_staple_len, NULL);
	if (sock->conf.tls_ocsp_staple == NULL) {
		log_warnx("%s: Failed to load ocsp staple from %s", __func__,
		    sock->conf.tls_ocsp_staple_file);
		return (-1);
	}

	if (sock->conf.tls_ocsp_staple_len == 0) {
		log_warnx("%s: ignoring 0 length ocsp staple from %s", __func__,
		    sock->conf.tls_ocsp_staple_file);
		return (0);
	}

	log_debug("%s: using ocsp staple from %s", __func__,
	    sock->conf.tls_ocsp_staple_file);

	return (0);
}

int
tls_load_crl(struct socket *sock)
{
	if ((sock->conf.tls_flags & TLSFLAG_CA) == 0 ||
	    sock->conf.tls_crl_file == NULL)
		return (0);

	sock->conf.tls_crl = tls_load_file(sock->conf.tls_crl_file,
	    &sock->conf.tls_crl_len, NULL);
	if (sock->conf.tls_crl == NULL)
		return (-1);

	log_debug("%s: using crl(s) from %s", __func__,
	    sock->conf.tls_crl_file);

	return (0);
}

int
socket_tls_init(struct socket *sock)
{
	if (sock->conf.tls == 0)
		return 0;

	if (sock->conf.tls_cert == NULL)
		/*
		 * hard fail if cert is not there yet
		 * we don't check again
		 */
		return (-1);

	log_debug("%s: initializing tls for %d", __func__, sock->conf.id);

	if (tls_init() != 0) {
		log_warnx("%s: failed to initialise tls", __func__);
		return (-1);
	}

	sock->tls_config = tls_config_new();
	if (sock->tls_config == NULL) {
		log_warnx("%s: failed to get tls config", __func__);
		return (-1);
	}

	sock->tls_ctx = tls_server();
	if (sock->tls_ctx == NULL) {
		log_warnx("%s: failed to get tls server", __func__);
		return (-1);
	}

	if (tls_config_set_protocols(sock->tls_config,
	    sock->conf.tls_protocols) != 0) {
		log_warnx("%s: failed to set tls protocols: %s", __func__,
		    tls_config_error(sock->tls_config));
		return (-1);
	}

	if (tls_config_set_ciphers(sock->tls_config,
	    sock->conf.tls_ciphers) != 0) {
		log_warnx("%s: failed to set tls ciphers: %s", __func__,
		    tls_config_error(sock->tls_config));
		return (-1);
	}

	if (tls_config_set_dheparams(sock->tls_config,
	    sock->conf.tls_dhe_params) != 0) {
		log_warnx("%s: failed to set tls dhe params: %s", __func__,
		    tls_config_error(sock->tls_config));
		return (-1);
	}

	if (tls_config_set_ecdhecurves(sock->tls_config,
	    sock->conf.tls_ecdhe_curves) != 0) {
		log_warnx("%s: failed to set tls ecdhe curves: %s", __func__,
		    tls_config_error(sock->tls_config));
		return (-1);
	}

	if (tls_config_set_keypair_ocsp_mem(sock->tls_config,
	    sock->conf.tls_cert, sock->conf.tls_cert_len,
	    sock->conf.tls_key, sock->conf.tls_key_len,
	    sock->conf.tls_ocsp_staple,
	    sock->conf.tls_ocsp_staple_len) != 0) {
		log_warnx("%s: failed to set tls certificate/key: %s", __func__,
		    tls_config_error(sock->tls_config));
		return (-1);
	}

	if (sock->conf.tls_ca != NULL) {
		if (tls_config_set_ca_mem(sock->tls_config, sock->conf.tls_ca,
			sock->conf.tls_ca_len) != 0) {
			log_warnx("%s: failed to add ca cert(s)", __func__);
			return (-1);
		}

		if (tls_config_set_crl_mem(sock->tls_config,
		    sock->conf.tls_crl, sock->conf.tls_crl_len) != 0) {
			log_warnx("%s: failed to add crl(s)", __func__);
			return (-1);
		}

		if (sock->conf.tls_flags & TLSFLAG_OPTIONAL)
			tls_config_verify_client_optional(sock->tls_config);
		else
			tls_config_verify_client(sock->tls_config);
	}

	/* log_debug("%s: adding keypair for server %s", __func__, */
	/*     sock->conf.name); */

	if (tls_config_add_keypair_ocsp_mem(sock->tls_config,
	    sock->conf.tls_cert, sock->conf.tls_cert_len,
	    sock->conf.tls_key, sock->conf.tls_key_len,
	    sock->conf.tls_ocsp_staple,
	    sock->conf.tls_ocsp_staple_len) != 0) {
		log_warnx("%s: failed to add tls keypair", __func__);
		return (-1);
	}

	if (tls_configure(sock->tls_ctx, sock->tls_config) != 0) {
		log_warnx("%s: failed to configure tls - %s", __func__,
		    tls_error(sock->tls_ctx));
		return (-1);
	}

	/* We're now done with the public/private key & ca/crl... */
	tls_config_clear_keys(sock->tls_config);

	freezero(sock->conf.tls_cert, sock->conf.tls_cert_len);
	freezero(sock->conf.tls_key, sock->conf.tls_key_len);
	free(sock->conf.tls_ca);
	free(sock->conf.tls_crl);

	sock->conf.tls_ca = NULL;
	sock->conf.tls_cert = NULL;
	sock->conf.tls_crl = NULL;
	sock->conf.tls_key = NULL;

	sock->conf.tls_ca_len = 0;
	sock->conf.tls_cert_len = 0;
	sock->conf.tls_crl_len = 0;
	sock->conf.tls_key_len = 0;

	return 0;
}

void
socket_tls_handshake(int fd, short event, void *arg)
{
	/* struct thingsd		*thingsd = (struct thingsd *)arg; */
	/* struct client		*client = NULL, *tclient; */
	/* ssize_t			 ret = 0; */

	/* TAILQ_FOREACH(tclient, thingsd->clients, entry) { */
	/* 	if (tclient->fd == fd) { */
	/* 		client = tclient; */
	/* 		break; */
	/* 	} */
	/* } */

	/* if (client == NULL) */
	/* 	return; */

	/* ret = tls_handshake(client->tls_ctx); */

	/* if (ret == 0) { */
	/* 	event_del(client->ev); */
	/* 	log_debug("%s: tls handshake success", __func__); */
	/* 	/1* client_add(thingsd, client); *1/ */
	/* } else if (ret == TLS_WANT_POLLIN) { */
	/* 	event_del(client->ev); */
	/* 	event_set(client->ev, client->fd, EV_READ|EV_PERSIST, */
	/* 		    socket_tls_handshake, thingsd); */
	/* 	if (event_add(client->ev, NULL)) */
	/* 		log_debug("%s: event add client", __func__); */
	/* } else if (ret == TLS_WANT_POLLOUT) { */
	/* 	event_del(client->ev); */
	/* 	event_set(client->ev, client->fd, EV_WRITE|EV_PERSIST, */
	/* 		    socket_tls_handshake, thingsd); */
	/* 	if (event_add(client->ev, NULL)) */
	/* 		log_debug("%s: event add client", __func__); */
	/* } else { */
	/* 	event_del(client->ev); */
	/* 	log_debug("%s: tls handshake failed - %s", __func__, */
	/* 	    tls_error(client->tls_ctx)); */
	/* } */
}

void
socket_tls_load(struct socket *sock)
{
	log_debug("%s: setup TLS for listener %d", __func__, sock->conf.id);

	if (tls_load_keypair(sock) == -1)
		fatalx("%s: failed to load public/private keys on sock %d",
		    __func__, sock->conf.id);
	if (tls_load_ca(sock) == -1)
		fatalx("failed to load ca cert(s) for sock %d", sock->conf.id);
	if (tls_load_crl(sock) == -1)
		fatalx("failed to load crl(s) for sock %d", sock->conf.id);
	if (tls_load_ocsp(sock) == -1)
		fatalx("failed to load ocsp staple for sock %d", sock->conf.id);
}
