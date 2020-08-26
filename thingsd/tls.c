/*
 * Copyright (c) 2019 Tracey Emery <tracey@traceyemery.net>
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
#include <stdbool.h>
#include <tls.h>

#include "proc.h"
#include "thingsd.h"

int
tls_load_keypair(struct thing *thing)
{
	if (thing->tls == false)
		return (0);

	thing->tls_cert = tls_load_file(thing->tls_cert_file,
	    &thing->tls_cert_len, NULL);
	if (thing->tls_cert == NULL)
		return (-1);

	log_debug("%s: using certificate %s", __func__, thing->tls_cert_file);

	/* XXX allow to specify password for encrypted key */
	thing->tls_key = tls_load_file(thing->tls_key_file,
	    &thing->tls_key_len, NULL);
	if (thing->tls_key == NULL)
		return (-1);

	log_debug("%s: using private key %s", __func__, thing->tls_key_file);

	return (0);
}

int
tls_load_ca(struct thing *thing)
{
	if ((thing->tls_flags & TLSFLAG_CA) == 0 ||
	    strlen(thing->tls_ca_file) == 0)
		return (0);

	thing->tls_ca = tls_load_file(thing->tls_ca_file,
	    &thing->tls_ca_len, NULL);
	if (thing->tls_ca == NULL)
		return (-1);

	log_debug("%s: using ca cert(s) from %s", __func__, thing->tls_ca_file);

	return (0);
}

int
tls_load_ocsp(struct thing *thing)
{
	if (thing->tls == false)
		return (0);

	if (strlen(thing->tls_ocsp_staple_file) == 0)
		return (0);

	thing->tls_ocsp_staple = tls_load_file(
	    thing->tls_ocsp_staple_file,
	    &thing->tls_ocsp_staple_len, NULL);
	if (thing->tls_ocsp_staple == NULL) {
		log_warnx("%s: Failed to load ocsp staple from %s", __func__,
		    thing->tls_ocsp_staple_file);
		return (-1);
	}

	if (thing->tls_ocsp_staple_len == 0) {
		log_warnx("%s: ignoring 0 length ocsp staple from %s", __func__,
		    thing->tls_ocsp_staple_file);
		return (0);
	}

	log_debug("%s: using ocsp staple from %s", __func__,
	    thing->tls_ocsp_staple_file);

	return (0);
}

int
tls_load_crl(struct thing *thing)
{
	if ((thing->tls_flags & TLSFLAG_CA) == 0 ||
	    strlen(thing->tls_crl_file) == 0)
		return (0);

	thing->tls_crl = tls_load_file(thing->tls_crl_file,
	    &thing->tls_crl_len, NULL);
	if (thing->tls_crl == NULL)
		return (-1);

	log_debug("%s: using crl(s) from %s", __func__, thing->tls_crl_file);

	return (0);
}

int
socket_tls_init(struct socket *socket, struct thing *thing)
{
	if (thing->tls == false)
		return 0;

	if (thing->tls_cert == NULL)
		/*
		 * hard fail if cert is not there yet
		 * we don't check again
		 */
		return (-1);

	log_debug("%s: setting up tls for %s", __func__, thing->name);

	if (tls_init() != 0) {
		log_warnx("%s: failed to initialise tls", __func__);
		return (-1);
	}

	socket->tls_config = tls_config_new();
	if (socket->tls_config == NULL) {
		log_warnx("%s: failed to get tls config", __func__);
		return (-1);
	}

	socket->tls_ctx = tls_server();
	if (socket->tls_ctx == NULL) {
		log_warnx("%s: failed to get tls server", __func__);
		return (-1);
	}

	if (tls_config_set_protocols(socket->tls_config,
	    thing->tls_protocols) != 0) {
		log_warnx("%s: failed to set tls protocols: %s", __func__,
		    tls_config_error(socket->tls_config));
		return (-1);
	}

	if (tls_config_set_ciphers(socket->tls_config,
	    thing->tls_ciphers) != 0) {
		log_warnx("%s: failed to set tls ciphers: %s", __func__,
		    tls_config_error(socket->tls_config));
		return (-1);
	}

	if (tls_config_set_dheparams(socket->tls_config,
	    thing->tls_dhe_params) != 0) {
		log_warnx("%s: failed to set tls dhe params: %s", __func__,
		    tls_config_error(socket->tls_config));
		return (-1);
	}

	if (tls_config_set_ecdhecurves(socket->tls_config,
	    thing->tls_ecdhe_curves) != 0) {
		log_warnx("%s: failed to set tls ecdhe curves: %s", __func__,
		    tls_config_error(socket->tls_config));
		return (-1);
	}

	if (tls_config_set_keypair_ocsp_mem(socket->tls_config, thing->tls_cert,
	    thing->tls_cert_len, thing->tls_key, thing->tls_key_len,
	    thing->tls_ocsp_staple, thing->tls_ocsp_staple_len) != 0) {
		log_warnx("%s: failed to set tls certificate/key: %s", __func__,
		    tls_config_error(socket->tls_config));
		return (-1);
	}

	if (thing->tls_ca != NULL) {
		if (tls_config_set_ca_mem(socket->tls_config, thing->tls_ca,
			thing->tls_ca_len) != 0) {
			log_warnx("%s: failed to add ca cert(s)", __func__);
			return (-1);
		}

		if (tls_config_set_crl_mem(socket->tls_config, thing->tls_crl,
			thing->tls_crl_len) != 0) {
			log_warnx("%s: failed to add crl(s)", __func__);
			return (-1);
		}

		if (thing->tls_flags & TLSFLAG_OPTIONAL)
			tls_config_verify_client_optional(socket->tls_config);
		else
			tls_config_verify_client(socket->tls_config);
	}

	log_debug("%s: adding keypair for server %s", __func__, thing->name);

	if (tls_config_add_keypair_ocsp_mem(socket->tls_config, thing->tls_cert,
	    thing->tls_cert_len, thing->tls_key, thing->tls_key_len,
	    thing->tls_ocsp_staple, thing->tls_ocsp_staple_len) != 0) {
		log_warnx("%s: failed to add tls keypair", __func__);
		return (-1);
	}

	if (tls_configure(socket->tls_ctx, socket->tls_config) != 0) {
		log_warnx("%s: failed to configure tls - %s", __func__,
		    tls_error(socket->tls_ctx));
		return (-1);
	}

	/* We're now done with the public/private key & ca/crl... */
	tls_config_clear_keys(socket->tls_config);

	socket->tls = true;

	freezero(thing->tls_cert, thing->tls_cert_len);
	freezero(thing->tls_key, thing->tls_key_len);
	free(thing->tls_ca);
	free(thing->tls_crl);

	thing->tls_ca = NULL;
	thing->tls_cert = NULL;
	thing->tls_crl = NULL;
	thing->tls_key = NULL;

	thing->tls_ca_len = 0;
	thing->tls_cert_len = 0;
	thing->tls_crl_len = 0;
	thing->tls_key_len = 0;

	return 0;
}

void
socket_tls_handshake(int fd, short event, void *arg)
{
	struct thingsd		*thingsd = (struct thingsd *)arg;
	struct client		*client = NULL, *tclient;
	ssize_t			 ret = 0;

	TAILQ_FOREACH(tclient, thingsd->clients, entry) {
		if (tclient->fd == fd) {
			client = tclient;
			break;
		}
	}

	if (client == NULL)
		return;

	ret = tls_handshake(client->tls_ctx);

	if (ret == 0) {
		event_del(client->ev);
		log_debug("%s: tls handshake success", __func__);
		/* client_add(thingsd, client); */
	} else if (ret == TLS_WANT_POLLIN) {
		event_del(client->ev);
		event_set(client->ev, client->fd, EV_READ|EV_PERSIST,
			    socket_tls_handshake, thingsd);
		if (event_add(client->ev, NULL))
			log_debug("%s: event add client", __func__);
	} else if (ret == TLS_WANT_POLLOUT) {
		event_del(client->ev);
		event_set(client->ev, client->fd, EV_WRITE|EV_PERSIST,
			    socket_tls_handshake, thingsd);
		if (event_add(client->ev, NULL))
			log_debug("%s: event add client", __func__);
	} else {
		event_del(client->ev);
		log_debug("%s: tls handshake failed - %s", __func__,
		    tls_error(client->tls_ctx));
	}
}
