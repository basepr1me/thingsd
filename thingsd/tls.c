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

#include <event.h>
#include <stdlib.h>
#include <tls.h>

#include "thingsd.h"

int
tls_load_keypair(struct thg *pthg)
{
	if (pthg->tls == false)
		return (0);
	if ((pthg->tls_cert = tls_load_file(pthg->tls_cert_file,
	    &pthg->tls_cert_len, NULL)) == NULL)
		return (-1);
	log_debug("%s: using certificate %s", __func__, pthg->tls_cert_file);
	/* XXX allow to specify password for encrypted key */
	if ((pthg->tls_key = tls_load_file(pthg->tls_key_file,
	    &pthg->tls_key_len, NULL)) == NULL)
		return (-1);
	log_debug("%s: using private key %s", __func__, pthg->tls_key_file);
	return (0);
}

int
tls_load_ca(struct thg *pthg)
{
	if ((pthg->tls_flags & TLSFLAG_CA) == 0 || pthg->tls_ca_file == NULL)
		return (0);
	if ((pthg->tls_ca = tls_load_file(pthg->tls_ca_file, &pthg->tls_ca_len,
	    NULL)) == NULL)
		return (-1);
	log_debug("%s: using ca cert(s) from %s", __func__, pthg->tls_ca_file);
	return (0);
}

int
tls_load_ocsp(struct thg *pthg)
{
	if (pthg->tls == false)
		return (0);
	if (pthg->tls_ocsp_staple_file == NULL)
		return (0);
	if ((pthg->tls_ocsp_staple = tls_load_file(
	    pthg->tls_ocsp_staple_file,
	    &pthg->tls_ocsp_staple_len, NULL)) == NULL) {
		log_warnx("%s: Failed to load ocsp staple from %s", __func__,
		    pthg->tls_ocsp_staple_file);
		return (-1);
	}
	if (pthg->tls_ocsp_staple_len == 0) {
		log_warnx("%s: ignoring 0 length ocsp staple from %s", __func__,
		    pthg->tls_ocsp_staple_file);
		return (0);
	}
	log_debug("%s: using ocsp staple from %s", __func__,
	    pthg->tls_ocsp_staple_file);
	return (0);
}

int
tls_load_crl(struct thg *pthg)
{
	if ((pthg->tls_flags & TLSFLAG_CA) == 0 || pthg->tls_crl_file == NULL)
		return (0);
	if ((pthg->tls_crl = tls_load_file(pthg->tls_crl_file,
	    &pthg->tls_crl_len, NULL)) == NULL)
		return (-1);
	log_debug("%s: using crl(s) from %s", __func__, pthg->tls_crl_file);
	return (0);
}

int
sock_tls_init(struct sock *psock, struct thg *pthg)
{
	if (pthg->tls == false)
		return 0;
	if (pthg->tls_cert == NULL)
		/* soft fail if cert is not there yet */
		return (0);
	log_debug("%s: setting up tls for %s", __func__, pthg->name);
	if (tls_init() != 0) {
		log_warnx("%s: failed to initialise tls", __func__);
		return (-1);
	}
	if ((psock->tls_config = tls_config_new()) == NULL) {
		log_warnx("%s: failed to get tls pthgig", __func__);
		return (-1);
	}
	if ((psock->tls_ctx = tls_server()) == NULL) {
		log_warnx("%s: failed to get tls server", __func__);
		return (-1);
	}
	if (tls_config_set_protocols(psock->tls_config,
	    pthg->tls_protocols) != 0) {
		log_warnx("%s: failed to set tls protocols: %s", __func__,
		    tls_config_error(psock->tls_config));
		return (-1);
	}
	if (tls_config_set_ciphers(psock->tls_config, pthg->tls_ciphers) != 0) {
		log_warnx("%s: failed to set tls ciphers: %s", __func__,
		    tls_config_error(psock->tls_config));
		return (-1);
	}
	if (tls_config_set_dheparams(psock->tls_config,
	    pthg->tls_dhe_params) != 0) {
		log_warnx("%s: failed to set tls dhe params: %s", __func__,
		    tls_config_error(psock->tls_config));
		return (-1);
	}
	if (tls_config_set_ecdhecurves(psock->tls_config,
	    pthg->tls_ecdhe_curves) != 0) {
		log_warnx("%s: failed to set tls ecdhe curves: %s", __func__,
		    tls_config_error(psock->tls_config));
		return (-1);
	}
	if (tls_config_set_keypair_ocsp_mem(psock->tls_config, pthg->tls_cert,
	    pthg->tls_cert_len, pthg->tls_key, pthg->tls_key_len,
	    pthg->tls_ocsp_staple, pthg->tls_ocsp_staple_len) != 0) {
		log_warnx("%s: failed to set tls certificate/key: %s", __func__,
		    tls_config_error(psock->tls_config));
		return (-1);
	}
	if (pthg->tls_ca != NULL) {
		if (tls_config_set_ca_mem(psock->tls_config, pthg->tls_ca,
			pthg->tls_ca_len) != 0) {
			log_warnx("%s: failed to add ca cert(s)", __func__);
			return (-1);
		}
		if (tls_config_set_crl_mem(psock->tls_config, pthg->tls_crl,
			pthg->tls_crl_len) != 0) {
			log_warnx("%s: failed to add crl(s)", __func__);
			return (-1);
		}
		if (pthg->tls_flags & TLSFLAG_OPTIONAL)
			tls_config_verify_client_optional(psock->tls_config);
		else
			tls_config_verify_client(psock->tls_config);
	}
	log_debug("%s: adding keypair for server %s", __func__, pthg->name);
	if (tls_config_add_keypair_ocsp_mem(psock->tls_config, pthg->tls_cert,
	    pthg->tls_cert_len, pthg->tls_key, pthg->tls_key_len,
	    pthg->tls_ocsp_staple, pthg->tls_ocsp_staple_len) != 0) {
		log_warnx("%s: failed to add tls keypair", __func__);
		return (-1);
	}
	if (tls_configure(psock->tls_ctx, psock->tls_config) != 0) {
		log_warnx("%s: failed to configure tls - %s", __func__,
		    tls_error(psock->tls_ctx));
		return (-1);
	}
	/* We're now done with the public/private key & ca/crl... */
	tls_config_clear_keys(psock->tls_config);
	psock->tls = true;
	freezero(pthg->tls_cert, pthg->tls_cert_len);
	freezero(pthg->tls_key, pthg->tls_key_len);
	free(pthg->tls_ca);
	free(pthg->tls_crl);
	pthg->tls_ca = NULL;
	pthg->tls_cert = NULL;
	pthg->tls_crl = NULL;
	pthg->tls_key = NULL;
	pthg->tls_ca_len = 0;
	pthg->tls_cert_len = 0;
	pthg->tls_crl_len = 0;
	pthg->tls_key_len = 0;
	return 0;
}

void
sock_tls_handshake(int fd, short event, void *arg)
{
	struct thgsd		*pthgsd = (struct thgsd *)arg;
	struct clt		*clt = NULL, *tclt;
	ssize_t			 ret = 0;

	TAILQ_FOREACH(tclt, &pthgsd->clts, entry) {
		if (tclt->fd == fd) {
			clt = tclt;
			break;
		}
	}
	ret = tls_handshake(clt->tls_ctx);
	if (ret == 0) {
		event_del(clt->ev);
		log_debug("%s: tls handshake success", __func__);
		clt_add(pthgsd, clt);
	} else if (ret == TLS_WANT_POLLIN) {
		event_del(clt->ev);
		event_set(clt->ev, clt->fd, EV_READ|EV_PERSIST,
			    sock_tls_handshake, pthgsd);
		if (event_add(clt->ev, NULL))
			log_info("event add clt");
	} else if (ret == TLS_WANT_POLLOUT) {
		event_del(clt->ev);
		event_set(clt->ev, clt->fd, EV_WRITE|EV_PERSIST,
			    sock_tls_handshake, pthgsd);
		if (event_add(clt->ev, NULL))
			log_info("event add clt");
	} else {
		event_del(clt->ev);
		log_debug("%s: tls handshake failed - %s", __func__,
		    tls_error(clt->tls_ctx));
	}
}
