/*
 * Copyright (c) 2020-2026 Tracey Emery <tracey@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/tree.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <event.h>
#include <fcntl.h>
#include <util.h>
#include <errno.h>
#include <imsg.h>

#include "thingsd.h"

int	 config_setsocks_tls(struct thingsd *, struct socket *);
static int
	config_settls(struct thingsd *, struct socket *,
	    enum tls_config_type, const char *, uint8_t *, size_t);
static int
	config_gettls(struct thingsd *, struct socket_config *,
	    struct tls_config *, const char *, uint8_t *, size_t,
	    uint8_t **, size_t *);

int
config_init(struct thingsd *env)
{
	if ((env->things = calloc(1, sizeof(*env->things))) == NULL)
		return (-1);
	if ((env->sockets = calloc(1, sizeof(*env->sockets))) == NULL)
		return (-1);
	if ((env->packages = calloc(1, sizeof(*env->packages))) == NULL)
		return (-1);
	if ((env->dead_things = calloc(1, sizeof(*env->dead_things))) == NULL)
		return (-1);
	env->packet_clients = calloc(1, sizeof(*env->packet_clients));
	if (env->packet_clients == NULL)
		return (-1);
	TAILQ_INIT(env->things);
	TAILQ_INIT(env->sockets);
	TAILQ_INIT(env->packages);
	TAILQ_INIT(env->dead_things);
	TAILQ_INIT(env->packet_clients);

	return (0);
}

int
config_getcfg(struct thingsd *env, struct imsg *imsg)
{
	/* nothing to do but tell parent configuration is done */
	imsg_compose_event(socks_iev_parent, IMSG_CFG_DONE, 0, 0, -1, NULL, 0);

	return (0);
}

int
config_getsocks(struct thingsd *env, struct imsg *imsg)
{
	struct socket		*sock = NULL;
	struct socket_config	 sock_conf;
	uint8_t			*p = imsg->data;

	IMSG_SIZE_CHECK(imsg, &sock_conf);
	memcpy(&sock_conf, p, sizeof(sock_conf));

	if (IMSG_DATA_SIZE(imsg) != sizeof(sock_conf)) {
		log_debug("%s: imsg size error", __func__);
		return (-1);
	}

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		return (-1);
	if ((sock->clients = calloc(1, sizeof(*sock->clients))) == NULL) {
		free(sock);
		return (-1);
	}
	TAILQ_INIT(sock->clients);

	memcpy(&sock->conf, &sock_conf, sizeof(sock->conf));

	/*
	 * The pointers in the config belong to the parent's address space.
	 * TLS material arrives separately via IMSG_CFG_TLS, the file names
	 * are only ever used by the parent.
	 */
	sock->conf.tls_cert = NULL;
	sock->conf.tls_cert_file = NULL;
	sock->conf.tls_cert_len = 0;
	sock->conf.tls_key = NULL;
	sock->conf.tls_key_file = NULL;
	sock->conf.tls_key_len = 0;
	sock->conf.tls_ca = NULL;
	sock->conf.tls_ca_file = NULL;
	sock->conf.tls_ca_len = 0;
	sock->conf.tls_crl = NULL;
	sock->conf.tls_crl_file = NULL;
	sock->conf.tls_crl_len = 0;
	sock->conf.tls_ocsp_staple = NULL;
	sock->conf.tls_ocsp_staple_file = NULL;
	sock->conf.tls_ocsp_staple_len = 0;

	if ((sock->fd = imsg_get_fd(imsg)) == -1) {
		log_warnx("%s: listener %d arrived without a descriptor",
		    __func__, sock->conf.id);
		free(sock->clients);
		free(sock);
		return (-1);
	}

	TAILQ_INSERT_TAIL(env->sockets, sock, entry);

	return (0);
}

int
config_setsocks(struct thingsd *env, struct socket *sock)
{
	struct socket_config	 u;
	int			 ret;

	/* setup socket in priv process */
	if (sockets_privinit(sock) == -1)
		return (-1);

	memcpy(&u, &sock->conf, sizeof(u));

	/*
	 * imsg closes the passed descriptor once it is sent, which also
	 * keeps listener descriptors from piling up in the parent.  The
	 * flush is synchronous because the parent pledges without sendfd
	 * once configuration is finished.
	 */
	if (imsg_compose(&parent_iev_socks->ibuf, IMSG_CFG_SOCKS, 0, 0,
	    sock->fd, &u, sizeof(u)) == -1) {
		log_warn("%s: failed to compose IMSG_CFG_SOCKS imsg", __func__);
		return (-1);
	}
	sock->fd = -1;
	do
		ret = imsgbuf_flush(&parent_iev_socks->ibuf);
	while (ret == -1 && errno == EAGAIN);
	if (ret == -1) {
		log_warn("%s: failed to flush IMSG_CFG_SOCKS imsg", __func__);
		return (-1);
	}

	/* Configure TLS if necessary. */
	config_setsocks_tls(env, sock);

	return (0);
}

static int
config_settls(struct thingsd *env, struct socket *sock,
    enum tls_config_type type, const char *label, uint8_t *data, size_t len)
{
	struct socket_config	*sock_conf = &sock->conf;
	struct tls_config	 tls;
	struct iovec		 iov[2];
	size_t			 c;

	if (data == NULL || len == 0)
		return (0);

	log_debug("%s: sending tls %s for \"%s[%u]\"", __func__, label,
	    sock_conf->name, sock_conf->id);

	memset(&tls, 0, sizeof(tls));
	tls.id = sock_conf->id;
	tls.tls_type = type;
	tls.tls_len = len;
	tls.tls_chunk_offset = 0;

	while (len > 0) {
		tls.tls_chunk_len = len;
		if (tls.tls_chunk_len > (MAX_IMSG_DATA_SIZE - sizeof(tls)))
			tls.tls_chunk_len = MAX_IMSG_DATA_SIZE - sizeof(tls);

		c = 0;
		iov[c].iov_base = &tls;
		iov[c++].iov_len = sizeof(tls);
		iov[c].iov_base = data;
		iov[c++].iov_len = tls.tls_chunk_len;

		if (imsg_composev_event(parent_iev_socks, IMSG_CFG_TLS, 0, 0,
		    -1, iov, c) == -1) {
			log_warn("%s: failed to compose IMSG_CFG_TLS imsg for "
			    "`%s'", __func__, sock_conf->name);
			return (-1);
		}

		tls.tls_chunk_offset += tls.tls_chunk_len;
		data += tls.tls_chunk_len;
		len -= tls.tls_chunk_len;
	}

	return (0);
}

int
config_setsocks_tls(struct thingsd *env, struct socket *sock)
{
	struct socket_config	*sock_conf = &sock->conf;

	if (sock_conf->tls == 0)
		return (0);

	log_debug("%s: configuring tls for %s", __func__, sock_conf->name);

	if (config_settls(env, sock, TLS_CFG_CA, "ca", sock_conf->tls_ca,
	    sock_conf->tls_ca_len) != 0)
		return (-1);

	if (config_settls(env, sock, TLS_CFG_CERT, "cert", sock_conf->tls_cert,
	    sock_conf->tls_cert_len) != 0)
		return (-1);

	if (config_settls(env, sock, TLS_CFG_CRL, "crl", sock_conf->tls_crl,
	    sock_conf->tls_crl_len) != 0)
		return (-1);

	if (config_settls(env, sock, TLS_CFG_KEY, "key", sock_conf->tls_key,
	    sock_conf->tls_key_len) != 0)
		return (-1);

	if (config_settls(env, sock, TLS_CFG_OCSP_STAPLE, "ocsp staple",
	    sock_conf->tls_ocsp_staple, sock_conf->tls_ocsp_staple_len) != 0)
		return (-1);

	return (0);
}

static int
config_gettls(struct thingsd *env, struct socket_config *sock_conf,
    struct tls_config *tls_conf, const char *label, uint8_t *data, size_t len,
    uint8_t **outdata, size_t *outlen)
{
	log_debug("%s: getting tls %s (%zu:%zu@%zu) for \"%s[%u]\"",
	    __func__, label, tls_conf->tls_len, len,
	    tls_conf->tls_chunk_offset, sock_conf->name, sock_conf->id);

	if (tls_conf->tls_chunk_offset == 0) {
		free(*outdata);
		*outdata = NULL;
		*outlen = 0;
		if ((*outdata = calloc(1, tls_conf->tls_len)) == NULL)
			goto fail;
		*outlen = tls_conf->tls_len;
	}

	if (*outdata == NULL) {
		log_debug("%s: tls config invalid chunk sequence", __func__);
		goto fail;
	}

	if (*outlen != tls_conf->tls_len) {
		log_debug("%s: tls config length mismatch (%zu != %zu)",
		    __func__, *outlen, tls_conf->tls_len);
		goto fail;
	}

	if (len > (tls_conf->tls_len - tls_conf->tls_chunk_offset)) {
		log_debug("%s: tls config invalid chunk length", __func__);
		goto fail;
	}

	memcpy(*outdata + tls_conf->tls_chunk_offset, data, len);

	return (0);

 fail:
	return (-1);
}

int
config_getsocks_tls(struct thingsd *env, struct imsg *imsg)
{
	struct socket		*sock = NULL;
	struct socket_config	*sock_conf;
	struct tls_config	 tls_conf;
	uint8_t			*p = imsg->data;
	size_t			 len;

	IMSG_SIZE_CHECK(imsg, &tls_conf);
	memcpy(&tls_conf, p, sizeof(tls_conf));

	len = tls_conf.tls_chunk_len;

	if ((IMSG_DATA_SIZE(imsg) - sizeof(tls_conf)) < len) {
		log_debug("%s: invalid message length", __func__);
		goto fail;
	}

	p += sizeof(tls_conf);

	sock = sockets_get_socket_byid(env, tls_conf.id);
	if (sock == NULL)
		return (0);

	sock_conf = &sock->conf;

	switch (tls_conf.tls_type) {
	case TLS_CFG_CA:
		if (config_gettls(env, sock_conf, &tls_conf, "ca", p, len,
		    &sock_conf->tls_ca, &sock_conf->tls_ca_len) != 0)
			goto fail;
		break;

	case TLS_CFG_CERT:
		if (config_gettls(env, sock_conf, &tls_conf, "cert", p, len,
		    &sock_conf->tls_cert, &sock_conf->tls_cert_len) != 0)
			goto fail;
		break;

	case TLS_CFG_CRL:
		if (config_gettls(env, sock_conf, &tls_conf, "crl", p, len,
		    &sock_conf->tls_crl, &sock_conf->tls_crl_len) != 0)
			goto fail;
		break;

	case TLS_CFG_KEY:
		if (config_gettls(env, sock_conf, &tls_conf, "key", p, len,
		    &sock_conf->tls_key, &sock_conf->tls_key_len) != 0)
			goto fail;
		break;

	case TLS_CFG_OCSP_STAPLE:
		if (config_gettls(env, sock_conf, &tls_conf, "ocsp staple",
		    p, len, &sock_conf->tls_ocsp_staple,
		    &sock_conf->tls_ocsp_staple_len) != 0)
			goto fail;
		break;

	default:
		log_debug("%s: unknown tls config type %i\n",
		     __func__, tls_conf.tls_type);
		goto fail;
	}

	return (0);

 fail:
	return (-1);
}
