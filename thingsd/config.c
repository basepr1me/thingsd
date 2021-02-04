/*
 * Copyright (c) 2020-2021 Tracey Emery <tracey@traceyemery.net>
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

#include "proc.h"
#include "thingsd.h"

extern enum privsep_procid privsep_process;

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
	struct privsep		*ps = env->thingsd_ps;
	unsigned int		 what;

	/* Global configuration. */
	if (privsep_process == PROC_PARENT)
		env->prefork_socks = SOCKS_NUMPROC;

	ps->ps_what[PROC_PARENT] = CONFIG_ALL;
	ps->ps_what[PROC_SOCKS] = CONFIG_SOCKS;

	/* Other configuration. */
	what = ps->ps_what[privsep_process];
	if (what & CONFIG_SOCKS) {
		if ((env->things = calloc(1, sizeof(*env->things))) == NULL)
			return (-1);
		if ((env->sockets = calloc(1, sizeof(*env->sockets))) == NULL)
			return (-1);
		if ((env->packages = calloc(1, sizeof(*env->packages))) == NULL)
			return (-1);
		if ((env->dead_things = calloc(1,
		    sizeof(*env->dead_things))) == NULL)
			return (-1);
		env->packet_clients = calloc(1, sizeof(*env->packet_clients));
		if (env->packet_clients == NULL)
			return (-1);
		TAILQ_INIT(env->things);
		TAILQ_INIT(env->sockets);
		TAILQ_INIT(env->packages);
		TAILQ_INIT(env->dead_things);
		TAILQ_INIT(env->packet_clients);
	}
	return (0);
}

int
config_getcfg(struct thingsd *env, struct imsg *imsg)
{
	/* nothing to do but tell parent configuration is done */
	if (privsep_process != PROC_PARENT)
		proc_compose(env->thingsd_ps, PROC_PARENT,
		    IMSG_CFG_DONE, NULL, 0);

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

	/* create a new socket */
	if ((sock = calloc(1, sizeof(*sock))) == NULL) {
		if (imsg->fd != -1)
			close(imsg->fd);
		return (-1);
	}

	memcpy(&sock->conf, &sock_conf, sizeof(sock->conf));
	sock->fd = imsg->fd;

	TAILQ_INSERT_TAIL(env->sockets, sock, entry);

	return (0);
}

int
config_setsocks(struct thingsd *env, struct socket *sock)
{
	struct privsep		*ps = env->thingsd_ps;
	struct socket_config	 u;
	int			 fd = -1, n, m;
	struct iovec		 iov[6];
	size_t			 c;
	unsigned int		 id, what;

	/* setup socket in priv process */
	if (sockets_privinit(sock) == -1)
		return (-1);

	for (id = 0; id < PROC_MAX; id++) {
		what = ps->ps_what[id];

		if ((what & CONFIG_SOCKS) == 0 || id == privsep_process)
			continue;

		memcpy(&u, &sock->conf, sizeof(u));

		c = 0;
		iov[c].iov_base = &u;
		iov[c++].iov_len = sizeof(u);
		if (id == PROC_SOCKS) {
			/* XXX imsg code will close the fd after 1st call */
			n = -1;
			proc_range(ps, id, &n, &m);
			for (n = 0; n < m; n++) {
				/* send thing fd */
				if (sock->fd == -1)
					fd = -1;
				else if ((fd = dup(sock->fd)) == -1)
					return (-1);
				if (proc_composev_imsg(ps, id, n,
				    IMSG_CFG_SOCKS, -1, fd, iov,
				    c) != 0) {
					log_warn("%s: failed to compose "
					    "IMSG_CFG_SOCKS imsg",
					    __func__);
					return (-1);
				}
				if (proc_flush_imsg(ps, id, n) == -1) {
					log_warn("%s: failed to flush "
					    "IMSG_CFG_SOCKS imsg",
					    __func__);
					return (-1);
				}
			}
			/* Configure TLS if necessary. */
			config_setsocks_tls(env, sock);
		}
	}

	/* Close thing socket early to prevent fd exhaustion in thingsd. */
	if (sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}
	return (0);
}

static int
config_settls(struct thingsd *env, struct socket *sock,
    enum tls_config_type type, const char *label, uint8_t *data, size_t len)
{
	struct privsep		*ps = env->thingsd_ps;
	struct socket_config	*sock_conf = &sock->conf;
	struct tls_config	 tls;
	struct iovec		 iov[2];
	size_t			 c;

	if (data == NULL || len == 0)
		return (0);

	DPRINTF("%s: sending tls %s for \"%s[%u]\" to %s fd %d", __func__,
	    label, sock_conf->name, sock_conf->id, ps->ps_title[PROC_SOCKS],
	    sock->fd);

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

		if (proc_composev(ps, PROC_SOCKS, IMSG_CFG_TLS, iov, c) != 0) {
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
#ifdef DEBUG
	struct privsep		*ps = env->thingsd_ps;
#endif

	DPRINTF("%s: %s %d getting tls %s (%zu:%zu@%zu) for \"%s[%u]\"",
	    __func__, ps->ps_title[privsep_process], ps->ps_instance, label,
	    tls_conf->tls_len, len, tls_conf->tls_chunk_offset, sock_conf->name,
	    sock_conf->id);

	if (tls_conf->tls_chunk_offset == 0) {
		*outdata = NULL;
		free(*outdata);
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

void
config_purge(struct thingsd *env, unsigned int reset)
{
	struct privsep		*ps = env->thingsd_ps;
	struct thing		*thing;
	unsigned int		 what;

	what = ps->ps_what[privsep_process];
	if (what & CONFIG_SOCKS) {
		while ((thing = TAILQ_FIRST(env->things)) != NULL) {
			TAILQ_REMOVE(env->things, thing, entry);
			free(thing);
		}
	}
}

int
config_setreset(struct thingsd *env, unsigned int reset)
{
	struct privsep	*ps = env->thingsd_ps;
	unsigned int	 id;

	for (id = 0; id < PROC_MAX; id++) {
		if (id == privsep_process)
			continue;
		proc_compose(ps, id, IMSG_CTL_RESET, &reset, sizeof(reset));
	}

	return (0);
}

int
config_getreset(struct thingsd *env, struct imsg *imsg)
{
	unsigned int	 mode;

	IMSG_SIZE_CHECK(imsg, &mode);
	memcpy(&mode, imsg->data, sizeof(mode));

	config_purge(env, mode);

	return (0);
}
