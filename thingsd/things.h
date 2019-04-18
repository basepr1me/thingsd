/*
 * Copyright (c) 2019 Tracey Emery <tracey@traceyemery.net>
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

#include "thingsd.h"

void			 thgs_sighdlr(int, short, void *);
void			 thgs_shutdown(struct dthgs *);
void			 thgs_dispatch_main(int, short, void *);
void			 do_reconn(void);
void			 show_list(enum thgs_list_type, pid_t);

/* things.c */
int		 	 thgs_imsg_compose_main(int, pid_t, void *, uint16_t);
struct thgsd		*pthgsd;
struct dthgs		*pdthgs;
struct thg_imsg		*compose_thgs(struct thg *, int);
struct clt_imsg		*compose_clts(struct clt *);
struct sock_imsg	*compose_socks(struct sock *);