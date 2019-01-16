/*
 * Copyright (c) 2016-2019 Tracey Emery <tracey@traceyemery.net>
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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <event.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>

#include "thingsd.h"

extern struct dthgs		*pdthgs;

void
open_thgs(struct thgsd *pthgsd, bool reconn)
{
	struct thg		*thg;
	struct dthg		*dthg;
	struct termios		 s_opts;
	int			 fd;
	int			 baudrate = 0, stop = 0;
	evbuffercb		 sockrd = sock_rd;
	evbuffercb		 sockwr = sock_wr;

	TAILQ_FOREACH(thg, &pthgsd->thgs, entry) {
		if (thg->exists)
			continue;
		if (thg->location != NULL) {
			thg->type = DEV;
			/*
			 * Just a reminder to set the ownership of your serial
			 * devices to _thingsd. Otherwise, a disconnected
			 * and reconnected thing will not be able to
			 * successfully open(2) the file descriptor.
			 */
			fd = open(thg->location, O_RDWR | O_NONBLOCK | O_NOCTTY
			    | O_NDELAY);
			if (fd == -1) {
				log_info("failed to open %s", thg->location);
				if (reconn)
					return;
				dthg = new_dthg(thg);
				pthgsd->exists = true;
				pthgsd->dcount++;
				thg->fd = -1;
				thg->exists = false;
				TAILQ_INSERT_TAIL(&pdthgs->zthgs, dthg, entry);
				return;
			} else {
				/* load current s_opts */
				tcgetattr(fd, &s_opts);
				/* set baud */
				switch (thg->baud) {
				case 50:
					baudrate = B50;
					break;
				case 75:
					baudrate = B75;
					break;
				case 110:
					baudrate = B110;
					break;
				case 134:
					baudrate = B134;
					break;
				case 150:
					baudrate = B150;
					break;
				case 200:
					baudrate = B200;
					break;
				case 300:
					baudrate = B300;
					break;
				case 600:
					baudrate = B600;
					break;
				case 1200:
					baudrate = B1200;
					break;
				case 1800:
					baudrate = B1800;
					break;
				case 2400:
					baudrate = B2400;
					break;
				case 4800:
					baudrate = B4800;
					break;
				case 9600:
					baudrate = B9600;
					break;
				case 19200:
					baudrate = B19200;
					break;
				case 38400:
					baudrate = B38400;
					break;
				case 57600:
					baudrate = B57600;
					break;
				case 76800:
					baudrate = B76800;
					break;
				case 115200:
					baudrate = B115200;
					break;
				}
				cfsetispeed(&s_opts, baudrate);
				cfsetospeed(&s_opts, baudrate);
				/* enable and set local */
				s_opts.c_cflag |= (CLOCAL | CREAD);
				/* set data bits */
				if (thg->data_bits != -1) {
					s_opts.c_cflag &= ~CSIZE;
					switch(thg->data_bits) {
					case 5:
						stop = CS5;
						break;
					case 6:
						stop = CS6;
						break;
					case 7:
						stop = CS7;
						break;
					case 8:
						stop = CS8;
						break;
					}
					s_opts.c_cflag |= stop;
				}
				/* set parity */
				if (thg->parity != NULL) {
					s_opts.c_cflag &= ~PARENB;
					/* enable parity checking */
					if (strcmp(thg->parity, "odd") == 0) {
						s_opts.c_cflag |= PARENB;
						s_opts.c_cflag |= PARODD;
						s_opts.c_iflag |= (INPCK |
						    ISTRIP);
					} else if (strcmp(thg->parity,
					    "even") == 0) {
						s_opts.c_cflag |= PARENB;
						s_opts.c_cflag &= ~PARODD;
						s_opts.c_iflag |= (INPCK |
						    ISTRIP);
					}
				}
				/* set stop bits */
				if (thg->stop_bits != -1) {
					if (thg->stop_bits == 2)
						s_opts.c_cflag |= CSTOPB;
					else
						s_opts.c_cflag &= ~CSTOPB;
				}
				/* set hardware control */
				if (thg->hw_ctl == false) {
					s_opts.c_cflag &= ~CRTSCTS;
				} else {
					s_opts.c_cflag |= CRTSCTS;
				}
				/* set software control */
				if (thg->sw_ctl == false) {
					s_opts.c_iflag &= ~(IXON | IXOFF |
					    IXANY);
				} else {
					s_opts.c_iflag |= (IXON | IXOFF |
					    IXANY);
				}
				/* set input/output as raw */
				s_opts.c_lflag &= ~(ICANON | ECHO | ECHOE |
				    ISIG);
				s_opts.c_oflag &= ~OPOST;
				/* Set the new options for the port */
				tcsetattr(fd, TCSANOW, &s_opts);
				if ((thg->fd = fd) == '\0') {
					log_info("serial device not opened");
					if (reconn)
						return;
					thg->exists = false;
					add_reconn(thg);
					return;
				}
				thg->bev = bufferevent_new(thg->fd, sockrd,
				    sockwr, sock_err, pthgsd);
				bufferevent_base_set(pthgsd->eb, thg->bev);
				if (thg->bev == NULL)
					fatalx("ipaddr bev error");
				thg->evb = evbuffer_new();
				if (thg->evb == NULL)
					fatalx("ipaddr evb error");
				bufferevent_enable(thg->bev, EV_READ|EV_WRITE);
			}
			if (reconn) {
				thg->exists = true;
				log_info("reconnected: %s", thg->name);
			}
		}
	}
}
