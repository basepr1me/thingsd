/*
 * Copyright (c) 2016, 2019, 2020 Tracey Emery <tracey@traceyemery.net>
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
#include <imsg.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>

#include "proc.h"
#include "thingsd.h"

void
open_things(struct thingsd *env, bool reconn)
{
	struct thing		*thing;
	struct dead_thing	*dead_thing;
	struct termios		 s_opts;
	int			 fd;
	int			 baudrate = 0, stop = 0;
	evbuffercb		 socketrd = socket_rd;
	evbuffercb		 socketwr = socket_wr;

	TAILQ_FOREACH(thing, env->things, entry) {
		if (thing->exists)
			continue;

		if (strlen(thing->location) != 0) {
			thing->type = DEV;

			/*
			 * Just a reminder to set the ownership of your serial
			 * devices to _thingsd. Otherwise, a thing will not be
			 * able to successfully open(2) the file descriptor.
			 */
			fd = open(thing->location, O_RDWR | O_NONBLOCK |
			    O_NOCTTY | O_NDELAY);

			if (fd == -1) {
				log_warnx("failed to open %s", thing->location);

				if (reconn)
					return;

				dead_thing = new_dead_thing(thing);

				env->exists = true;
				env->dcount++;
				thing->fd = -1;
				thing->exists = false;

				TAILQ_INSERT_TAIL(env->dead_things->
				    dead_things_list, dead_thing, entry);

				return;
			} else {
				/* load current s_opts */
				tcgetattr(fd, &s_opts);

				/* set baud */
				switch (thing->baud) {
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
				if (thing->data_bits != -1) {
					s_opts.c_cflag &= ~CSIZE;
					switch(thing->data_bits) {
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
				if (strlen(thing->parity) != 0) {
					s_opts.c_cflag &= ~PARENB;

					/* enable parity checking */
					if (strcmp(thing->parity, "odd") == 0) {
						s_opts.c_cflag |= PARENB;
						s_opts.c_cflag |= PARODD;
						s_opts.c_iflag |= (INPCK |
						    ISTRIP);
					} else if (strcmp(thing->parity,
					    "even") == 0) {
						s_opts.c_cflag |= PARENB;
						s_opts.c_cflag &= ~PARODD;
						s_opts.c_iflag |= (INPCK |
						    ISTRIP);
					}

				}

				/* set stop bits */
				if (thing->stop_bits != -1) {
					if (thing->stop_bits == 2)
						s_opts.c_cflag |= CSTOPB;
					else
						s_opts.c_cflag &= ~CSTOPB;
				}

				/* set hardware control */
				if (thing->hw_ctl == false) {
					s_opts.c_cflag &= ~CRTSCTS;
				} else {
					s_opts.c_cflag |= CRTSCTS;
				}

				/* set software control */
				if (thing->sw_ctl == false) {
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

				thing->fd = fd;
				if (thing->fd == '\0') {
					log_warnx("serial device not opened");
					if (reconn)
						return;
					thing->exists = false;
					add_reconn(thing);
					return;
				}

				thing->bev = bufferevent_new(thing->fd,
				    socketrd, socketwr, socket_err, env);

				if (thing->bev == NULL)
					fatalx("ipaddr bev error");

				thing->evb = evbuffer_new();

				if (thing->evb == NULL)
					fatalx("ipaddr evb error");

				bufferevent_enable(thing->bev, EV_READ |
				    EV_WRITE);
			}

			if (reconn) {
				thing->exists = true;
				log_info("reconnected: %s", thing->name);
			}

		}
	}
}
