thingsd for OpenBSD
====================

The thingsd OpenBSD proxy daemon provides a mechanism for clients and client
processes to communicate with an array of serial and IoT things. At its core,
thingsd is primarily a data aggregator and repeater, in that it waits for
packets to swap between subscriber clients and things. However, thingsd also
provides password control over those connections, including client limits.

On the client side, thingsd sets up TCP/IP sockets to transmit packets to and
from things. On the server side, thingsd can connect to any serial device which
has a viable file descriptor, create a persistent connection to the IP address
of a device transmitting packets on the same network, or setup a UDP listener
on the network to receive broadcasted packets. Devices tested include:
ESP8266/ESP32 modules, on both the serial and network sides, XBee Series 2
coordinators connected in a mesh network, and NF24 devices. To transmit to an
IP address, which does not allow persistence, thingsd will create an ad hoc
connection, transmit a packet, and detach. The thingsd proxy daemon is agnostic
about packet data.

Prerequisites
-------------

* OpenBSD 6.4 or higher

Files
-----

* `/usr/local/sbin/thingsd`
* `/usr/local/man/man8/thingsd.8`
* `/etc/examples/thingsd.conf`
* `/usr/local/man/man5/thingsd.conf.5`
* `/etc/rc.d/thingsd`
* `/usr/local/sbin/thingsctl`
* `/usr/local/man/man8/thingsctl.8`

Usage
-----

Compile and install.

		make
		make install
		doas addgroup _thingsd
		doas useradd -d /var/empty -L daemon -g _thingsd -s /sbin/nologin _thingsd
		doas cp examples/etc/rc.d/thingsd /etc/rc.d/
		doas chown _thingsd /dev/[thingsd.conf devices]

Edit thingsd.conf according to `man thingsd.conf`. Your settings will depend
on your machine and the things you have setup.

Once the thingsd.conf is edited, run `rcctl enable thingsd` and
`rcctl start thingsd`. The thingsd daemon can also be run manually from the
command line. To keep thingsd from daemonizing, run `thingsd -d` from the
command line.

To test your setup, connect to your machine running thingsd with netcat:

		nc SERVERNAME PORT

Then paste in a subscription packet for your setup:

		~~~subscribe{{name,"CLIENT"},{things{thing{"dev","passwd"}}}}

You should start receiving packets from your setup thing.

See the examples for more testing options.

Further examples can be found in the src/examples directory above.

Author
------

[Tracey Emery](https://github.com/basepr1me/)

See the [License](LICENSE.md) file for more information.
