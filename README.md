thingsd for OpenBSD
====================

The thingsd OpenBSD proxy daemon provides a mechanism for clients and client
processes to communicate with an array of serial and IoT things. At its core,
thingsd is primarily a packet repeater in that it waits for packets to swap
between subscriber clients and things. However, thingsd also provides password
control over those connections, including client limits.

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
		doas cp examples/etc/rc.d/thingsd /etc/rc.d/

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

Further examples can be found in the src/examples directory above.

Todo
----

* Finish thingsctl functions
* Implement TLS

Author
------

[Tracey Emery](https://github.com/spoollord/)

See the [License](LICENSE.md) file for more information.
