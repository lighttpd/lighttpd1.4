#! /bin/sh
#
# skeleton	example file to build /etc/init.d/ scripts.
#		This file should be used to construct scripts for /etc/init.d.
#
#		Written by Miquel van Smoorenburg <miquels@cistron.nl>.
#		Modified for Debian 
#		by Ian Murdock <imurdock@gnu.ai.mit.edu>.
#
# Version:	@(#)skeleton  1.9  26-Feb-2001  miquels@cistron.nl
#

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/lighttpd
OPTS="-f /etc/lighttpd/lighttpd.conf"
NAME=lighttpd
DESC=lighttpd

test -x $DAEMON || exit 0

# Include lighttpd defaults if available
if [ -f /etc/default/lighttpd ] ; then
	. /etc/default/lighttpd
fi

set -e

case "$1" in
  start)
	echo -n "Starting $DESC: "
	start-stop-daemon --start --quiet  \
		--pidfile /var/run/$NAME.pid --exec $DAEMON -- $OPTS
	echo "$NAME."
	;;
  stop)
	echo -n "Stopping $DESC: "
	if start-stop-daemon --stop --pidfile /var/run/$NAME.pid \
		--exec $DAEMON; then
		rm -f /var/run/$NAME.pid
		echo "$NAME."
	fi
	;;
  reload)
	#
	#	If the daemon can reload its config files on the fly
	#	for example by sending it SIGHUP, do it here.
	#
	#	If the daemon responds to changes in its config file
	#	directly anyway, make this a do-nothing entry.
	#
	echo "Reloading $DESC configuration files."
	start-stop-daemon --stop --signal 1 --quiet --pidfile /var/run/$NAME.pid \
		--exec $DAEMON
  ;;
  restart|force-reload)
	#
	#	If the "reload" option is implemented, move the "force-reload"
	#	option to the "reload" entry above. If not, "force-reload" is
	#	just the same as "restart".
	#
	echo -n "Restarting $DESC: "
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/$NAME.pid \
		--exec $DAEMON
	rm -f /var/run/$NAME.pid
	sleep 1
	start-stop-daemon --start --quiet --pidfile /var/run/$NAME.pid \
		--exec $DAEMON -- $OPTS
	echo "$NAME."
	;;
  *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	#echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
