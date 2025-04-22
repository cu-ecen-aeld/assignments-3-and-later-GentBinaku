#!/bin/sh
### BEGIN INIT INFO
# Provides:          aesdsocket
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $network $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start AESD socket daemon
# Description:       Manages the aesdsocket daemon lifecycle
### END INIT INFO

DAEMON=/usr/local/bin/aesdsocket
DAEMON_OPTS="-d"
NAME=aesdsocket
PIDFILE=/var/run/${NAME}.pid

case "$1" in
    start)
        echo "Starting $NAME..."
        start-stop-daemon --start \
            --quiet \
            --pidfile "$PIDFILE" \
            --make-pidfile \
            --background \
            --exec "$DAEMON" -- $DAEMON_OPTS
        ;;

    stop)
        echo "Stopping $NAME..."
        start-stop-daemon --stop \
            --quiet \
            --pidfile "$PIDFILE" \
            --retry 5
        ;;

    restart)
        $0 stop
        $0 start
        ;;

    status)
        if [ -e "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
            echo "$NAME is running (PID $(cat $PIDFILE))"
            exit 0
        else
            echo "$NAME is not running"
            exit 1
        fi
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;

esac
