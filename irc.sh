#!/bin/sh
# irc rwxrob 2
name="$1"
count="$2"
log="$(date +"$name-%Y-%m-%d-$count.txt")"
serv="verne.freenode.net"
nick="asdf"
/usr/local/bin/sic -h "$serv" -n "$nick" | tee "$log"
