#!/bin/sh
exec echo -n $(ip addr show tun0 2> /dev/null | grep -Po 'inet \K[\d.]+') | xclip -selection clipboard
