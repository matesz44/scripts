#!/bin/sh

exec rlwrap nc -l -n -vv -p $1
