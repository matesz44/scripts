#!/bin/sh

# my preferred style.css is at https://m4t3sz.gitlab.io/bsc/style.css
echo '<html><head><link rel=stylesheet type=text/css href=style.css></head><body>' > $1.html
exec smu $1.md >> $1.html
