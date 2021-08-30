#!/bin/sh
# more simpler and better alternative to make pseudoshells from webshells

# usage: run the script to copy the 1liner to clip, paste your webshell
# between do and ;done like this: 
# while IFS= read -r CMD;do curl 127.0.0.1/a.php --get --data-urlencode "p=${CMD}";done

LINE='while IFS= read -r CMD;do ;done'

exec printf "%s" "${LINE}" | xclip -selection clipboard
