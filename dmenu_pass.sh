#!/bin/sh

# Original script: https://efe.kim/files/scripts/dmenu_pass 

# Since I use otp I needed to add the check if the line ends with -otp
# I set up pws like this: site/user, site/user-otp, site/user-otp-recovery

# I needed the directories. I'm bad with regex so if you know a shorer
# one for this(delete everything except dirs in the ~/.password-store dir) 
# let me know :D

password=$(find ~/.password-store/ -type f -name '*.gpg' |
    sed 's/.*\/\.password-store\/\(.*\)\.gpg$/\1/' |
    dmenu -i)

case $password in
    *-otp) pass otp show -c "$password" ;;
    */*) pass show -c "$password" ;;
    *) exit 0 ;;
esac
