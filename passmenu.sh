#!/usr/bin/env bash

# original script:
# https://git.zx2c4.com/password-store/tree/contrib/dmenu/passmenu

# my edits:
# - removed unnecessary code
# - added pass otp support
#   - If the pass-name ends with -otp it will use pass otp
#       in order to get the code instead of the URI

prefix=${PASSWORD_STORE_DIR-~/.password-store}
password_files=( "$prefix"/**/*.gpg )
password_files=( "${password_files[@]#"$prefix"/}" )
password_files=( "${password_files[@]%.gpg}" )

password=$(printf '%s\n' "${password_files[@]}" | dmenu "$@")

if [[ "$password" == *-otp ]]
then
    pass otp show -c "$password" 2>/dev/null
else
    pass show -c "$password" 2>/dev/null
fi
