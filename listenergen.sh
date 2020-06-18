#!/bin/sh

# -- Just a dmenu wrapper --
# It just needs a port and a listener type
# and u get the listener with a port u set
# Created by M4t35Z

# Inspired by: 
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

port="$($1 | dmenu -p "Gimme a port u wanna listen on")"

# Replace vars if they are empty
case "" in
    $port) port=1234 ;;
esac

# Listener copypasta
nc1_shell="nc -lvnp $port"
ncx_shell="rlwrap nc -l -n -vv -p $port"
ncu_shell="nc -u -lvnp $port"
socat_shell="socat file:\`tty\`,raw,echo=0 TCP-L:$port"
openssl_shell="openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes && openssl s_server -quiet -key key.pem -cert cert.pem -port $port"
ncatssl_shell="ncat --ssl -vv -l -p $port"

# Texts
nc1_text="nc1 (most basic) -> $nc1_shell"
ncx_text="ncx (xtreme (rlwrap)) -> $ncx_shell"
ncu_text="ncu (udp) -> $ncu_shell"
socat_text="socat -> $socat_shell"
openssl_text="openssl -> $openssl_shell"
ncatssl_text="ncat (ssl) -> $ncatssl_shell"

# The Juicy part
case "$(printf "$nc1_text\\n$ncx_text\\n$ncu_text\\n$socat_text\\n$openssl_text\\n$ncatssl_text" | dmenu -l 10 -i -p "L1573n3rZ")" in

    ## nc
    "$nc1_text") echo -n "$nc1_shell" | xclip -selection clipboard ;;
    "$ncx_text") echo -n "$ncx_shell" | xclip -selection clipboard ;;
    "$ncu_text") echo -n "$ncu_shell" | xclip -selection clipboard ;;
    
    ## socat
    "$socat_text") echo -n "$socat_shell" | xclip -selection clipboard ;;

    ## openssl
    "$openssl_text") echo -n "$openssl_shell" | xclip -selection clipboard ;;
    "$ncatssl_text") echo -n "$ncatssl_shell" | xclip -selection clipboard ;;
esac
