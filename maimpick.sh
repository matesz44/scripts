#!/bin/sh

case "$(printf "a selected area\\ncurrent window\\nfull screen\\na selected area (copy)\\ncurrent window (copy)\\nfull screen (copy)" | dmenu -l 6 -i -p "Screenshot which area?")" in
	"a selected area") maim -s scr-"$(date '+%y%m%d-%H%M-%S').png" ;;
	"current window") maim -i "$(xdotool getactivewindow)" pic-window-"$(date '+%y%m%d-%H%M-%S').png" ;;
	"full screen") maim pic-full-"$(date '+%y%m%d-%H%M-%S').png" ;;
	"a selected area (copy)") maim -s | xclip -selection clipboard -t image/png ;;
	"current window (copy)") maim -i "$(xdotool getactivewindow)" | xclip -selection clipboard -t image/png ;;
	"full screen (copy)") maim | xclip -selection clipboard -t image/png ;;
esac
