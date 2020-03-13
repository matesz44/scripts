#!/bin/sh

# wpa_passphrase <SSID> <PASSWD> > /etc/wpa_supplicant/wpa_supplicant_<SSID>.conf
# sudo wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant_<SSID>.conf

case "$(printf "TP-LINK_BCF4\\ndhclient" | dmenu -i -p "Wifi settings")" in
    "TP-LINK_BCF4") terminator -e "sudo wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant_TP-LINK_BCF4.conf" ;;
    "dhclient") sudo dhclient ;;
esac
