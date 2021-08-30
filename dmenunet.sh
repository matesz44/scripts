#!/bin/sh

# wpa_passphrase <SSID> <PASSWD> > /etc/wpa_supplicant/wpa_supplicant_<SSID>.conf
# sudo wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant_<SSID>.conf

case "$(printf "TP-LINK_BCF4\\neth0\\ndhcpcd" | dmenu -i -p "Internet")" in
    "TP-LINK_BCF4") st -e sudo wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant_TP-LINK_BCF4.conf ;;
    "DAVIDEK") st -e sudo wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant_DAVIDEK.conf ;;
    "dhcpcd") sudo -A dhcpcd ;;
    "eth0") sudo -A ip link set eth0 up ;;
esac
