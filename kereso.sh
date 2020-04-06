#!/bin/sh

#########################################################
# Kereso script
# Created by: M4t35Z
#########################################################
# Examples:
#
# ./kereso.sh <datafile> <word/"more words">
# 
# ./kereso.sh izelt.txt "Két pár csáppal rendelkeznek"
# OUTPUT:
# Két pár csáppal rendelkeznek --> rákok
#########################################################

grep -i "$2" "$1" |
awk -F: '{print $1, "-->", $2}'
