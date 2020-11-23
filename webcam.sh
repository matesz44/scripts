#!/bin/sh
# Install
# https://github.com/umlaeute/v4l2loopback
# apt install v4l2loopback-dkms
# modprobe v4l2loopback
# ----------------------------------------
# 
# Examples:
# Image
# static img: ffmpeg -loop 1 -re -i foo.jpg -f v4l2 -vcodec rawvideo -pix_fmt yuv420p /dev/video0
# Video
# webcam gandalf.mp4 /dev/video0
while true;
do ffmpeg -re -i "$1" -f v4l2 "$2"
done

