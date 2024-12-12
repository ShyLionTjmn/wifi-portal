#!/bin/sh
PROG="wifi-portal"
SERVICE="wifi-portal"

cd build
go build ../ && sudo install $PROG /usr/local/sbin/ && sudo systemctl restart $SERVICE && sleep 1 && sudo systemctl --no-pager status $SERVICE && echo "Check later:" && echo "sudo systemctl --no-pager status $SERVICE"
