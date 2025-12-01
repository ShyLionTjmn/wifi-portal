#!/bin/sh
PROG="wifi-portal"
SERVICE="wifi-portal"

LEVEL=0

if [ ! -z "$1" ]
then
  LEVEL="$1"
fi

cd build
go build ../ && sudo install $PROG /usr/local/sbin/ && sudo /usr/local/sbin/$PROG -v $LEVEL
