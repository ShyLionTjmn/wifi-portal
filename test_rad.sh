#!/bin/sh

(cat <<EOM
User-Name = a
User-Password = a
EOM
) | radclient -4 -x 127.0.0.1:1812 auth secret
