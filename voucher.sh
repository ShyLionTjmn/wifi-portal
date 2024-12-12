#!/bin/sh

RED_CMD="redis-cli -s /tmp/redis.sock"

$RED_CMD -x SET wifi_portal.vouchers <<EOM
{
  "zxspectrum": {
    "until": 1728327600
  }
}
EOM
