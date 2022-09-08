#!/bin/bash

if [ $# -lt 1 ]; then
  echo "usage: ${0} ifname [finame2 ...]"
  exit 1
fi

for ifname in "$@"; do
  echo $ifname
  echo 0 | sudo tee /sys/class/net/$ifname/napi_defer_hard_irqs
  echo 0 | sudo tee /sys/class/net/$ifname/gro_flush_timeout
done
