#!/bin/bash

NPROC=$(nproc)

if [ $# -lt 2 ]; then
  echo "usage: ${0} cores ifname [finame2 ...]"
  exit 1
fi

i=0
ifaces=""
for ifname in "$@"; do
  if [ $i -eq 0 ]; then
    ((i+=1))
    continue
  fi

  sudo ethtool -K $ifname ntuple off
  sudo ethtool -L $ifname combined $1
  ifaces="$ifaces $ifname"

  ((i+=1))
done

sudo killall irqbalance
sudo $(dirname "$0")/set_irq_affinity.sh "$ifaces"
