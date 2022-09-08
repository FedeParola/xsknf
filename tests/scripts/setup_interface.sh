#!/bin/bash

if [ $# -lt 1 ]; then
  echo "usage: ${0} ifname [ifiname2 ...]"
  exit 1
fi

ifaces=""
for ifname in "$@"; do
  sudo ip link set $ifname up
  sudo ip link set $ifname promisc on
  sudo ethtool --set-priv-flags $ifname disable-fw-lldp on

  ifaces="$ifaces $ifname"
done

sudo modprobe msr
sudo wrmsr 0xc8b 0x7e0
sudo $(dirname "$0")/set_rx_queues_rss.sh 1 "$ifaces"
