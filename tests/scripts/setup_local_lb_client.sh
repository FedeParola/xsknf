#!/bin/bash

if [[ $# -lt 1 ]]; then
	echo "Interface required"
	exit 1
fi

sudo ip link set $1 up
sudo ip link set $1 addr 0a:00:00:00:00:02
sudo ip addr add 172.0.0.2/24 dev $1
sudo arp -s 172.0.0.1 0a:00:00:00:00:00