#!/bin/bash

if [[ $# -lt 1 ]]; then
	echo "Interface required"
	exit 1
fi

sudo ip link set $1 up
sudo ip addr add 10.0.0.1/24 dev $1
sudo arp -s 10.0.0.2 aa:aa:aa:aa:aa:aa