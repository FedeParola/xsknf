#!/bin/bash

if [[ $# -lt 1 ]]; then
	echo "Interface required"
	exit 1
fi

if  [ $# -lt 2 ]; then
	queues=1
else
	queues=$2
fi

sudo ip link del veth1a

sudo ip addr add 192.168.0.1/24 dev lo

sudo ip link set $1 up
sudo ip link set $1 addr 0a:00:00:00:00:00
sudo ip addr add 172.0.0.1/24 dev $1
$HOME/scripts/set-rx-queues-rss.sh $queues $1

sudo arp -s 172.0.0.2 0a:00:00:00:00:00

echo "2 2" > services.txt
echo "172.0.0.1 11211 TCP 192.168.0.1 11211 0a:00:00:00:00:00 local" >> services.txt
echo "172.0.0.1 11211 UDP 192.168.0.1 11211 0a:00:00:00:00:00 local" >> services.txt