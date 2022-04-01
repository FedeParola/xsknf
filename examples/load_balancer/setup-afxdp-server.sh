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

sudo ip link add veth1a numrxqueues $queues numtxqueues $queues type veth \
		peer veth1b numrxqueues $queues numtxqueues $queues
sudo ip link set veth1a up
sudo ip link set veth1b up
sudo ip addr del 172.0.0.1/24 dev $1
sudo ip addr del 192.168.0.1/24 dev lo
sudo ip addr add 192.168.0.1/24 dev veth1a

# Needed, otherwise TCP/UDP checksums are wrong
sudo ethtool -K veth1a tx-checksum-ip-generic off
# Avoid arp requests when the backend tries to contact the client
sudo ip route add 172.0.0.0/24 via 192.168.0.254
mac=$(cat /sys/class/net/$1/address)
sudo arp -s 192.168.0.254 $mac

mac=$(cat /sys/class/net/veth1a/address)

echo "2 2" > services.txt
echo "172.0.0.1 11211 TCP 192.168.0.1 11211 $mac veth1b" >> services.txt
echo "172.0.0.1 11211 UDP 192.168.0.1 11211 $mac veth1b" >> services.txt

sudo ip link set $1 up
sudo ip link set $1 promisc on
$HOME/scripts/set-rx-queues-rss.sh $queues $1