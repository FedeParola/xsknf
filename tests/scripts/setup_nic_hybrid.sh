#!/bin/bash

if [ $# -lt 3 ]; then
  echo "usage: ${0} ifname total_queues passthrough_queues"
  exit 1
fi

sudo ethtool -K ${1} ntuple on
sudo ethtool --set-priv-flags ${1} flow-director-atr on
rss_string=""

for ((queue=0; queue<${2}; queue++)); do
    sudo ethtool -N ${1} flow-type udp4 dst-ip 172.0.0.$(($queue+1)) action $queue
    if [ $queue -lt ${3} ]; then
        rss_string="$rss_string 0"
    else
		rss_string="$rss_string 1"
	fi
done

sudo ethtool -X ${1} weight $rss_string