#!/usr/bin/python3

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('services', help='Number of distinct virtual services generate',
                    type=int)
parser.add_argument('backends', help='Number of backends per service',
                    type=int)
args = parser.parse_args()

tot_backends = args.services * args.backends

if args.services <= 0 or args.backends <= 0:
  print("Services and backends number must be > 0")
  exit(1)

with open('services.txt', 'w') as services:
  services.write(f'{args.services} {tot_backends}\n')

  for service in range(1, args.services + 1):
    srv_first = service & 0xff
    srv_second = service >> 8 & 0xff
    srv_third = service >> 16 & 0xff

    for backend in range(1, args.backends + 1):
      bkd_first = backend & 0xff
      bkd_second = backend >> 8 & 0xff
      bkd_third = backend >> 16 & 0xff

      services.write(f'172.{srv_third}.{srv_second}.{srv_first} 80 UDP 192.{bkd_third}.{bkd_second}.{bkd_first} 80 0a:00:00:00:00:01 ens1f0\n')