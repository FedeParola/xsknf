#!/usr/bin/python3

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('rules', help='Number of rules (different src ip address) to generate',
                    type=int)
args = parser.parse_args()

with open('acl.txt', 'w') as acl:
  acl.write(f'{args.rules}\n')

  for i in range(args.rules):
    first = i & 0xff
    second = i >> 8 & 0xff
    third = i >> 16 & 0xff
    acl.write(f'11.{third}.{second}.{first} 172.0.0.1 5000 80 UDP DROP\n')