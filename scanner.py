#!/usr/bin/env python3

print('Initializing...')

import argparse
import logging

from typing import Union, List, Tuple

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import *

SERVICE_NAMES = set(TCP_SERVICES.keys()) | set(UDP_SERVICES.keys())

def syn_scan(hosts, ports):
    print(hosts, ports)
    targets = (IP(dst=hosts) / TCP(dport=ports, flags='S'))
    print('Scanning', len(list(targets)), 'ports...')
    found, not_found = sr(targets, timeout=.1)
    return found


def port_display(sent, received):
    if 'ICMP' in sent:
        return 'icmp', sent.dst, 'ping'
    if 'UDP' in sent:
        return 'udp/%d' % sent.dport, sent.dst, 'open'
    if 'TCP' in sent:
        return ('tcp/%d' % sent.dport,
                sent.dst,
                'open' if received['TCP'].flags & 2 else 'closed')
    raise TypeError('Unknown packet type!')


def print_results(results: SndRcvList):
    results.make_lined_table(port_display)


def parse_ports(val: str) -> List[Union[int, str, Tuple[int, int]]]:
    ports = []
    for port_spec in val.split(','):
        port_spec = port_spec.strip().lower()
        m = re.match('^(\d+)-(\d+)$', port_spec)
        if m is not None:
            ports.append(tuple(map(int, m.groups())))
        elif re.match('^\d+$', port_spec):
            ports.append(int(port_spec))
        elif re.match('^\w+$', port_spec):
            if port_spec not in SERVICE_NAMES:
                raise ValueError(port_spec + ' is an unknown port name')
            ports.append(port_spec)
        else:
            break
    else:
        return ports
    raise ValueError('Invalid port specification')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'hosts',
        type=lambda x: [i.strip() for i in x.split(',')],
        help='The hosts to scan'
    )
    parser.add_argument(
        '-p',
        type=parse_ports,
        required=True,
        metavar='PORTS', dest='ports',
        help='The ports to scan on each host'
    )
    args = parser.parse_args()
    results = syn_scan(args.hosts, args.ports)
    print_results(results)


if __name__ == '__main__':
    main()
