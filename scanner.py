#!/usr/bin/env python3

import os
import sys
import argparse
import logging


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import *

SERVICE_NAMES = set(TCP_SERVICES.keys()) | set(UDP_SERVICES.keys())

DEFAULT_TIMEOUT = .1

def syn_scan(host_ips, ports, timeout=DEFAULT_TIMEOUT):
    targets = host_ips / TCP(sport=RandShort(), dport=ports, flags='S')
    print('SYN scanning', len(list(targets)), 'ports on', len(list(host_ips)), 'hosts...')
    found, not_found = sr(targets, timeout=timeout)
    return found


def icmp_scan(host_ips, timeout=DEFAULT_TIMEOUT):
    targets = host_ips / fuzz(ICMP(type='echo-request'))
    print('Pinging', len(list(host_ips)), 'hosts...')
    found, not_found = sr(targets, timeout=timeout)
    return found


def udp_scan(host_ips, ports, timeout=DEFAULT_TIMEOUT):
    # Does not have default payloads for known services configured...
    targets = host_ips / UDP(sport=RandShort(), dport=ports) / b'hello'
    print('UDP scanning', len(list(targets)), 'ports on', len(list(host_ips)), 'hosts...')
    found, not_found = sr(targets, timeout=timeout)
    return found


def port_display(sent, received):
    if 'ICMP' in sent:
        return 'icmp', sent.dst, 'up'
    if 'UDP' in sent:
        if 'ICMP' in received:
            state = 'closed'
        else:
            state = 'open|filtered'
        return 'udp/%d' % sent.dport, sent.dst, state
    if 'TCP' in sent:
        return ('tcp/%d' % sent.dport,
                sent.dst,
                'open' if received['TCP'].flags & 2 else 'closed')
    raise TypeError('Unknown packet type!')


def print_results(results: SndRcvList):
    results.make_lined_table(port_display)


def parse_ports(val: str):
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
    if os.geteuid() != 0:
        print('Warning: this script requires root privileges', file=sys.stderr)
    parser = argparse.ArgumentParser()
    hosts_group = parser.add_mutually_exclusive_group(required=True)
    hosts_group.add_argument(
        'hosts',
        nargs='?',
        type=lambda x: [i.strip() for i in x.split(',')], default=None,
        help='The hosts to scan'
    )
    hosts_group.add_argument(
        '-i',
        type=argparse.FileType('r'), default=None, metavar='FILE', dest='hosts_file',
        help='An input file containing hosts to scan'
    )
    parser.add_argument(
        '-S',
        type=parse_ports, default=None, metavar='PORTS', dest='syn_scan',
        help='TCP SYN scan on the given ports'
    )
    parser.add_argument(
        '-I',
        action='store_true', dest='icmp_scan',
        help='ICMP Ping scan'
    )
    parser.add_argument(
        '-U',
        type=parse_ports, default=None, metavar='PORTS', dest='udp_scan',
        help='UDP scan on the given ports (limited functionality)'
    )
    parser.add_argument(
        '-q',
        action='store_true', dest='quiet',
        help='Do not show the scapy summary while scanning'
    )
    args = parser.parse_args()
    if args.quiet:
        conf.verb = False
    hosts = args.hosts
    if hosts is None:
        with args.hosts_file:
            hosts = [host for line in args.hosts_file for host in line.strip().split(',')]
    results = SndRcvList()

    host_ips = IP(dst=hosts)
    if args.icmp_scan:
        results += icmp_scan(host_ips)
    if args.syn_scan is not None:
        results += syn_scan(host_ips, args.syn_scan)
    if args.udp_scan is not None:
        results += udp_scan(host_ips, args.udp_scan)

    if len(results) == 0:
        print('No results - have you specified a scan?')
    else:
        print_results(results)


if __name__ == '__main__':
    main()
