#!/usr/bin/env python3
import os
import sys
import socket
import logging
import argparse
import collections

from scanfile.nmap import NmapScan
from scanfile.nessus import NessusScan
from scanfile.nexpose import NexposeScan
from scanfile.common import Scan, CIDRRange

# lxml handles namespaces much better
import xml.etree.ElementTree as ET
#from lxml import etree as ET

'''
Manipulate XML scan files for nexpose, nessus, and nmap
'''

logger = logging.getLogger(__name__)


def get_scan_object(xmlfile):
    ''' takes xml text or xml file path and returns appropriate Scan object '''
    if type(xmlfile) == str:
        scan = Scan.parse_scan_xml(xmlfile)
    else:
        scan = xmlfile
    if Scan.is_nexpose_scan(scan):
        return NexposeScan(scan)
    elif Scan.is_nessus_scan(scan):
        return NessusScan(scan)
    elif Scan.is_nmap_scan(scan):
        return NmapScan(scan)
    raise NotImplementedError


def handle_host_name(args, scan):
    imap = {}
    for l in open(args.filename):
        ip, name = l.lower().strip().split(' ')
        logger.debug('{} {}'.format(ip, name))
        imap[ip] = name
    for host in scan:
        if host.addr in imap:
            logger.debug('Adding hostname {}: {}'.format(imap[host.addr], host.addr))
            host.add_hostname(imap[host.addr])

def handle_host_netmap(args, scan):
    nfrom = CIDRRange(args.net_from)
    nto = CIDRRange(args.net_to)
    for host in scan:
        if host.addr in nfrom:
            newaddr = nfrom.netmap(host.addr, nto)
            logger.debug('netmap {} -> {}'.format(host.addr, newaddr))
            host.change_addr(newaddr)

def handle_host_removebad(args, scan):
    ''' remove hosts that are not responsive (eg tcp rst on every port) '''
    scan.remove_false()


def handle_host_remove(args, scan):
    targets = args.hosts
    if args.filename:
        targets.extend([l.strip() for l in open(args.filename)])
    addrs = set()
    cidrs = set()
    for t in set(targets):
        if len(t) == 0:
            continue
        try:
            socket.inet_aton(t.split('/')[0])
        except:
            raise ValueError('Invalid address or range: '+t)
        if t.find('/') > 0:
            cidrs.add(CIDRRange(t))
        else:
            addrs.add(t)
    if args.invert:
        for h in scan:
            if h.addr not in addrs:
                found = False
                for c in cidrs:
                    if h.in_cidr(c):
                        found = True
                        break
                if not found:
                    scan.remove_host(h)
                    logger.debug('Removed host '+h.addr)
    else:
        for h in scan:
            if h.addr in addrs:
                scan.remove_host(h)
                logger.debug('Removed host '+h.addr)
            else:
                for c in cidrs:
                    if h.in_cidr(c):
                        scan.remove_host(h)
                        logger.debug('Removed host '+h.addr)
                        break

def handle_host_list(args, scan):
    for h in scan:
        if args.verbose:
            print(h.addr, len(h.vulns))
        else:
            print(h.addr)

def handle_plugin_remove(args, scan):
    pids = args.pids
    if args.filename:
        pids.extend([l.strip() for l in open(args.filename)])
    pids = set(pids)
    for h in scan:
        for v in h:
            pid = v.plugin_id
            if args.invert:
                if pid not in pids:
                    h.remove_plugin(pid)
                    logger.debug('Removed plugin '+str(pid))
            else:
                if pid in pids:
                    h.remove_plugin(pid)
                    logger.debug('Removed plugin '+str(pid))

def handle_plugin_list(args, scan):
    ''' enumerate unique plugins '''
    pids = set()
    if type(scan) == NessusScan:
        for h in scan:
            for v in h:
                pid = v.plugin_id
                if pid not in pids:
                    print(pid, v.elem.get('pluginName'))
                    pids.add(pid)
    elif type(scan) == NexposeScan:
        for h in scan:
            for v in h:
                pid = v.plugin_id
                if pid not in pids:
                    print(pid, scan.vuln_defs[pid].get('title'))
                    pids.add(pid)

def handle_ports(args, scan):
    tcp_ports = set()
    udp_ports = set()
    assets = []                 # assets with open ports
    port_count = collections.defaultdict(int)
    for host in scan:
        flag = 0
        for vuln in host:
            if vuln.port != 0:
                flag = 1
                if vuln.protocol == 'tcp':
                    tcp_ports.add(vuln.port)
                elif vuln.protocol == 'udp':
                    udp_ports.add(vuln.port)
                port_count[vuln.port] += 1
        if flag:
            assets.append(host)
    if args.details:
        # total open ports and assets with open ports
        print('Total open ports:  {}'.format(len(tcp_ports) + len(udp_ports)))
        print('Assets with ports: {}'.format(len(assets)))
        # port and host count
        for p in sorted(port_count, key=lambda k:port_count[k]):
            print('{} {}'.format(p, port_count[p]))
    else:
        for t in sorted(tcp_ports):
            print('tcp/{}'.format(t))
        for u in sorted(udp_ports):
            print('udp/{}'.format(u))


def handle_host_vulns(args, scan):
    for h in scan:
        for v in h:
            print(h.addr, v.port, v.plugin_id, v.title)


def handle_host_port(args, scan):
    if args.port:
        for h in scan:
            if args.port in h.ports:
                print(h.addr)
    else:
        for h in scan:
            print(h.addr, ','.join(map(str, h.ports)))

def handle_host_info(args, scan):
    for h in scan:
        print(h.addr, len(h.vulns))


def handle_split(args, scan):
    hosts = list(scan.hosts)
    targets = args.hosts
    if args.filename:
        targets.extend([l.strip() for l in open(args.filename)])
    addrs = set()
    cidrs = set()
    f, e = os.path.splitext(args.scanname)
    for t in set(targets):
        if len(t) == 0:
            continue
        try:
            socket.inet_aton(t.split('/')[0])
        except:
            raise ValueError('Invalid address or range: '+t)
        if t.find('/') > 0:
            cidr = CIDRRange(t)
            for c in cidrs:
                if cidr.overlaps(c):
                    raise ValueError('Overlapping ranges specified: {} and {}'.format(c.cidr, cidr.cidr))
            cidrs.add(cidr)
        else:
            addrs.add(t)

    if args.number:
        host_partitions = (hosts[i:i+args.number] for i in range(0, len(hosts), args.number))
        i = 0
        for p in host_partitions:
            scan.remove_all_hosts()
            for h in p:
                scan.add_host(h)
            name, ext = os.path.splitext(args.scanname)
            fn = '{}.{}-{}{}'.format(f, i, i+len(p)-1, e)
            logger.debug('Writing {} hosts to {}'.format(len(p), fn))
            scan.dump(fn, args.pretty)
            i += len(p)
    else:
        scan.remove_all_hosts()
        # write out scan files for single addresses
        cidr_hosts = collections.defaultdict(list)
        remaining_hosts = []
        for h in hosts:
            if h.addr in addrs:
                scan.add_host(h)
                fn = '{}_{}{}'.format(f, h.addr, e)
                scan.dump(fn)
                scan.remove_all_hosts()
            else:
                flag = 0
                for c in cidrs:
                    if h.in_cidr(c):
                        cidr_hosts[str(c)].append(h)
                        flag = 1
                        break
                if not flag:
                    remaining_hosts.append(h)
        # write out scan files for ranges
        for c in cidr_hosts:
            for h in cidr_hosts[c]:
                scan.add_host(h)
            fn = '{}_{}{}'.format(f, str(c).replace('/', '-'), e)
            scan.dump(fn)
            scan.remove_all_hosts()
        # add remaining hosts that didn't match an addr or cidr into a single file
        if len(remaining_hosts):
            for h in remaining_hosts:
                scan.add_host(h)
            fn = '{}_other{}'.format(f, e)
            scan.dump(fn)
            scan.remove_all_hosts()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manipulate hosts/plugins in a neXpose (XML 2.0), nessus (.nessus), or nmap (XML) scan file. File type is determined by inspection.')
    parser.set_defaults(handle=None)
    parser.add_argument('-o', '--outfile', help='output modified scan file')
    parser.add_argument('--pretty', action='store_true', help='output pretty xml')
    parser.add_argument('--debug', action='store_true', help='enable debug output')
    parser.add_argument('scanner_file', help='scanner export file')
    parser.set_defaults(scanname=None)
    subparsers = parser.add_subparsers(help='choose an item to act on')

    split_parser = subparsers.add_parser('split', help='split scan file by addr or cidr')
    split_parser.add_argument('-n', '--number', type=int, help='hosts per file')
    split_parser.set_defaults(handle=handle_split)
    split_parser.add_argument('-f', '--filename', help='addresses or CIDR ranges, 1 per line')
    split_parser.add_argument('hosts', nargs='*', default=[], help='list of host addresses or CIDR ranges')

    host_parser = subparsers.add_parser('host', help='manipulate hosts')
    host_subparser = host_parser.add_subparsers(help='choose an action')
    host_remove_parser = host_subparser.add_parser('remove', help='remove hosts')
    host_remove_parser.set_defaults(handle=handle_host_remove)
    host_remove_parser.add_argument('-v', '--invert', action='store_true', help='keep only specified hosts')
    host_remove_parser.add_argument('-f', '--filename', help='addresses or CIDR ranges, 1 per line')
    host_remove_parser.add_argument('hosts', nargs='*', default=[], help='list of host addresses or CIDR ranges')
    host_removebad_parser = host_subparser.add_parser('removebad', help='remove bad hosts')
    host_removebad_parser.set_defaults(handle=handle_host_removebad)
    host_list_parser = host_subparser.add_parser('list', help='list hosts')
    host_list_parser.add_argument('-v', '--verbose', action='store_true', help='enable verbose output')
    host_list_parser.set_defaults(handle=handle_host_list)
    host_info_parser = host_subparser.add_parser('info', help='host information')
    host_info_parser.set_defaults(handle=handle_host_info)
    host_info_parser.add_argument('hosts', nargs='*', default=[], help='list of host addresses')
    host_vuln_parser = host_subparser.add_parser('vulns', help='list host+vulns')
    host_vuln_parser.set_defaults(handle=handle_host_vulns)

    host_port_parser = host_subparser.add_parser('ports', help='list host+ports')
    host_port_parser.add_argument('-p', '--port', type=int)
    host_port_parser.set_defaults(handle=handle_host_port)

    name_parser = host_subparser.add_parser('name', help='add hostname')
    name_parser.add_argument('-f', '--filename', help='file with lines ip,hostname')
    name_parser.set_defaults(handle=handle_host_name)

    netmap_parser = host_subparser.add_parser('netmap', help='map ips in a network to a new network')
    netmap_parser.add_argument('net_from', help='cidr network to map')
    netmap_parser.add_argument('net_to', help='cidr network dest')
    netmap_parser.set_defaults(handle=handle_host_netmap)

    plugin_parser = subparsers.add_parser('plugin', help='manipulate plugins')
    plugin_subparser = plugin_parser.add_subparsers(help='')
    plugin_remove_parser = plugin_subparser.add_parser('remove', help='remove plugins')
    plugin_remove_parser.set_defaults(handle=handle_plugin_remove)
    plugin_remove_parser.add_argument('-v', '--invert', action='store_true', help='keep only specified plugins')
    plugin_remove_parser.add_argument('-f', '--filename', help='plugin IDs, 1 per line')
    plugin_remove_parser.add_argument('pids', default=[], nargs='*', help='list of plugins')

    plugin_list_parser = plugin_subparser.add_parser('list', help='list plugins')
    plugin_list_parser.set_defaults(handle=handle_plugin_list)

    port_parser = subparsers.add_parser('ports', help='list discovered ports')
    port_parser.set_defaults(handle=handle_ports)
    port_parser.add_argument('--details', action='store_true', help='ports and services report')

    args = parser.parse_args()
    args.scanname = os.path.basename(args.scanner_file)
    if not args.handle:
        print('Choose an action. List actions with -h')
        sys.exit()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[%(levelname)s]:%(lineno)s %(message)s'))
        logger.addHandler(h)

    scan = get_scan_object(args.scanner_file)
    args.handle(args, scan)

    if args.outfile:
        if args.outfile == args.scanner_file:
            print('Refusing to overwrite input file')
            sys.exit()
        with open(args.outfile, 'w') as fp:
            fp.write(scan.get_xml(args.pretty))
