import re
import os
import socket
import struct
import xml.dom.minidom
import xml.etree.ElementTree as ET

class Addr4():
    def __init__(self, addr):
        try:
            socket.inet_pton(socket.AF_INET, addr)
        except:
            raise ValueError('invalid ipv4 address')
        self.addr = addr
        self.addr32 = 0
    def mask_net(self, mask):
        pass

class CIDRRange():
    def __init__(self, cidr):
        ''' takes cidr string '''
        self.cidr = cidr.strip()
        net, mask_bits = cidr.strip().split('/')
        mask_bits = int(mask_bits)
        self.mask_bits = mask_bits
        self.mask = (2**mask_bits-1) << (32-mask_bits)
        self.net = struct.unpack('>L', socket.inet_aton(net))[0] & self.mask
        self.bcast = ((1 << (32-mask_bits)) - 1) | self.net
    def overlaps(self, other):
        mask = min(self.mask, other.mask)
        if (mask & self.net) == (mask & other.net):
            return True
        return False
    def __contains__(self, addr):
        return self.in_range(addr)
    def in_range(self, addr):
        if type(addr) == str:
            addr = struct.unpack('>L', socket.inet_aton(addr))[0]
        if addr & self.mask == self.net:
            return True
        return False
    def __str__(self):
        return self.cidr
    def __eq__(self, other):
        return hash(self) == hash(other)
    def __hash__(self):
        return hash(self.cidr)
    def __iter__(self):
        self.next_addr = self.net
        self.last_addr = self.bcast
        return self
    def __next__(self):
        if self.next_addr > self.last_addr:
            raise StopIteration
        addr = self.next_addr
        self.next_addr += 1
        return socket.inet_ntoa(struct.pack('>L', addr))
    def netmap(self, addr, to_cidr):
        host32 = self.mask_host(addr)
        return socket.inet_ntop(socket.AF_INET, struct.pack('>L', to_cidr.net | host32))
    def mask_net(self, addr):
        pass
    def mask_host(self, addr):
        addr32 = struct.unpack('>L', socket.inet_pton(socket.AF_INET, addr))[0]
        host_mask = 2**(32 - self.mask_bits) - 1
        return addr32 & host_mask

class Vuln():
    def __init__(self):
        self.title = None
        self.synopsis = None
        self.port = None
        self.protocol = None
        self.severity = None
        self.elem = None
        self.plugin_id = None
    def __str__(self):
        return '{} {:.1f} {}'.format(self.port, self.severity, self.title)

class Host():
    def __init__(self):
        self.host = None
        self.addr = None
        self.addr32 = None
        self.os = None
        self.os_matches = []
        self.names = []
        self.vulns = []
        self.ports = []
    def __str__(self):
        return 'addr={}, os={}, names={}'.format(self.addr, self.os, ';'.join(self.names))
    def get_info_string(self):
        s = ''
        s += 'Address {}\n'.format(self.addr)
        s += 'Hostname {}\n'.format(', '.join(self.names))
        for v in self.vulns:
            s += v.title + '\n'
        return s
    def add_vuln(self, vuln):
        raise NotImplementedError('must be implemented in a subclass')
    def remove_vuln(self, vuln):
        raise NotImplementedError('must be implemented in a subclass')
    def get_vulns(self):
        return self.vulns
    def in_cidr(self, cidr):
        if cidr.in_range(self.addr32):
            return True
        return False
    def __iter__(self):
        self._iter_index = 0
        return self
    def __next__(self):
        try:
            self._iter_index += 1
            return self.vulns[self._iter_index - 1]
        except IndexError:
            raise StopIteration
    def __len__(self):
        return len(self.vulns)


class Scan():
    @staticmethod
    def parse_scan_xml(xmlfile):
        return ET.parse(xmlfile).getroot()
    @staticmethod
    def is_nessus_scan(scan):
        return scan.tag.startswith('NessusClientData')
    @staticmethod
    def is_nexpose_scan(scan):
        return scan.tag == 'NexposeReport'
    @staticmethod
    def is_nmap_scan(scan):
        return scan.tag == 'nmaprun'
    def remove_all_hosts(self):
        for h in list(self.host_root):
            self.host_root.remove(h)
        self.hosts = []
    def remove_host(self, host):
        self.host_root.remove(host.elem)
        self.hosts.remove(host)
    def add_host(self, host):
        self.host_root.append(host.elem)
        self.hosts.append(host)
        host.scan = self
    def get_xml(self, pretty=False):
        # convert xml obj to string and remove extra whitespace between tags
        xml_str = re.sub(b'>\s+<', b'><', ET.tostring(self.scan, encoding='utf-8', method='xml'))
        if pretty:
            # takes longer, uses more space
            xml_str = xml.dom.minidom.parseString(xml_str).toprettyxml()
        else:
            xml_str = xml_str.decode()
        return xml_str
    def dump(self, filename, pretty=False, overwrite=False):
        if not overwrite and os.path.exists(filename):
            raise FileExistsError(filename)
        open(filename, 'w').write(self.get_xml(pretty))
    def __iter__(self):
        self._iter_index = 0
        return self
    def __next__(self):
        try:
            self._iter_index += 1
            return self.hosts[self._iter_index - 1]
        except IndexError:
            raise StopIteration
    def __len__(self):
        return len(self.hosts)
