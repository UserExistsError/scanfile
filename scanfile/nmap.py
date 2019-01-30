import socket
import struct
import xml.etree.ElementTree as ET
from .common import Vuln, Host, Scan


class NmapHost(Host):
    def __init__(self, elem, scan):
        Host.__init__(self)
        self.elem = elem
        self.scan = scan
        self.addr = [e.get('addr') for e in elem.findall('./address') if e.get('addrtype') == 'ipv4'][0]
        self.addr32 = struct.unpack('>L', socket.inet_aton(self.addr))[0]
        os = []
        for o in sorted(elem.findall('./os/osmatch'), key=lambda x: float(x.get('accuracy')), reverse=True):
            if not o.get('name') in self.os_matches:
                self.os_matches.append(o.get('name'))
        if len(self.os_matches):
            self.os = self.os_matches[0]
        self.names = [n.get('name') for n in elem.findall('./hostnames/hostname')]
        self.ports = sorted(set([int(e.get('portid')) for e in elem.findall('./ports/port') if e.find('state').get('state') == 'open']))


class NmapScan(Scan):
    def __init__(self, xmlscan):
        if type(xmlscan) == ET.Element:
            self.scan = xmlscan
        else:
            self.scan = ET.parse(xmlscan).getroot()
        if not Scan.is_nmap_scan(self.scan):
            raise ValueError
        self.host_root = self.scan
        self.hosts = [NmapHost(host, self) for host in self.scan.findall('./host')]
