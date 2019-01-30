import socket
import struct
import xml.etree.ElementTree as ET
from .common import Vuln, Host, Scan

'''
<NessusClientData_v2>
  <Report name="custom" xmlns:cm="http://www.nessus.org/cm">
    <ReportHost name="127.0.0.1">
      <HostProperties>
        <tag name="host-ip">127.0.0.1</tag>
        <tag name="host-fqdn">hostname</tag>
      </HostProperties>
      <ReportItem/>
    </ReportHost>
  </Report>
</NessusClientData_v2>
'''

g_nessus_vuln_xml = '''
<ReportItem/>
'''

g_nessus_host_xml = '''
<ReportHost name="">
  <HostProperties>
    <tag name="host-ip"></tag>
    <tag name="host-fqdn"></tag>
  </HostProperties>
<ReportItem/>
'''

g_nessus_scan_xml = '''
<NessusClientData_v2>
  <Report name="custom" xmlns:cm="http://www.nessus.org/cm">
  </Report>
</NessusClientData_v2>'''



class NessusVuln(Vuln):
    def __init__(self, elem=g_nessus_vuln_xml, host=None):
        ''' elem is the ReportItem '''
        if type(elem) != ET.Element:
            elem = ET.parse(xmlscan).getroot()
        self.elem = elem
        self.host = host
        self.title = elem.get('pluginName')
        try:
            self.synopsis = elem.find('synopsis').text
        except:
            self.synopsis = ''
        self.port = int(elem.get('port'))
        self.protocol = elem.get('protocol')
        self.severity = int(elem.get('severity'))
        self.plugin_id = elem.get('pluginID')

class NessusHost(Host):
    def __init__(self, elem=g_nessus_host_xml, scan=None):
        Host.__init__(self)
        if type(elem) != ET.Element:
            elem = ET.parse(xmlscan).getroot()
        self.elem = elem
        self.scan = scan
        addrs = [t for t in elem.findall('./HostProperties/tag') if t.get('name') == 'host-ip']
        if len(addrs):
            self.addr = addrs[0].text
        else:
            self.addr = elem.get('name')
        self.addr32 = struct.unpack('>L', socket.inet_aton(self.addr))[0]
        os = [t for t in elem.findall('./HostProperties/tag') if t.get('name') == 'operating-system']
        if len(os):
            self.os_matches = os[0].text.split('\n')
        if len(self.os_matches):
            self.os = self.os_matches[0]
        self.names = [t.text for t in elem.findall('./HostProperties/tag') if t.get('name') == 'host-fqdn']
        self.ports = sorted(set([int(r.get('port')) for r in elem.findall('./ReportItem') if r.get('pluginFamily') == 'Port scanners']))
        self.vulns = [NessusVuln(e, self) for e in elem.findall('./ReportItem')]
        self.parent_map = {c:p for p in elem.iter() for c in p}
    def add_hostname(self, hostname):
        props = self.elem.find('./HostProperties')
        e = ET.Element('tag', {'name': 'host-fqdn'})
        e.text = hostname
        props.append(e)
    def change_addr(self, addr):
        # traceroute last hop will be inaccurate
        self.elem.attrib['name'] = addr
        for t in self.elem.findall('./HostProperties/tag'):
            if t.get('name') == 'host-ip':
                t.text = addr
    def remove_vuln(self, vuln):
        return self.remove_plugin(vuln.plugin_id)
    def remove_plugin(self, plugin_id):
        vulns = []
        for v in self.vulns:
            if v.plugin_id != plugin_id:
                vulns.append(v)
            else:
                self.parent_map[v.elem].remove(v.elem)
        self.vulns = vulns


class NessusScan(Scan):
    def __init__(self, xmlscan=g_nessus_scan_xml):
        #if type(xmlscan) in [ET.Element, ET._Element]:
        if type(xmlscan) == ET.Element:

            self.scan = xmlscan
        else:
            self.scan = ET.parse(xmlscan).getroot()
        if not Scan.is_nessus_scan(self.scan):
            raise ValueError
        self.host_root = self.scan.find('./Report')
        self.hosts = [NessusHost(host, self) for host in self.scan.findall('./Report/ReportHost')]
    def remove_false(self):
        ''' find hosts that are likely not there. sometimes nessus will count an IP
        as active if there is at least 1 response during a traceroute '''
        hosts = list(self.hosts)
        for host in hosts:
            flag = False
            # plugin IDs
            # nessus scan information 19506
            # traceroute 10287
            # syn scanner 11219
            # udp scanner 34277
            # cisco asa 93347
            # cisco smart install 105161
            # fqdn resolution 12053
            # icmp timestamp 10114
            # 19506+10287 ONLY probably means host sent a TCP RST at some point
            for item in host.elem.findall('./ReportItem'):
#                if item.get('pluginID', None) in ['19506', '10287', '46215', '10919']: 
#                    continue
                #if item.get('pluginID', '19506') not in ['19506', '10287', '12053', '10114', '105161']:
                if item.get('pluginID', None) in ['11219', '34277']:
                    flag = True
                    break
            if not flag:
                print('FALSE', host.elem.get('name'))
                self.remove_host(host)
