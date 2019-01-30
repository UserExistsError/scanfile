import socket
import struct
import xml.dom.minidom
import xml.etree.ElementTree as ET

from .common import Vuln, Host, Scan

g_nexpose_vuln_xml = '''
<test/>
'''

g_nexpose_host_xml = '''
<node address="" status="alive" site-name="custom">
  <fingerprints/>
  <tests/>
  <endpoints/>
</node>
'''

g_nexpose_scan_xml = '''
<NexposeReport version="2.0">
  <scans/>
  <nodes/>
  <VulnerabilityDefinitions/>
</NexposeReport>
'''

class NexposeVuln(Vuln):
    def __init__(self, elem=g_nexpose_vuln_xml, host=None, endpoint=None):
        ''' elem is <test> '''
        if type(elem) != ET.Element:
            elem = ET.parse(xmlscan).getroot()
        self.elem = elem
        self.host = host        # NexposeHost object
        self.vuln = host.scan.vuln_defs[elem.get('id')]
        self.title = self.vuln.get('title')
        self.synopsis = ''#self.vuln.find('./description/ContainerBlockElement/Paragraph').text
        if endpoint and endpoint.get('port'):
            self.port = int(endpoint.get('port', 0))
            self.protocol = endpoint.get('protocol', None)
        else:
            self.port = 0
            self.protocol = 0
        self.severity = int(self.vuln.get('severity'))
        self.plugin_id = elem.get('id')

class NexposeHost(Host):
    def __init__(self, elem=g_nexpose_host_xml, scan=None):
        ''' elem - ElementTree object
            scan NexposeScan object '''
        Host.__init__(self)
        if type(elem) != ET.Element:
            elem = ET.parse(xmlscan).getroot()
        self.elem = elem
        self.scan = scan
        self.addr = elem.get('address')
        self.addr32 = struct.unpack('>L', socket.inet_aton(self.addr))[0]
        os = []
        for o in sorted(elem.findall('./fingerprints/os'), key=lambda x: float(x.get('certainty')), reverse=True):
            if not o.get('product') in self.os_matches:
                self.os_matches.append(o.get('product'))
        if len(self.os_matches):
            self.os = self.os_matches[0]
        self.names = [n.text for n in elem.findall('./names/name')]
        self.ports = sorted(set([int(e.get('port')) for e in elem.findall('./endpoints/endpoint') if e.get('status') == 'open']))
        self.parent_map = {c:p for p in elem.iter() for c in p}
        self.vulns = []
        for e in elem.findall('.//endpoint'):
            for v in e.findall('.//test'):
                if v.get('id'):
                    self.vulns.append(NexposeVuln(v, self, endpoint=e))
        for v in elem.findall('./tests/test'):
            if v.get('id'):
                self.vulns.append(NexposeVuln(v, self))
        #self.vulns = [NexposeVuln(e, self) for e in elem.findall('.//test') if e.get('id', False)]
#    def add_vuln(self, 
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
    def add_hostname(self, hostname):
        names = self.elem.find('./names')
        if names == None:
            names = ET.Element('names')
            self.elem.append(names)
        e = ET.Element('name')
        e.text = hostname
        names.append(e)
    def change_addr(self, addr):
        # traceroute last hop will be inaccurate
        self.elem.attrib['address'] = addr
        for t in self.elem.findall('./HostProperties/tag'):
            if t.get('name') == 'host-ip':
                t.text = addr


class NexposeScan(Scan):
    def __init__(self, xmlscan=ET.fromstring(g_nexpose_scan_xml)):
        if type(xmlscan) == ET.Element:
            self.scan = xmlscan
        else:
            self.scan = ET.parse(xmlscan).getroot()
        if not Scan.is_nexpose_scan(self.scan):
            raise ValueError
        self.elem = self.scan
        self.vuln_defs = {v.get('id'):v for v in self.elem.findall('./VulnerabilityDefinitions/vulnerability')}
        self.host_root = self.scan.find('./nodes')
        # self.vuln_defs = {}
        # self.rebuild_vuln_db()
        self.hosts = [NexposeHost(host, self) for host in self.elem.findall('./nodes/node')]
    def rebuild_vuln_db(self, vuln_db_xml='scanners/data/nexpose-vulndb.xml'):
        # vd_elem_ref = ET.parse(vuln_db_xml).getroot()
        # vd_elem = self.elem.find('./VulnerabilityDefinitions')
        for h in self.hosts:
            for v in h:
                if v.elem.get('id') not in self.vuln_defs:
                    e = vd_elem_ref.find('./vulnerability[@id="{}"]'.format(v.elem.get('id')))
                    #vd_elem.append(e)
                    self.vuln_defs[e.get('id')] = e
    def get_xml(self, pretty=False):
        self.rebuild_vuln_db()
        return Scan.get_xml(self, pretty)
    def remove_false(self):
        return

def _build_vulndb(files):
    ''' build vuln database for nexpose xml files '''
    import re
    vuln_defs = ET.fromstring('<VulnerabilityDefinitions/>')
    vuln_ids = set()
    for f in files:
        s = NexposeScan(f)
        for e in s.elem.find('./VulnerabilityDefinitions'):
            if e.get('id') not in vuln_ids:
                vuln_defs.append(e)
                vuln_ids.add(e.get('id'))
    xml_str = re.sub(b'>\s+<', b'><', ET.tostring(vuln_defs, encoding='utf-8', method='xml'))
    xml_str = xml.dom.minidom.parseString(xml_str).toprettyxml()
    return xml_str