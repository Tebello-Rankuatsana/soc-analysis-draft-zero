import subprocess
import xml.etree.ElementTree as ET
import json
import re

class NmapScanner:
    def __init__(self):
        self.scan_types = {
            'quick': '-T4 -F',
            'comprehensive': '-sS -sV -sC -A -O -p-',
            'udp': '-sU -sV -p 1-1024',
            'vulnerability': '--script vuln',
            'stealth': '-sS -Pn -T2'
        }
    
    def scan(self, target, scan_type='quick'):
        if scan_type not in self.scan_types:
            scan_type = 'quick'
        
        command = f"nmap {self.scan_types[scan_type]} -oX - {target}"
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                return {'error': result.stderr}
            
            xml_data = result.stdout
            root = ET.fromstring(xml_data)
            parsed_result = self._parse_nmap_output(root)
            return parsed_result
            
        except subprocess.TimeoutExpired:
            return {'error': 'Scan timeout exceeded'}
        except Exception as e:
            return {'error': str(e)}
    
    def scan_realtime(self, target):
        command = f"nmap -T4 -F --unprivileged {target}"
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in process.stdout:
            yield {'line': line.strip()}
        return_code = process.wait()
        if return_code != 0:
            yield {'error': process.stderr.read()}
    
    def _parse_nmap_output(self, root):
        result = {'hosts': [], 'summary': {}, 'raw_output': ET.tostring(root, encoding='unicode')}
        for host in root.findall('host'):
            host_data = {}
            address_elem = host.find('address')
            if address_elem is not None:
                host_data['ip'] = address_elem.get('addr')
            os_elem = host.find('os')
            if os_elem is not None:
                os_match = os_elem.find('osmatch')
                if os_match is not None:
                    host_data['os'] = os_match.get('name')
            ports = []
            for port in host.findall('.//port'):
                port_data = {
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'state': port.find('state').get('state') if port.find('state') is not None else 'unknown',
                    'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
                }
                ports.append(port_data)
            host_data['ports'] = ports
            result['hosts'].append(host_data)
        result['summary'] = {
            'total_hosts': len(result['hosts']),
            'total_ports': sum(len(h.get('ports', [])) for h in result['hosts'])
        }
        return result