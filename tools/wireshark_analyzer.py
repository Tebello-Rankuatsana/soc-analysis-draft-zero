import subprocess
import json
import os
import tempfile

class WiresharkAnalyzer:
    def __init__(self):
        self.filters = {
            'http': 'http',
            'dns': 'dns',
            'ftp': 'ftp',
            'ssh': 'ssh',
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'malicious': 'http.request.method == "POST" || dns.qry.name contains "malware"'
        }
    
    def analyze(self, pcap_file, filters=None):
        """Analyze packet capture file"""
        if not os.path.exists(pcap_file):
            return {'error': 'PCAP file not found'}
        
        # Use tshark for analysis (headless Wireshark)
        commands = []
        
        # Get file info
        commands.append(f"tshark -r {pcap_file} -q -z io,stat,0")
        
        # Get protocol hierarchy
        commands.append(f"tshark -r {pcap_file} -q -z proto,colinfo")
        
        # Apply filters if provided
        filter_str = ''
        if filters:
            filter_str = ' '.join([f for f in filters if f in self.filters])
            if filter_str:
                filter_str = f'-Y "{self.filters[filter_str]}"'
        
        # Get packet details
        commands.append(f"tshark -r {pcap_file} {filter_str} -T json -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e http.host -e http.request.uri")
        
        result = {}
        for i, cmd in enumerate(commands):
            try:
                output = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if output.returncode == 0:
                    if i == 2:  # JSON output for packets
                        try:
                            result['packets'] = json.loads(output.stdout)
                        except:
                            result['packets'] = output.stdout
                    else:
                        result[f'analysis_{i}'] = output.stdout
                else:
                    result[f'error_{i}'] = output.stderr
                    
            except subprocess.TimeoutExpired:
                result[f'error_{i}'] = 'Timeout exceeded'
            except Exception as e:
                result[f'error_{i}'] = str(e)
        
        return result
    
    def detect_suspicious(self, pcap_file):
        """Detect suspicious network activity"""
        patterns = [
            ('port_scan', 'tcp.flags.syn == 1 and tcp.flags.ack == 0'),
            ('dns_tunnel', 'dns.qry.type == 1 and dns.qry.name contains "base64"'),
            ('http_exfil', 'http.request.method == "GET" and http.content_length > 1000'),
            ('ssh_bruteforce', 'ssh.message_code == 51')
        ]
        
        results = {}
        for name, pattern in patterns:
            cmd = f"tshark -r {pcap_file} -Y '{pattern}' -T fields -e ip.src -e ip.dst | sort | uniq -c"
            
            try:
                output = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                results[name] = output.stdout if output.returncode == 0 else output.stderr
            except Exception as e:
                results[name] = str(e)
        
        return results