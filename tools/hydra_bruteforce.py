import subprocess
import tempfile
import os
import json
import re

class HydraBruteforce:
    def bruteforce(self, service, target, wordlist):
        """Run Hydra brute force attack"""
        if not os.path.exists(wordlist):
            return {'error': f'Wordlist not found: {wordlist}'}

        # Parse target to extract host and port
        host = target
        port = None
        if ':' in target:
            parts = target.split(':')
            host = parts[0]
            port = parts[1]

        # Build command
        cmd = [
            'hydra',
            '-V',  # Verbose
            '-f',  # Exit on first found
            '-t', '4',  # Tasks
            '-w', '30',  # Wait time
            '-l', 'admin',  # Default username (can be extended)
            '-P', wordlist,
            '-o', '-',  # Output to stdout
            '-J',  # JSON output
            host
        ]

        # Add service and port
        if service == 'ssh':
            cmd.insert(-1, 'ssh')
        elif service == 'ftp':
            cmd.insert(-1, 'ftp')
        elif service == 'http-post-form':
            cmd.insert(-1, 'http-post-form')
            # Default form path, can be customized
            cmd.append('"/login.php:user=^USER^&pass=^PASS^:F=incorrect"')
        elif service == 'mysql':
            cmd.insert(-1, 'mysql')
        elif service == 'rdp':
            cmd.insert(-1, 'rdp')
        else:
            cmd.insert(-1, service)

        if port:
            cmd.extend(['-s', port])

        try:
            # Run hydra
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600  # 10 min timeout
            )

            stdout, stderr = process.communicate()

            # Try to parse JSON output from hydra
            result_data = {
                'success': process.returncode == 0,
                'output': stdout,
                'error': stderr if stderr else None,
                'cracked': []
            }

            # Extract JSON from stdout (hydra wraps JSON in text)
            json_match = re.search(r'\{.*\}', stdout, re.DOTALL)
            if json_match:
                try:
                    json_data = json.loads(json_match.group())
                    if 'results' in json_data:
                        for res in json_data['results']:
                            result_data['cracked'].append({
                                'host': res.get('host'),
                                'login': res.get('login'),
                                'password': res.get('password'),
                                'port': res.get('port')
                            })
                except:
                    pass

            return result_data

        except subprocess.TimeoutExpired:
            process.kill()
            return {'error': 'Bruteforce timeout exceeded (10 minutes)'}
        except Exception as e:
            return {'error': str(e)}