import subprocess
import tempfile
import os
import re

class JohnCracker:
    def crack(self, hash_value, hash_type, wordlist):
        """Crack password hash using John the Ripper"""
        # Check if wordlist exists
        check_cmd = f"test -f {wordlist}"
        check = subprocess.run(check_cmd, shell=True, capture_output=True)
        if check.returncode != 0:
            return {'error': f'Wordlist not found: {wordlist}'}

        # Map common hash types to John's format
        format_map = {
            'md5': 'raw-md5',
            'sha1': 'raw-sha1',
            'sha256': 'raw-sha256',
            'nt': 'nt',
            'md5crypt': 'md5crypt',
            'sha512crypt': 'sha512crypt'
        }
        
        john_format = format_map.get(hash_type, hash_type)

        # Create temporary file for the hash
        fd, hash_file = tempfile.mkstemp(suffix='.hash')
        os.close(fd)
        
        try:
            # Write hash to file
            with open(hash_file, 'w') as f:
                f.write(hash_value + '\n')

            # Run John to crack (using run() which supports timeout)
            try:
                process = subprocess.run(
                    ['john', f'--format={john_format}', f'--wordlist={wordlist}', hash_file],
                    capture_output=True,
                    text=True,
                    timeout=60  # 60 second timeout
                )
                stdout = process.stdout
                stderr = process.stderr
            except subprocess.TimeoutExpired:
                return {'error': 'Cracking timeout exceeded (60 seconds)'}

            if process.returncode != 0 and 'No password hashes loaded' in stderr:
                return {'error': 'Invalid hash format or unsupported type'}

            # Now get the cracked password
            try:
                show_process = subprocess.run(
                    ['john', '--show', hash_file],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            except subprocess.TimeoutExpired:
                return {'error': 'Timeout reading results'}

            cracked_password = None
            if show_process.returncode == 0:
                # Parse output like "hash:password"
                match = re.search(r':([^\n]+)', show_process.stdout)
                if match:
                    cracked_password = match.group(1).strip()

            return {
                'success': True,
                'cracked': cracked_password is not None,
                'password': cracked_password,
                'hash_type': hash_type,
                'wordlist_used': wordlist,
                'john_output': stdout,
                'john_error': stderr if stderr else None
            }

        except Exception as e:
            return {'error': str(e)}
        finally:
            # Cleanup
            if os.path.exists(hash_file):
                os.remove(hash_file)