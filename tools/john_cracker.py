import subprocess
import tempfile
import os
import re

class JohnCracker:
    def crack(self, hash_value, hash_type, wordlist):
        """Crack password hash using John the Ripper"""
        if not os.path.exists(wordlist):
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

            # Build John command
            cmd = [
                'john',
                f'--format={john_format}',
                f'--wordlist={wordlist}',
                '--pot=john.pot',
                '--stdout'
            ]

            # First, run John to crack
            process = subprocess.Popen(
                ['john', f'--format={john_format}', f'--wordlist={wordlist}', hash_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0 and 'No password hashes loaded' in stderr:
                return {'error': 'Invalid hash format or unsupported type'}

            # Now get the cracked password
            show_process = subprocess.run(
                ['john', '--show', hash_file],
                capture_output=True,
                text=True,
                timeout=30
            )

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

        except subprocess.TimeoutExpired:
            process.kill()
            return {'error': 'Cracking timeout exceeded (5 minutes)'}
        except Exception as e:
            return {'error': str(e)}
        finally:
            # Cleanup
            if os.path.exists(hash_file):
                os.remove(hash_file)