import subprocess
import tempfile
import os
import re

class JohnCracker:
    def crack(self, hash_value, hash_type, wordlist):
        """Crack password hash using John the Ripper"""
        # Check if wordlist exists using Python's os.path
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

            # Build the command as a list (prevents path issues)
            cmd = [
                'john',
                f'--format={john_format}',
                f'--wordlist={wordlist}',
                hash_file
            ]
            
            # Run John with timeout using Popen (for Python 3.6 compatibility)
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Manual timeout (compatible with older Python)
                import time
                start_time = time.time()
                timeout = 60
                
                while process.poll() is None:
                    if time.time() - start_time > timeout:
                        process.kill()
                        return {'error': f'Cracking timeout exceeded ({timeout} seconds)'}
                    time.sleep(0.1)
                
                stdout, stderr = process.communicate()
                
            except Exception as e:
                return {'error': f'Process error: {str(e)}'}

            if process.returncode != 0 and 'No password hashes loaded' in stderr:
                return {'error': 'Invalid hash format or unsupported type'}

            # Get the cracked password
            try:
                show_process = subprocess.Popen(
                    ['john', '--show', hash_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Manual timeout for show command
                start_time = time.time()
                while show_process.poll() is None:
                    if time.time() - start_time > 10:
                        show_process.kill()
                        return {'error': 'Timeout reading results'}
                    time.sleep(0.1)
                
                show_stdout, show_stderr = show_process.communicate()
                
            except Exception as e:
                return {'error': f'Error reading results: {str(e)}'}

            cracked_password = None
            if show_process.returncode == 0:
                # Parse output like "hash:password"
                match = re.search(r':([^\n]+)', show_stdout)
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