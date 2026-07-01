from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit
import subprocess
import json
import os
import logging
import tempfile
from datetime import datetime
from tools.nmap_scanner import NmapScanner
from tools.wireshark_analyzer import WiresharkAnalyzer
from tools.metasploit_wrapper import MetasploitWrapper
from tools.hydra_bruteforce import HydraBruteforce
from tools.john_cracker import JohnCracker
import threading

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tool instances
nmap = NmapScanner()
wireshark = WiresharkAnalyzer()
metasploit = MetasploitWrapper()
hydra = HydraBruteforce()
john = JohnCracker()

# Ensure upload directory exists
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    
    if not target:
        return jsonify({'status': 'error', 'message': 'Target required'}), 400

    try:
        result = nmap.scan(target, scan_type)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/packet-analyze', methods=['POST'])
def analyze_packets():
    """Handle actual PCAP file upload and analysis"""
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'Empty filename'}), 400

    # Save uploaded file temporarily
    temp_path = None
    try:
        # Create temp file with .pcap extension
        fd, temp_path = tempfile.mkstemp(suffix='.pcap', dir=UPLOAD_DIR)
        os.close(fd)
        file.save(temp_path)

        # Get filters from form data
        filters_json = request.form.get('filters', '[]')
        try:
            filters = json.loads(filters_json)
        except:
            filters = []

        # Analyze
        result = wireshark.analyze(temp_path, filters)
        
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Packet analysis failed: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        # Clean up temp file
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

@app.route('/api/exploit', methods=['POST'])
def run_exploit():
    data = request.json
    exploit_name = data.get('exploit')
    options = data.get('options', {})
    
    if not exploit_name:
        return jsonify({'status': 'error', 'message': 'Exploit name required'}), 400

    try:
        result = metasploit.execute(exploit_name, options)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Exploit failed: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/bruteforce', methods=['POST'])
def run_bruteforce():
    data = request.json
    service = data.get('service')
    target = data.get('target')
    wordlist = data.get('wordlist', '/usr/share/wordlists/rockyou.txt')
    
    if not service or not target:
        return jsonify({'status': 'error', 'message': 'Service and target required'}), 400

    try:
        result = hydra.bruteforce(service, target, wordlist)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Bruteforce failed: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/crack-hash', methods=['POST'])
def crack_hash():
    data = request.json
    hash_value = data.get('hash')
    hash_type = data.get('hash_type', 'md5')
    wordlist = data.get('wordlist', '/usr/share/wordlists/rockyou.txt')
    
    if not hash_value:
        return jsonify({'status': 'error', 'message': 'Hash required'}), 400

    try:
        result = john.crack(hash_value, hash_type, wordlist)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Hash cracking failed: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/tools')
def get_tools():
    tools = [
        {'name': 'Nmap Scanner', 'description': 'Network discovery and security scanning', 'endpoint': '/api/scan', 'inputs': ['target', 'scan_type']},
        {'name': 'Wireshark Analyzer', 'description': 'Network protocol analyzer', 'endpoint': '/api/packet-analyze', 'inputs': ['file', 'filters']},
        {'name': 'Metasploit Exploit', 'description': 'Penetration testing framework', 'endpoint': '/api/exploit', 'inputs': ['exploit', 'options']},
        {'name': 'Hydra Brute Force', 'description': 'Password cracker for network services', 'endpoint': '/api/bruteforce', 'inputs': ['service', 'target', 'wordlist']},
        {'name': 'John the Ripper', 'description': 'Password hash cracker', 'endpoint': '/api/crack-hash', 'inputs': ['hash', 'hash_type', 'wordlist']}
    ]
    return jsonify(tools)

@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to SOC Analysis Dashboard'})

@socketio.on('realtime_scan')
def handle_realtime_scan(data):
    target = data.get('target')
    def scan_updates():
        for update in nmap.scan_realtime(target):
            emit('scan_update', update)
    thread = threading.Thread(target=scan_updates)
    thread.start()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)