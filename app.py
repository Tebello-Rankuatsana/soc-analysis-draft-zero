from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit
import subprocess
import json
import os
import logging
from datetime import datetime
from tools.nmap_scanner import NmapScanner
from tools.wireshark_analyzer import WiresharkAnalyzer
from tools.metasploit_wrapper import MetasploitWrapper
from tools.hydra_bruteforce import HydraBruteforce
from tools.john_cracker import JohnCracker
import threading

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
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

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """SOC Analysis Dashboard"""
    return render_template('dashboard.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Run network scan using Nmap"""
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    
    try:
        result = nmap.scan(target, scan_type)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/packet-analyze', methods=['POST'])
def analyze_packets():
    """Analyze packet capture files"""
    data = request.json
    pcap_file = data.get('file_path')
    filters = data.get('filters', {})
    
    try:
        result = wireshark.analyze(pcap_file, filters)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Packet analysis failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/exploit', methods=['POST'])
def run_exploit():
    """Execute Metasploit exploit"""
    data = request.json
    exploit_name = data.get('exploit')
    options = data.get('options', {})
    
    try:
        result = metasploit.execute(exploit_name, options)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Exploit failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/bruteforce', methods=['POST'])
def run_bruteforce():
    """Run password brute force attack"""
    data = request.json
    service = data.get('service')
    target = data.get('target')
    wordlist = data.get('wordlist', '/usr/share/wordlists/rockyou.txt')
    
    try:
        result = hydra.bruteforce(service, target, wordlist)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Bruteforce failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/crack-hash', methods=['POST'])
def crack_hash():
    """Crack password hashes using John the Ripper"""
    data = request.json
    hash_value = data.get('hash')
    hash_type = data.get('hash_type', 'md5')
    wordlist = data.get('wordlist', '/usr/share/wordlists/rockyou.txt')
    
    try:
        result = john.crack(hash_value, hash_type, wordlist)
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Hash cracking failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/tools')
def get_tools():
    """Get list of available tools"""
    tools = [
        {
            'name': 'Nmap Scanner',
            'description': 'Network discovery and security scanning',
            'endpoint': '/api/scan',
            'inputs': ['target', 'scan_type']
        },
        {
            'name': 'Wireshark Analyzer',
            'description': 'Network protocol analyzer',
            'endpoint': '/api/packet-analyze',
            'inputs': ['file_path', 'filters']
        },
        {
            'name': 'Metasploit Exploit',
            'description': 'Penetration testing framework',
            'endpoint': '/api/exploit',
            'inputs': ['exploit', 'options']
        },
        {
            'name': 'Hydra Brute Force',
            'description': 'Password cracker for network services',
            'endpoint': '/api/bruteforce',
            'inputs': ['service', 'target', 'wordlist']
        },
        {
            'name': 'John the Ripper',
            'description': 'Password hash cracker',
            'endpoint': '/api/crack-hash',
            'inputs': ['hash', 'hash_type', 'wordlist']
        }
    ]
    return jsonify(tools)

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'message': 'Connected to SOC Analysis Dashboard'})

@socketio.on('realtime_scan')
def handle_realtime_scan(data):
    """Handle real-time scanning updates"""
    target = data.get('target')
    
    def scan_updates():
        for update in nmap.scan_realtime(target):
            emit('scan_update', update)
    
    thread = threading.Thread(target=scan_updates)
    thread.start()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)