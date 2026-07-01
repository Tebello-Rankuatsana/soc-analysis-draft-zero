// Socket.IO connection
const socket = io();

// Status tracking
let toolsReady = 0;
let activeScans = 0;

// Initialize connection
socket.on('connect', function() {
    updateStatus(true);
    loadTools();
});

socket.on('connect_error', function() {
    updateStatus(false);
});

socket.on('connected', function(data) {
    console.log(data.message);
    addAlert('success', 'Connected to SOC Analysis Platform');
});

socket.on('scan_update', function(data) {
    if (data.line) {
        appendResult('scanResults', data.line);
    }
    if (data.error) {
        appendResult('scanResults', 'Error: ' + data.error);
    }
});

// Navigation
document.querySelectorAll('.sidebar li').forEach(item => {
    item.addEventListener('click', function() {
        document.querySelectorAll('.sidebar li').forEach(li => li.classList.remove('active'));
        this.classList.add('active');
        
        const tab = this.dataset.tab;
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tab).classList.add('active');
    });
});

// Tool functions
async function loadTools() {
    try {
        const response = await fetch('/api/tools');
        const tools = await response.json();
        toolsReady = tools.length;
        document.getElementById('toolsReady').textContent = toolsReady;
        
        const toolsList = document.getElementById('toolsList');
        toolsList.innerHTML = '';
        tools.forEach(tool => {
            const div = document.createElement('div');
            div.className = 'tool-item';
            div.innerHTML = `
                <h4>${tool.name}</h4>
                <p>${tool.description}</p>
                <small style="color: #666;">Endpoint: ${tool.endpoint}</small>
            `;
            toolsList.appendChild(div);
        });
    } catch (error) {
        console.error('Error loading tools:', error);
    }
}

async function runScan() {
    const target = document.getElementById('scanTarget').value;
    const scanType = document.getElementById('scanType').value;
    
    if (!target) {
        alert('Please enter a target IP or hostname');
        return;
    }
    
    const resultsDiv = document.getElementById('scanResults');
    resultsDiv.innerHTML = '<div class="loading"></div> Starting scan...';
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target, scan_type: scanType})
        });
        
        const data = await response.json();
        resultsDiv.innerHTML = JSON.stringify(data, null, 2);
    } catch (error) {
        resultsDiv.textContent = 'Error: ' + error.message;
    }
}

async function analyzePackets() {
    const fileInput = document.getElementById('pcapFile');
    const filters = Array.from(document.getElementById('packetFilters').selectedOptions).map(opt => opt.value);
    
    if (!fileInput.files[0]) {
        alert('Please select a PCAP file');
        return;
    }
    
    const resultsDiv = document.getElementById('packetResults');
    resultsDiv.innerHTML = '<div class="loading"></div> Analyzing packets...';
    
    // For file upload, we need FormData
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('filters', JSON.stringify(filters));
    
    try {
        const response = await fetch('/api/packet-analyze', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        resultsDiv.innerHTML = JSON.stringify(data, null, 2);
    } catch (error) {
        resultsDiv.textContent = 'Error: ' + error.message;
    }
}

async function runExploit() {
    const exploit = document.getElementById('exploitSelect').value;
    const optionsText = document.getElementById('exploitOptions').value;
    
    let options = {};
    try {
        options = JSON.parse(optionsText);
    } catch (e) {
        alert('Invalid JSON in options');
        return;
    }
    
    const resultsDiv = document.getElementById('exploitResults');
    resultsDiv.innerHTML = '<div class="loading"></div> Executing exploit...';
    
    try {
        const response = await fetch('/api/exploit', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({exploit, options})
        });
        
        const data = await response.json();
        resultsDiv.innerHTML = JSON.stringify(data, null, 2);
    } catch (error) {
        resultsDiv.textContent = 'Error: ' + error.message;
    }
}

async function runBruteforce() {
    const service = document.getElementById('bfService').value;
    const target = document.getElementById('bfTarget').value;
    const wordlist = document.getElementById('bfWordlist').value;
    
    if (!target) {
        alert('Please enter a target');
        return;
    }
    
    const resultsDiv = document.getElementById('bruteforceResults');
    resultsDiv.innerHTML = '<div class="loading"></div> Starting brute force attack...';
    
    try {
        const response = await fetch('/api/bruteforce', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({service, target, wordlist})
        });
        
        const data = await response.json();
        resultsDiv.innerHTML = JSON.stringify(data, null, 2);
    } catch (error) {
        resultsDiv.textContent = 'Error: ' + error.message;
    }
}

async function crackHash() {
    const hash = document.getElementById('hashInput').value;
    const hashType = document.getElementById('hashType').value;
    const wordlist = document.getElementById('crackWordlist').value;
    
    if (!hash) {
        alert('Please enter a hash value');
        return;
    }
    
    const resultsDiv = document.getElementById('crackResults');
    resultsDiv.innerHTML = '<div class="loading"></div> Cracking hash...';
    
    try {
        const response = await fetch('/api/crack-hash', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({hash, hash_type: hashType, wordlist})
        });
        
        const data = await response.json();
        resultsDiv.innerHTML = JSON.stringify(data, null, 2);
    } catch (error) {
        resultsDiv.textContent = 'Error: ' + error.message;
    }
}

function generateReport() {
    const resultsDiv = document.getElementById('reportResults');
    resultsDiv.innerHTML = '<div class="loading"></div> Generating report...';
    
    // Collect all results
    const report = {
        timestamp: new Date().toISOString(),
        scans: document.getElementById('scanResults').textContent,
        packet_analysis: document.getElementById('packetResults').textContent,
        exploits: document.getElementById('exploitResults').textContent,
        bruteforce: document.getElementById('bruteforceResults').textContent,
        hash_cracking: document.getElementById('crackResults').textContent
    };
    
    setTimeout(() => {
        resultsDiv.innerHTML = JSON.stringify(report, null, 2);
    }, 1000);
}

// Helper functions
function updateStatus(connected) {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    
    if (connected) {
        dot.className = 'status-dot online';
        text.textContent = 'Connected';
    } else {
        dot.className = 'status-dot offline';
        text.textContent = 'Disconnected';
    }
}

function appendResult(elementId, text) {
    const div = document.getElementById(elementId);
    if (div) {
        div.innerHTML += text + '\n';
        div.scrollTop = div.scrollHeight;
    }
}

function addAlert(type, message) {
    // Simple alert for now
    console.log(`[${type}] ${message}`);
}