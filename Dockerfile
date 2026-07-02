FROM kalilinux/kali-rolling

# Install system dependencies (includes all Kali tools)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    wireshark \
    tshark \
    metasploit-framework \
    hydra \
    john \
    wordlists \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Create virtual environment and install Python packages
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create directories
RUN mkdir -p /app/data /app/uploads

# Expose port
EXPOSE 5000

# Run using the virtual environment's Python
CMD ["/app/venv/bin/python", "app.py"]