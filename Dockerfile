FROM kalilinux/kali-rolling

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    wireshark \
    tshark \
    metasploit-framework \
    hydra \
    john \
    wordlists \
    && rm -rf /var/lib/apt/lists/*

# Set up Python environment
WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p /app/data /app/uploads

# Expose port
EXPOSE 5000

# Run the application
CMD ["python3", "app.py"]