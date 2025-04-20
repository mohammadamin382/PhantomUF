
FROM python:3.9-slim

WORKDIR /app

# Install required system packages
RUN apt-get update && apt-get install -y \
    iptables \
    net-tools \
    lsof \
    iftop \
    htop \
    tcpdump \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy PhantomUF files
COPY . /app/

# Install Python dependencies
RUN pip install --no-cache-dir numpy cryptography psutil

# Create logs directory
RUN mkdir -p /app/logs

# Set executable permissions
RUN chmod +x /app/phantomuf.py /app/install.sh

# Make this run as a daemon process
ENTRYPOINT ["python", "phantomuf.py", "start"]
