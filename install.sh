
#!/bin/bash

# PhantomUF - Advanced Real-time Linux Network Security System
# Installation Script

echo "====================================================================="
echo "          PhantomUF Security System Installation Script              "
echo "====================================================================="
echo "This script will install and configure PhantomUF on your system."
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)."
    exit 1
fi

# Detect system type
DISTRO=""
if [ -f /etc/lsb-release ]; then
    DISTRO=$(grep -oP '(?<=DISTRIB_ID=).+' /etc/lsb-release | tr -d '"')
elif [ -f /etc/redhat-release ]; then
    DISTRO="RHEL"
elif [ -f /etc/debian_version ]; then
    DISTRO="Debian"
else
    echo "Warning: Could not determine Linux distribution. Installation may fail."
    DISTRO="Unknown"
fi

echo "Detected distribution: $DISTRO"
echo

# Create installation directory
INSTALL_DIR="/opt/phantomuf"
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/keys"
mkdir -p "$INSTALL_DIR/keys/quantum"
mkdir -p "$INSTALL_DIR/reports"
mkdir -p "$INSTALL_DIR/modules"

# Install dependencies
echo "Installing dependencies..."
if [ "$DISTRO" == "Ubuntu" ] || [ "$DISTRO" == "Debian" ]; then
    apt update
    apt install -y python3 python3-pip iptables netstat-nat iftop lsof dnsutils net-tools
    python3 -m pip install cryptography numpy psutil
elif [ "$DISTRO" == "RHEL" ] || [ "$DISTRO" == "Fedora" ] || [ "$DISTRO" == "CentOS" ]; then
    yum install -y python3 python3-pip iptables net-tools lsof iftop bind-utils
    python3 -m pip install cryptography numpy psutil
else
    echo "Installing Python dependencies..."
    python3 -m pip install cryptography numpy psutil
fi

echo "Copying PhantomUF files..."
# Copy current directory contents to installation directory
cp -r ./* "$INSTALL_DIR/"

# Create PhantomUF command symlink
echo "Creating command-line utility..."
cat > "/usr/local/bin/phantomuf" << 'EOL'
#!/bin/bash
if [ "$EUID" -ne 0 ] && [ "$1" != "status" ] && [ "$1" != "help" ]; then
    echo "Error: PhantomUF requires root privileges to function properly."
    echo "Please run with sudo: sudo phantomuf $*"
    exit 1
fi

python3 /opt/phantomuf/phantomuf.py "$@"
EOL

# Make it executable
chmod +x "/usr/local/bin/phantomuf"

# Set correct permissions
echo "Setting permissions..."
chmod -R 750 "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/keys"
chmod 700 "$INSTALL_DIR/keys/quantum"

# Create systemd service
echo "Creating systemd service..."
cat > "/etc/systemd/system/phantomuf.service" << EOL
[Unit]
Description=PhantomUF Security System
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/phantomuf.py start
ExecStop=/usr/bin/python3 $INSTALL_DIR/phantomuf.py stop
Restart=on-failure
User=root
Group=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable and start the service
systemctl daemon-reload
systemctl enable phantomuf.service

echo "====================================================================="
echo "Installation complete!"
echo "====================================================================="
echo "PhantomUF has been installed to: $INSTALL_DIR"
echo
echo "Available commands:"
echo "  phantomuf start        - Start the security system"
echo "  phantomuf stop         - Stop the security system"
echo "  phantomuf status       - Check system status"
echo "  phantomuf log          - View security logs"
echo "  phantomuf scan         - Run vulnerability scan"
echo "  phantomuf recommend    - Get security recommendations"
echo
echo "You can also use systemd to manage the service:"
echo "  systemctl start phantomuf    - Start the service"
echo "  systemctl stop phantomuf     - Stop the service"
echo "  systemctl status phantomuf   - Check service status"
echo
echo "Starting PhantomUF service..."
systemctl start phantomuf

echo "PhantomUF is now actively protecting your system!"
echo "====================================================================="
