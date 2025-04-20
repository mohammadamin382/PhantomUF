#!/bin/bash

# PhantomUF Installation Script
# This script installs PhantomUF to /opt/phantomuf, sets up a global command,
# and optionally sets up a Docker container

echo "PhantomUF Installation Script"
echo "============================"
echo

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./install.sh)"
  exit 1
fi

# Parse command line options
DOCKER_MODE=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --docker)
      DOCKER_MODE=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done

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

# Create completion script
cat > /etc/bash_completion.d/phantomuf <<EOF
_phantomuf() {
    local cur prev opts
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"

    # Main commands
    opts="start stop status log rule scan recommend"

    # Complete based on the current word
    if [[ \${prev} == "phantomuf" ]]; then
        COMPREPLY=( \$(compgen -W "\${opts}" -- \${cur}) )
        return 0
    fi

    # Subcommands
    if [[ \${prev} == "rule" ]]; then
        local subopts="add del list"
        COMPREPLY=( \$(compgen -W "\${subopts}" -- \${cur}) )
        return 0
    fi

    if [[ \${prev} == "scan" ]]; then
        local subopts="--type --report"
        COMPREPLY=( \$(compgen -W "\${subopts}" -- \${cur}) )
        return 0
    fi
}
complete -F _phantomuf phantomuf
EOF

if [ "$DOCKER_MODE" -eq 1 ]; then
    echo "Setting up Docker for PhantomUF..."

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        echo "Docker is not installed. Would you like to install it? (y/n)"
        read -r install_docker
        if [[ "$install_docker" =~ ^[Yy]$ ]]; then
            # Install Docker
            curl -fsSL https://get.docker.com -o get-docker.sh
            sh get-docker.sh

            # Start and enable Docker
            systemctl start docker
            systemctl enable docker
        else
            echo "Please install Docker and run this script again with --docker"
            exit 1
        fi
    fi

    # Build the Docker image
    echo "Building PhantomUF Docker image..."
    docker build -t phantomuf:latest .

    # Create Docker container run script
    cat > /usr/local/bin/phantomuf-docker <<EOF
#!/bin/bash

case "\$1" in
  start)
    # Check if container is already running
    if docker ps | grep -q phantomuf; then
      echo "PhantomUF is already running."
      exit 0
    fi

    # Start the container in detached mode
    docker run -d --name phantomuf --restart unless-stopped --network host --cap-add=NET_ADMIN --privileged phantomuf:latest
    echo "PhantomUF has been started in Docker container."
    ;;

  stop)
    # Stop and remove the container
    docker stop phantomuf
    docker rm phantomuf
    echo "PhantomUF Docker container has been stopped and removed."
    ;;

  status)
    # Check container status
    if docker ps | grep -q phantomuf; then
      echo "PhantomUF is running in Docker container."
      docker exec phantomuf python phantomuf.py status
    else
      echo "PhantomUF Docker container is not running."
    fi
    ;;

  logs)
    # Show container logs
    docker logs phantomuf
    ;;

  *)
    echo "Usage: phantomuf-docker {start|stop|status|logs}"
    exit 1
    ;;
esac
EOF

    chmod +x /usr/local/bin/phantomuf-docker

    echo "Creating wrapper script for phantomuf command..."
    cat > /usr/local/bin/phantomuf <<EOF
#!/bin/bash

if [ "\$1" = "start" ] || [ "\$1" = "stop" ] || [ "\$1" = "status" ] || [ "\$1" = "log" ]; then
    # Use docker for basic commands
    case "\$1" in
      start)
        phantomuf-docker start
        ;;
      stop)
        phantomuf-docker stop
        ;;
      status)
        phantomuf-docker status
        ;;
      log)
        phantomuf-docker logs
        ;;
    esac
else
    # For other commands, execute inside running container
    if docker ps | grep -q phantomuf; then
        docker exec -it phantomuf python phantomuf.py "\$@"
    else
        echo "PhantomUF container is not running. Start it with 'phantomuf start' first."
        exit 1
    fi
fi
EOF

    chmod +x /usr/local/bin/phantomuf

    echo "Docker setup complete!"
    echo
    echo "To start PhantomUF now, run:"
    echo "  phantomuf start"
    echo
    echo "This will run PhantomUF in a Docker container as a background service."

else
    # Standard installation (systemd service)
    echo "Creating systemd service..."
    # Create systemd service file
    cat > /etc/systemd/system/phantomuf.service <<EOF
[Unit]
Description=PhantomUF Network Security System
After=network.target

[Service]
ExecStart=/opt/phantomuf/phantomuf.py start
ExecStop=/opt/phantomuf/phantomuf.py stop
Type=simple
Restart=on-failure
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    echo "Installation complete!"
    echo
    echo "To start PhantomUF now, run:"
    echo "  systemctl start phantomuf"
    echo
    echo "To enable autostart on boot:"
    echo "  systemctl enable phantomuf"
    echo
    echo "Usage:"
    echo "  phantomuf start - Start PhantomUF security system"
    echo "  phantomuf stop - Stop PhantomUF security system"
    echo "  phantomuf status - Check status of PhantomUF"
    echo "  phantomuf log - View security logs"
    echo "  phantomuf scan - Run vulnerability scan"
    echo
    echo "To install with Docker support instead, run:"
    echo "  sudo ./install.sh --docker"
fi

# Set correct permissions
echo "Setting permissions..."
chmod -R 750 "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/keys"
chmod 700 "$INSTALL_DIR/keys/quantum"

# Create PhantomUF command symlink (This section is largely redundant with the Docker approach)
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