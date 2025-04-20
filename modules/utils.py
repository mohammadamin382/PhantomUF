
"""
Utility Module for PhantomUF
Provides common utility functions
"""

import os
import re
import platform
import logging
import subprocess
import socket

logger = logging.getLogger("PhantomUF.Utils")

def banner():
    """Display PhantomUF banner"""
    banner_text = """
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██╗   ██╗███████╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██║   ██║██╔════╝
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██║   ██║█████╗  
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██║   ██║██╔══╝  
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║╚██████╔╝██║     
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝     
                                                                                     
    Advanced Real-time Linux Network Security System
    Version 1.0.0
    """
    print(banner_text)
    
def is_root():
    """Check if the script is running with root privileges"""
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
def setup_environment():
    """Setup and verify the environment for PhantomUF"""
    logger.info("Setting up PhantomUF environment...")
    
    # Check Linux distribution and version
    distro = platform.linux_distribution() if hasattr(platform, 'linux_distribution') else ['Unknown', 'Unknown', 'Unknown']
    logger.info(f"Running on {distro[0]} {distro[1]}")
    
    # Check kernel version
    kernel = platform.uname().release
    logger.info(f"Kernel version: {kernel}")
    
    # Check for required tools
    required_tools = ['iptables', 'netstat', 'iftop', 'lsof']
    missing_tools = []
    
    for tool in required_tools:
        if not command_exists(tool):
            missing_tools.append(tool)
            
    if missing_tools:
        logger.warning(f"Missing required tools: {', '.join(missing_tools)}")
        
    # Check outbound connectivity
    if check_outbound_connectivity():
        logger.info("Outbound connectivity: OK")
    else:
        logger.warning("Outbound connectivity: FAILED")
        
    # Create required directories
    os.makedirs("logs", exist_ok=True)
    
    return True
    
def command_exists(command):
    """Check if a command exists on the system"""
    try:
        subprocess.run(["which", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.SubprocessError:
        return False
        
def check_outbound_connectivity():
    """Check if the system has outbound connectivity"""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except (socket.timeout, socket.error):
        return False
        
def get_public_ip():
    """Get the public IP address of the system"""
    try:
        # Try multiple services in case one is down
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com"
        ]
        
        for service in services:
            try:
                response = subprocess.check_output(["curl", "-s", service], universal_newlines=True)
                ip = response.strip()
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    return ip
            except subprocess.SubprocessError:
                continue
                
        return None
    except Exception as e:
        logger.error(f"Failed to get public IP: {e}")
        return None
        
def get_interfaces():
    """Get a list of network interfaces"""
    interfaces = []
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
            
        for line in lines[2:]:  # Skip header lines
            interface = line.split(':')[0].strip()
            if interface != 'lo':  # Skip loopback
                interfaces.append(interface)
                
        return interfaces
    except Exception as e:
        logger.error(f"Failed to get network interfaces: {e}")
        return []
        
def get_open_ports():
    """Get a list of open ports on the system"""
    open_ports = []
    try:
        output = subprocess.check_output(["netstat", "-tuln"], universal_newlines=True)
        
        for line in output.split('\n'):
            if 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    addr = parts[3]
                    if ':' in addr:
                        port = addr.split(':')[-1]
                        open_ports.append(port)
                        
        return sorted(list(set(open_ports)))
    except Exception as e:
        logger.error(f"Failed to get open ports: {e}")
        return []
        
def parse_cidr(ip_cidr):
    """Parse CIDR notation into IP and subnet mask"""
    if '/' in ip_cidr:
        ip, prefix = ip_cidr.split('/')
        prefix = int(prefix)
        if prefix <= 32:
            # IPv4
            subnet_mask = prefix_to_subnet_mask(prefix)
            return ip, subnet_mask
    return ip_cidr, "255.255.255.255"  # Default to single IP
    
def prefix_to_subnet_mask(prefix):
    """Convert a prefix length to a subnet mask"""
    mask = ((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1)
    return '.'.join([str((mask >> i) & 0xff) for i in [24, 16, 8, 0]])
