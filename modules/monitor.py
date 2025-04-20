
"""
Network Monitor Module for PhantomUF
Monitors network traffic and connections for suspicious activity
"""

import os
import re
import time
import socket
import logging
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, Counter

logger = logging.getLogger("PhantomUF.Monitor")

class NetworkMonitor:
    """Monitors network traffic and connections"""
    
    def __init__(self, config, log_manager):
        self.config = config
        self.log_manager = log_manager
        self.analyzer = None
        self.running = False
        self.connection_count = 0
        self.start_time = None
        self.active_connections = defaultdict(list)
        self.connection_history = defaultdict(Counter)
        self.port_scan_threshold = self.config.get("port_scan_threshold", 15)
        self.suspicious_ports = set([21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5900])
        
    def initialize(self):
        """Initialize the network monitoring component"""
        logger.info("Initializing Network Monitor...")
        
    def set_analyzer(self, analyzer):
        """Set the threat analyzer reference"""
        self.analyzer = analyzer
        
    def start(self):
        """Start the network monitoring service"""
        if self.running:
            logger.warning("Network Monitor is already running")
            return
            
        logger.info("Starting Network Monitor...")
        self.start_time = time.time()
        self.running = True
        
        # Start monitoring threads
        threading.Thread(target=self._monitor_connections, daemon=True).start()
        threading.Thread(target=self._monitor_network_traffic, daemon=True).start()
        threading.Thread(target=self._check_suspicious_activity, daemon=True).start()
        
        logger.info("Network Monitor started successfully")
        
    def stop(self):
        """Stop the network monitoring service"""
        if not self.running:
            logger.warning("Network Monitor is not running")
            return
            
        logger.info("Stopping Network Monitor...")
        self.running = False
        logger.info("Network Monitor stopped successfully")
        
    def get_uptime(self):
        """Get the uptime of the monitoring service in seconds"""
        if not self.start_time:
            return 0
        return int(time.time() - self.start_time)
        
    def get_connection_count(self):
        """Get the total number of connections monitored"""
        return self.connection_count
        
    def _monitor_connections(self):
        """Monitor active network connections"""
        logger.info("Connection monitoring thread started")
        
        while self.running:
            try:
                # Get current connections using netstat
                output = subprocess.check_output(
                    ["netstat", "-tunapl"], 
                    stderr=subprocess.STDOUT, 
                    universal_newlines=True
                )
                
                current_connections = set()
                
                for line in output.split('\n'):
                    if 'ESTABLISHED' in line or 'SYN_SENT' in line or 'SYN_RECV' in line:
                        parts = line.split()
                        if len(parts) >= 7:
                            # Extract source and destination
                            local_addr = parts[3]
                            remote_addr = parts[4]
                            state = parts[5]
                            pid_program = ' '.join(parts[6:])
                            
                            # Parse addresses
                            if ':' in local_addr:
                                local_ip, local_port = local_addr.rsplit(':', 1)
                            else:
                                local_ip, local_port = local_addr, ""
                                
                            if ':' in remote_addr:
                                remote_ip, remote_port = remote_addr.rsplit(':', 1)
                            else:
                                remote_ip, remote_port = remote_addr, ""
                                
                            # Skip local connections
                            if remote_ip in ('127.0.0.1', '0.0.0.0', '::1', ''):
                                continue
                                
                            connection_key = f"{remote_ip}:{remote_port}-{local_ip}:{local_port}"
                            current_connections.add(connection_key)
                            
                            # If this is a new connection
                            if connection_key not in self.active_connections:
                                connection_info = {
                                    'remote_ip': remote_ip,
                                    'remote_port': remote_port,
                                    'local_ip': local_ip,
                                    'local_port': local_port,
                                    'state': state,
                                    'program': pid_program,
                                    'start_time': datetime.now()
                                }
                                
                                self.active_connections[connection_key] = connection_info
                                self.connection_count += 1
                                
                                # Log new connection
                                self.log_manager.log_event(
                                    "connection",
                                    f"New connection from {remote_ip}:{remote_port} to {local_ip}:{local_port} ({pid_program})",
                                    "INFO"
                                )
                                
                                # Track connection history for this IP
                                self.connection_history[remote_ip][local_port] += 1
                                
                                # Send to analyzer
                                if self.analyzer:
                                    self.analyzer.analyze_connection(connection_info)
                
                # Remove closed connections
                closed_connections = set(self.active_connections.keys()) - current_connections
                for conn_key in closed_connections:
                    conn = self.active_connections[conn_key]
                    duration = (datetime.now() - conn['start_time']).total_seconds()
                    
                    self.log_manager.log_event(
                        "connection",
                        f"Connection closed: {conn['remote_ip']}:{conn['remote_port']} to {conn['local_ip']}:{conn['local_port']} (Duration: {duration:.1f}s)",
                        "INFO"
                    )
                    
                    del self.active_connections[conn_key]
                
                # Sleep before next check
                time.sleep(2)
                    
            except Exception as e:
                logger.error(f"Error in connection monitoring: {e}")
                time.sleep(5)
                
    def _monitor_network_traffic(self):
        """Monitor network traffic statistics"""
        logger.info("Network traffic monitoring thread started")
        
        # Keep track of interface statistics
        last_stats = {}
        
        while self.running:
            try:
                # Read network stats from /proc/net/dev
                with open('/proc/net/dev', 'r') as f:
                    lines = f.readlines()
                    
                current_stats = {}
                
                # Skip the header lines
                for line in lines[2:]:
                    parts = line.strip().split(':')
                    if len(parts) < 2:
                        continue
                        
                    interface = parts[0].strip()
                    if interface == 'lo':  # Skip loopback
                        continue
                        
                    values = parts[1].split()
                    if len(values) < 16:
                        continue
                        
                    # Collect receive and transmit bytes
                    rx_bytes = int(values[0])
                    tx_bytes = int(values[8])
                    current_stats[interface] = {'rx_bytes': rx_bytes, 'tx_bytes': tx_bytes}
                    
                # Calculate rates
                for interface, stats in current_stats.items():
                    if interface in last_stats:
                        rx_rate = (stats['rx_bytes'] - last_stats[interface]['rx_bytes']) / 2.0  # bytes per second
                        tx_rate = (stats['tx_bytes'] - last_stats[interface]['tx_bytes']) / 2.0  # bytes per second
                        
                        # Convert to KB/s for logging
                        rx_rate_kb = rx_rate / 1024.0
                        tx_rate_kb = tx_rate / 1024.0
                        
                        # Log if traffic exceeds threshold
                        traffic_threshold = self.config.get("traffic_threshold_kb", 5000)  # 5 MB/s default
                        if rx_rate_kb > traffic_threshold or tx_rate_kb > traffic_threshold:
                            self.log_manager.log_event(
                                "traffic",
                                f"High traffic on {interface}: RX: {rx_rate_kb:.2f} KB/s, TX: {tx_rate_kb:.2f} KB/s",
                                "WARNING"
                            )
                            
                            # Send to analyzer
                            if self.analyzer:
                                self.analyzer.analyze_traffic_spike({
                                    'interface': interface,
                                    'rx_rate': rx_rate_kb,
                                    'tx_rate': tx_rate_kb,
                                    'timestamp': datetime.now()
                                })
                
                # Update last stats
                last_stats = current_stats
                
                # Sleep before next check
                time.sleep(2)
                    
            except Exception as e:
                logger.error(f"Error in traffic monitoring: {e}")
                time.sleep(5)
                
    def _check_suspicious_activity(self):
        """Check for suspicious network activity patterns"""
        logger.info("Suspicious activity monitoring thread started")
        
        while self.running:
            try:
                # Check for port scanning
                for ip, port_counter in self.connection_history.items():
                    # If an IP has tried to connect to many different ports in a short time
                    if len(port_counter) >= self.port_scan_threshold:
                        suspicious_ports_hit = sum(1 for port in port_counter if int(port) in self.suspicious_ports)
                        
                        if suspicious_ports_hit >= 3:  # If they've hit multiple sensitive ports
                            self.log_manager.log_event(
                                "threat",
                                f"Possible port scan detected from {ip} (tried {len(port_counter)} ports including {suspicious_ports_hit} sensitive ports)",
                                "WARNING"
                            )
                            
                            # Send to analyzer
                            if self.analyzer:
                                self.analyzer.analyze_port_scan({
                                    'source_ip': ip,
                                    'ports_tried': list(port_counter.keys()),
                                    'timestamp': datetime.now(),
                                    'suspicious_count': suspicious_ports_hit
                                })
                
                # Reset short-term history periodically to avoid false positives from legitimate scans
                current_time = time.time()
                if int(current_time) % 300 == 0:  # Every 5 minutes
                    self.connection_history.clear()
                    time.sleep(1)  # Ensure we don't trigger multiple times in the same second
                
                # Sleep before next check
                time.sleep(5)
                    
            except Exception as e:
                logger.error(f"Error in suspicious activity monitoring: {e}")
                time.sleep(5)
