
"""
Threat Analyzer Module for PhantomUF
Analyzes network traffic patterns and identifies potential threats
"""

import time
import logging
import threading
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque

logger = logging.getLogger("PhantomUF.Analyzer")

class ThreatAnalyzer:
    """Analyzes network traffic for potential threats"""
    
    def __init__(self, config, log_manager):
        self.config = config
        self.log_manager = log_manager
        self.defender = None
        self.running = False
        
        # Threat detection thresholds
        self.ddos_threshold = self.config.get("ddos_threshold", 100)  # connections per minute
        self.brute_force_threshold = self.config.get("brute_force_threshold", 5)  # failed auth attempts
        self.port_scan_threshold = self.config.get("port_scan_threshold", 15)  # ports tried
        
        # Data collection
        self.connection_history = defaultdict(lambda: deque(maxlen=60))  # Track last minute of connections
        self.auth_failures = defaultdict(int)  # Track authentication failures by IP
        self.traffic_spikes = defaultdict(list)  # Track traffic spikes by interface
        
        # Blacklist of known malicious IPs
        self.ip_blacklist = set()
        self.load_blacklist()
        
        # Whitelist of trusted IPs (never block these)
        self.ip_whitelist = set(['127.0.0.1'])
        whitelist_ips = self.config.get("whitelist_ips", [])
        self.ip_whitelist.update(whitelist_ips)
        
    def initialize(self):
        """Initialize the threat analyzer component"""
        logger.info("Initializing Threat Analyzer...")
        
    def set_defender(self, defender):
        """Set the threat defender reference"""
        self.defender = defender
        
    def start(self):
        """Start the threat analysis service"""
        if self.running:
            logger.warning("Threat Analyzer is already running")
            return
            
        logger.info("Starting Threat Analyzer...")
        self.running = True
        
        # Start analysis threads
        threading.Thread(target=self._analyze_periodic, daemon=True).start()
        
        logger.info("Threat Analyzer started successfully")
        
    def stop(self):
        """Stop the threat analysis service"""
        if not self.running:
            logger.warning("Threat Analyzer is not running")
            return
            
        logger.info("Stopping Threat Analyzer...")
        self.running = False
        logger.info("Threat Analyzer stopped successfully")
        
    def load_blacklist(self):
        """Load blacklisted IPs from configuration or external sources"""
        # Load from config
        blacklist_ips = self.config.get("blacklist_ips", [])
        self.ip_blacklist.update(blacklist_ips)
        
        # TODO: Implement loading from external threat intelligence feeds
        logger.info(f"Loaded {len(self.ip_blacklist)} blacklisted IPs")
        
    def analyze_connection(self, connection_info):
        """Analyze a new network connection for threats"""
        remote_ip = connection_info['remote_ip']
        
        # Skip localhost and private IPs from certain checks
        if remote_ip in ('127.0.0.1', '0.0.0.0', '::1'):
            return
            
        # Check if IP is in blacklist
        if remote_ip in self.ip_blacklist and remote_ip not in self.ip_whitelist:
            if self.defender:
                self.defender.block_ip(remote_ip, "IP in blacklist")
            return
            
        # Record connection for rate-based analysis
        timestamp = datetime.now()
        self.connection_history[remote_ip].append(timestamp)
        
        # Check for DDoS (too many connections too quickly)
        if len(self.connection_history[remote_ip]) >= self.ddos_threshold:
            if self._is_ddos_attack(remote_ip):
                self.log_manager.log_event(
                    "threat", 
                    f"Possible DDoS attack from {remote_ip} ({len(self.connection_history[remote_ip])} connections in last minute)", 
                    "WARNING"
                )
                
                if self.defender and remote_ip not in self.ip_whitelist:
                    self.defender.mitigate_ddos(remote_ip, self.connection_history[remote_ip])
                    
        # Check for connections to sensitive ports
        sensitive_ports = {'22': 'SSH', '3306': 'MySQL', '5432': 'PostgreSQL', '27017': 'MongoDB', 
                          '1433': 'MSSQL', '3389': 'RDP', '23': 'Telnet'}
        
        local_port = connection_info['local_port']
        if local_port in sensitive_ports:
            service = sensitive_ports[local_port]
            self.log_manager.log_event(
                "connection", 
                f"Connection to sensitive service {service} from {remote_ip}", 
                "INFO"
            )
            
    def analyze_auth_failure(self, auth_info):
        """Analyze an authentication failure for possible brute force attacks"""
        source_ip = auth_info['source_ip']
        service = auth_info['service']
        
        # Skip whitelist
        if source_ip in self.ip_whitelist:
            return
            
        # Increment failure counter for this IP
        self.auth_failures[source_ip] += 1
        
        if self.auth_failures[source_ip] >= self.brute_force_threshold:
            self.log_manager.log_event(
                "threat", 
                f"Possible brute force attack on {service} from {source_ip} ({self.auth_failures[source_ip]} failures)", 
                "WARNING"
            )
            
            if self.defender:
                self.defender.mitigate_brute_force(source_ip, service, self.auth_failures[source_ip])
                
            # Reset counter after taking action
            self.auth_failures[source_ip] = 0
            
    def analyze_traffic_spike(self, traffic_info):
        """Analyze a sudden spike in network traffic"""
        interface = traffic_info['interface']
        rx_rate = traffic_info['rx_rate']
        tx_rate = traffic_info['tx_rate']
        
        self.traffic_spikes[interface].append(traffic_info)
        
        # Keep only recent spikes
        cutoff_time = datetime.now() - timedelta(minutes=5)
        self.traffic_spikes[interface] = [
            spike for spike in self.traffic_spikes[interface] 
            if spike['timestamp'] > cutoff_time
        ]
        
        # If we've had multiple spikes in the last 5 minutes
        if len(self.traffic_spikes[interface]) >= 3:
            self.log_manager.log_event(
                "threat", 
                f"Sustained high traffic on {interface}: {rx_rate:.2f} KB/s RX, {tx_rate:.2f} KB/s TX", 
                "WARNING"
            )
            
            if self.defender:
                self.defender.mitigate_traffic_spike(interface, self.traffic_spikes[interface])
                
    def analyze_port_scan(self, scan_info):
        """Analyze a potential port scanning attempt"""
        source_ip = scan_info['source_ip']
        ports_tried = scan_info['ports_tried']
        suspicious_count = scan_info['suspicious_count']
        
        # Skip whitelist
        if source_ip in self.ip_whitelist:
            return
            
        threat_level = "Medium"
        if suspicious_count >= 5:
            threat_level = "High"
        elif suspicious_count >= 10:
            threat_level = "Critical"
            
        self.log_manager.log_event(
            "threat", 
            f"Port scan from {source_ip} - {len(ports_tried)} ports, {suspicious_count} sensitive ports - Threat: {threat_level}", 
            "WARNING"
        )
        
        if self.defender:
            # Block immediately for high threat scans
            if threat_level in ("High", "Critical"):
                self.defender.block_ip(source_ip, f"Port scan ({threat_level} threat)")
            else:
                self.defender.monitor_ip(source_ip, f"Suspicious scanning activity")
                
    def _is_ddos_attack(self, ip):
        """Determine if connection pattern represents a DDoS attack"""
        # Count connections in the last minute
        one_minute_ago = datetime.now() - timedelta(minutes=1)
        recent_connections = [ts for ts in self.connection_history[ip] if ts > one_minute_ago]
        
        # If connections exceed threshold and they come in consistent burst patterns
        if len(recent_connections) >= self.ddos_threshold:
            # Calculate time intervals between connections
            intervals = []
            for i in range(1, len(recent_connections)):
                interval = (recent_connections[i] - recent_connections[i-1]).total_seconds()
                intervals.append(interval)
                
            # If most intervals are very small, likely a DDoS
            if intervals and sum(i < 0.5 for i in intervals) / len(intervals) > 0.7:
                return True
                
        return False
        
    def _analyze_periodic(self):
        """Perform periodic threat analysis"""
        logger.info("Periodic threat analysis thread started")
        
        while self.running:
            try:
                # Clean up old connection data
                current_time = datetime.now()
                for ip in list(self.connection_history.keys()):
                    # Remove data older than 5 minutes
                    cutoff_time = current_time - timedelta(minutes=5)
                    while self.connection_history[ip] and self.connection_history[ip][0] < cutoff_time:
                        self.connection_history[ip].popleft()
                        
                    # Remove empty entries
                    if not self.connection_history[ip]:
                        del self.connection_history[ip]
                        
                # Reset auth failure counters periodically to prevent false positives
                if current_time.minute % 30 == 0 and current_time.second < 2:  # Every 30 minutes
                    self.auth_failures.clear()
                    time.sleep(2)  # Ensure we don't trigger multiple times
                    
                # Sleep for a bit
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in periodic threat analysis: {e}")
                time.sleep(30)
