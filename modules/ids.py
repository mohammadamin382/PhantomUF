
"""
Intrusion Detection System Module for PhantomUF
Implements advanced pattern detection and anomaly-based intrusion detection
"""

import re
import time
import logging
import threading
import subprocess
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque

logger = logging.getLogger("PhantomUF.IDS")

class IntrusionDetectionSystem:
    """Advanced intrusion detection system for PhantomUF"""
    
    def __init__(self, config, log_manager, defender):
        self.config = config
        self.log_manager = log_manager
        self.defender = defender
        self.running = False
        
        # Analysis windows and baselines
        self.traffic_baselines = {}
        self.connection_patterns = defaultdict(list)
        self.packet_signatures = self._load_signatures()
        self.anomaly_scores = defaultdict(float)
        
        # Learning data
        self.learning_mode = config.get("ids_learning_mode", False)
        self.learning_data = {
            'connections_per_hour': defaultdict(list),
            'bytes_per_minute': defaultdict(list),
            'port_access_patterns': defaultdict(set),
            'typical_user_agents': set(),
            'typical_protocols': Counter()
        }
        
        # Thresholds
        self.anomaly_threshold = config.get("anomaly_threshold", 0.75)
        self.alert_threshold = config.get("alert_threshold", 0.5)
        
        # Statistical models
        self.models = {}
        
    def initialize(self):
        """Initialize the IDS module"""
        logger.info("Initializing Intrusion Detection System...")
        
        # Load any saved baseline data
        self._load_baseline_data()
        
        # Initialize detection modules
        self._init_detection_modules()
        
        logger.info("IDS initialization complete")
        
    def start(self):
        """Start the IDS service"""
        if self.running:
            logger.warning("IDS is already running")
            return
            
        logger.info("Starting Intrusion Detection System...")
        self.running = True
        
        # Start analysis threads
        threading.Thread(target=self._analyze_traffic_patterns, daemon=True).start()
        threading.Thread(target=self._scan_for_signatures, daemon=True).start()
        threading.Thread(target=self._monitor_system_calls, daemon=True).start()
        
        if self.learning_mode:
            logger.info("IDS is in learning mode - will establish baselines before enforcement")
            threading.Thread(target=self._learning_process, daemon=True).start()
            
        logger.info("Intrusion Detection System started successfully")
        
    def stop(self):
        """Stop the IDS service"""
        if not self.running:
            logger.warning("IDS is not running")
            return
            
        logger.info("Stopping Intrusion Detection System...")
        self.running = False
        
        # Save learning data if needed
        if self.learning_mode:
            self._save_learning_data()
            
        logger.info("Intrusion Detection System stopped successfully")
        
    def analyze_packet(self, packet_data):
        """Analyze a network packet for suspicious content"""
        if not self.running:
            return
            
        # Extract packet metadata
        source_ip = packet_data.get('source_ip', '')
        dest_ip = packet_data.get('dest_ip', '')
        protocol = packet_data.get('protocol', '')
        payload = packet_data.get('payload', b'')
        
        # Skip analysis for whitelisted IPs
        whitelist_ips = self.config.get("whitelist_ips", [])
        if source_ip in whitelist_ips:
            return
            
        # Signature-based detection
        for sig_name, signature in self.packet_signatures.items():
            if re.search(signature['pattern'], payload, re.DOTALL):
                self.log_manager.log_event(
                    "ids",
                    f"Signature match: {sig_name} from {source_ip}",
                    "WARNING"
                )
                
                if self.defender and signature['severity'] >= 3:
                    self.defender.block_ip(source_ip, f"Malicious packet signature: {sig_name}")
                    
        # Add to learning data if in learning mode
        if self.learning_mode:
            self._add_to_learning_data(packet_data)
            
    def analyze_behavior(self, behavior_data):
        """Analyze system behavior for anomalies"""
        if not self.running:
            return
            
        source_ip = behavior_data.get('source_ip', '')
        behavior_type = behavior_data.get('type', '')
        details = behavior_data.get('details', {})
        
        # Calculate anomaly score based on deviation from baselines
        anomaly_score = self._calculate_anomaly_score(behavior_data)
        
        # Update running anomaly score for this IP
        self.anomaly_scores[source_ip] = max(
            0.8 * self.anomaly_scores[source_ip] + 0.2 * anomaly_score,
            anomaly_score
        )
        
        # Take action based on anomaly score
        if self.anomaly_scores[source_ip] >= self.anomaly_threshold:
            self.log_manager.log_event(
                "ids",
                f"High anomaly score for {source_ip}: {self.anomaly_scores[source_ip]:.2f} - {behavior_type}",
                "WARNING"
            )
            
            if self.defender:
                threat_score = int(self.anomaly_scores[source_ip] * 5)  # Convert to 0-5 scale
                self.defender.monitor_ip(source_ip, f"Behavioral anomaly: {behavior_type}", threat_score)
                
                # If extremely anomalous, block immediately
                if self.anomaly_scores[source_ip] > 0.9:
                    self.defender.block_ip(source_ip, f"Extreme behavioral anomaly: {behavior_type}")
                    
        # Alert on moderate anomalies
        elif self.anomaly_scores[source_ip] >= self.alert_threshold:
            self.log_manager.log_event(
                "ids",
                f"Moderate anomaly for {source_ip}: {self.anomaly_scores[source_ip]:.2f} - {behavior_type}",
                "INFO"
            )
            
    def _load_signatures(self):
        """Load known attack signatures"""
        # These are regex patterns that match known attack payloads
        signatures = {
            'sql_injection': {
                'pattern': rb'(?i)(\'|\%27)(\s|\+)*(OR|AND)(\s|\+)*(\(|\%28)',
                'severity': 4
            },
            'xss_basic': {
                'pattern': rb'(?i)(<script>|javascript:|\balert\s*\()',
                'severity': 3
            },
            'command_injection': {
                'pattern': rb'(?i)(\;|\||\`|\$\()\s*(cat|ls|nc|wget|curl|bash|chmod)',
                'severity': 5
            },
            'log4j': {
                'pattern': rb'\$\{jndi:(ldap|rmi|dns)://',
                'severity': 5
            },
            'buffer_overflow': {
                'pattern': rb'(\x90{20,})',  # NOP sled
                'severity': 5
            },
            'path_traversal': {
                'pattern': rb'(?i)(\.\.\/|\.\.%2f|\.\.\\)',
                'severity': 4
            }
        }
        
        # Add custom signatures from config
        custom_signatures = self.config.get("custom_signatures", {})
        signatures.update(custom_signatures)
        
        logger.info(f"Loaded {len(signatures)} attack signatures")
        return signatures
        
    def _load_baseline_data(self):
        """Load baseline data for anomaly detection"""
        # This would normally load from a saved file
        # For now, we'll create some reasonable defaults
        interfaces = self._get_network_interfaces()
        
        for interface in interfaces:
            self.traffic_baselines[interface] = {
                'avg_packets_per_min': 1000,
                'std_packets_per_min': 500,
                'avg_bytes_per_min': 1024 * 1024,  # 1 MB
                'std_bytes_per_min': 512 * 1024,   # 0.5 MB
                'typical_protocols': {'TCP': 0.7, 'UDP': 0.25, 'ICMP': 0.05}
            }
            
        logger.info(f"Established default baselines for {len(interfaces)} interfaces")
        
    def _init_detection_modules(self):
        """Initialize detection modules"""
        # This would initialize different detection strategies
        pass
        
    def _get_network_interfaces(self):
        """Get list of network interfaces"""
        interfaces = []
        try:
            # Parse /proc/net/dev for interface names
            with open('/proc/net/dev', 'r') as f:
                for line in f.readlines()[2:]:  # Skip header lines
                    interface = line.split(':')[0].strip()
                    if interface != 'lo':  # Skip loopback
                        interfaces.append(interface)
        except Exception as e:
            logger.error(f"Failed to get network interfaces: {e}")
            interfaces = ['eth0']  # Default fallback
            
        return interfaces
        
    def _analyze_traffic_patterns(self):
        """Analyze network traffic patterns for anomalies"""
        logger.info("Traffic pattern analysis thread started")
        
        while self.running:
            try:
                # Get current traffic statistics
                for interface in self.traffic_baselines.keys():
                    current_stats = self._get_interface_stats(interface)
                    
                    if not current_stats:
                        continue
                        
                    # Compare with baseline
                    baseline = self.traffic_baselines[interface]
                    z_score_packets = (current_stats['packets_per_min'] - baseline['avg_packets_per_min']) / max(1, baseline['std_packets_per_min'])
                    z_score_bytes = (current_stats['bytes_per_min'] - baseline['avg_bytes_per_min']) / max(1, baseline['std_bytes_per_min'])
                    
                    # Calculate protocol distribution anomaly
                    protocol_anomaly = 0
                    for proto, baseline_freq in baseline['typical_protocols'].items():
                        current_freq = current_stats['protocols'].get(proto, 0)
                        protocol_anomaly += abs(current_freq - baseline_freq)
                    
                    # Overall anomaly score for this traffic sample (0-1 scale)
                    traffic_anomaly = min(1.0, (
                        0.3 * min(abs(z_score_packets), 5) / 5 +
                        0.3 * min(abs(z_score_bytes), 5) / 5 +
                        0.4 * min(protocol_anomaly, 1)
                    ))
                    
                    # If anomaly detected
                    if traffic_anomaly > self.alert_threshold:
                        self.log_manager.log_event(
                            "ids",
                            f"Traffic anomaly on {interface}: score={traffic_anomaly:.2f}",
                            "WARNING" if traffic_anomaly > self.anomaly_threshold else "INFO"
                        )
                        
                        # Identify potential attacker IPs
                        attacker_ips = self._identify_anomalous_ips(interface)
                        
                        if attacker_ips and self.defender:
                            for ip, score in attacker_ips:
                                behavior_data = {
                                    'source_ip': ip,
                                    'type': 'traffic_anomaly',
                                    'details': {
                                        'interface': interface,
                                        'anomaly_score': score
                                    }
                                }
                                self.analyze_behavior(behavior_data)
                
                # Sleep before next analysis
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in traffic pattern analysis: {e}")
                time.sleep(60)
                
    def _get_interface_stats(self, interface):
        """Get current statistics for a network interface"""
        try:
            # This would collect real-time stats
            # For now, return mock data
            return {
                'packets_per_min': 1200,
                'bytes_per_min': 1.2 * 1024 * 1024,
                'protocols': {'TCP': 0.65, 'UDP': 0.3, 'ICMP': 0.05}
            }
        except Exception as e:
            logger.error(f"Failed to get interface stats for {interface}: {e}")
            return None
            
    def _identify_anomalous_ips(self, interface):
        """Identify IPs contributing to traffic anomalies"""
        try:
            # This would use tools like iftop to find top bandwidth consumers
            # For now, return empty list
            return []
        except Exception as e:
            logger.error(f"Failed to identify anomalous IPs: {e}")
            return []
            
    def _scan_for_signatures(self):
        """Periodically scan traffic for known attack signatures"""
        logger.info("Signature scanning thread started")
        
        while self.running:
            try:
                # Simulate packet capture and analysis
                # In reality, this would use libpcap or similar
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in signature scanning: {e}")
                time.sleep(30)
                
    def _monitor_system_calls(self):
        """Monitor system calls for suspicious activity"""
        logger.info("System call monitoring thread started")
        
        while self.running:
            try:
                # This would use tools like auditd to monitor syscalls
                # For now, just sleep
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in system call monitoring: {e}")
                time.sleep(30)
                
    def _calculate_anomaly_score(self, behavior_data):
        """Calculate anomaly score based on behavior data"""
        # Simplified scoring model
        return 0.5  # Default moderate score
        
    def _add_to_learning_data(self, data):
        """Add data to learning dataset during learning mode"""
        if 'source_ip' in data:
            ip = data['source_ip']
            self.learning_data['bytes_per_minute'][ip].append(
                data.get('bytes', 0)
            )
            
        if 'protocol' in data:
            self.learning_data['typical_protocols'][data['protocol']] += 1
            
    def _save_learning_data(self):
        """Save learning data for future use"""
        logger.info("Saving learned baselines")
        # This would save to a persistent format
        
    def _learning_process(self):
        """Process that builds baseline models in learning mode"""
        logger.info("IDS learning process started")
        
        learn_duration = self.config.get("learning_duration", 24 * 60 * 60)  # 24 hours default
        start_time = time.time()
        
        while self.running and time.time() - start_time < learn_duration:
            # Calculate percentage complete
            pct_complete = min(100, int((time.time() - start_time) / learn_duration * 100))
            
            if pct_complete % 10 == 0:
                logger.info(f"IDS learning: {pct_complete}% complete")
                
            time.sleep(60)
            
        # When complete, build models from collected data
        if self.running:
            logger.info("IDS learning complete, building baseline models")
            self._build_baseline_models()
            
            # Switch out of learning mode
            self.learning_mode = False
            self.config.set("ids_learning_mode", False)
            
            logger.info("IDS now in active protection mode")
            
    def _build_baseline_models(self):
        """Build statistical models from learning data"""
        # Calculate averages and standard deviations
        for ip, bytes_data in self.learning_data['bytes_per_minute'].items():
            if len(bytes_data) > 10:  # Only if we have enough samples
                self.models[f"bytes_per_min_{ip}"] = {
                    'mean': np.mean(bytes_data),
                    'std': max(1, np.std(bytes_data))
                }
                
        # Build protocol distribution model
        total = sum(self.learning_data['typical_protocols'].values())
        if total > 0:
            self.models["protocol_distribution"] = {
                proto: count / total 
                for proto, count in self.learning_data['typical_protocols'].items()
            }
            
        logger.info(f"Built {len(self.models)} baseline models from learning data")
