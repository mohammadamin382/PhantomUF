
"""
Threat Defender Module for PhantomUF
Responds to identified threats with appropriate defensive measures
"""

import time
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("PhantomUF.Defender")

class ThreatDefender:
    """Defends against identified network threats"""
    
    def __init__(self, config, log_manager, firewall):
        self.config = config
        self.log_manager = log_manager
        self.firewall = firewall
        self.running = False
        
        # Defense settings
        self.auto_block = self.config.get("auto_block", True)
        self.block_duration = self.config.get("block_duration", 3600)  # 1 hour by default
        self.max_threat_level = self.config.get("max_threat_level", 5)  # 1-5 scale
        
        # Monitoring data
        self.monitored_ips = {}  # IPs under extra scrutiny
        self.blocked_ips = {}  # Currently blocked IPs
        self.threat_scores = defaultdict(int)  # Cumulative threat scores by IP
        self.blocked_count = 0  # Counter for blocked threats
        
    def initialize(self):
        """Initialize the threat defender component"""
        logger.info("Initializing Threat Defender...")
        
    def start(self):
        """Start the threat defense service"""
        if self.running:
            logger.warning("Threat Defender is already running")
            return
            
        logger.info("Starting Threat Defender...")
        self.running = True
        
        # Start defense threads
        threading.Thread(target=self._monitor_threats, daemon=True).start()
        
        logger.info("Threat Defender started successfully")
        
    def stop(self):
        """Stop the threat defense service"""
        if not self.running:
            logger.warning("Threat Defender is not running")
            return
            
        logger.info("Stopping Threat Defender...")
        self.running = False
        logger.info("Threat Defender stopped successfully")
        
    def block_ip(self, ip, reason, duration=None):
        """Block an IP address due to malicious activity"""
        if not duration:
            duration = self.block_duration
            
        if ip in self.blocked_ips:
            logger.info(f"IP {ip} is already blocked")
            return
            
        if not self.auto_block:
            self.log_manager.log_event(
                "defense", 
                f"Would block IP {ip} for {reason}, but auto-blocking is disabled", 
                "WARNING"
            )
            return
            
        # Apply firewall rule to block the IP
        rule_id = self.firewall.block_ip(ip, reason, duration)
        
        if rule_id:
            self.blocked_ips[ip] = {
                'rule_id': rule_id,
                'reason': reason,
                'blocked_at': datetime.now(),
                'duration': duration
            }
            
            self.blocked_count += 1
            
            self.log_manager.log_event(
                "defense", 
                f"Blocked IP {ip} for {reason} (duration: {duration}s)", 
                "WARNING"
            )
            
            logger.info(f"Blocked IP {ip} for {reason}")
            
            # If temporary block, schedule unblock
            if duration:
                def unblock_later():
                    time.sleep(duration)
                    self.unblock_ip(ip, "Block duration expired")
                    
                threading.Thread(target=unblock_later, daemon=True).start()
                
    def unblock_ip(self, ip, reason):
        """Remove IP block"""
        if ip not in self.blocked_ips:
            logger.warning(f"IP {ip} is not blocked")
            return
            
        rule_id = self.blocked_ips[ip]['rule_id']
        if self.firewall.delete_rule(rule_id):
            self.log_manager.log_event(
                "defense", 
                f"Unblocked IP {ip}: {reason}", 
                "INFO"
            )
            
            del self.blocked_ips[ip]
            logger.info(f"Unblocked IP {ip}: {reason}")
            
    def monitor_ip(self, ip, reason, threat_score=1):
        """Add an IP to enhanced monitoring"""
        if ip in self.monitored_ips:
            # Update existing monitoring
            self.monitored_ips[ip]['last_updated'] = datetime.now()
            self.monitored_ips[ip]['reasons'].append(reason)
        else:
            # Start new monitoring
            self.monitored_ips[ip] = {
                'first_seen': datetime.now(),
                'last_updated': datetime.now(),
                'reasons': [reason]
            }
            
            self.log_manager.log_event(
                "defense", 
                f"Added IP {ip} to enhanced monitoring: {reason}", 
                "INFO"
            )
            
        # Update threat score
        self.threat_scores[ip] += threat_score
        
        # If threat score exceeds threshold, block the IP
        if self.threat_scores[ip] >= self.max_threat_level:
            reasons = ', '.join(self.monitored_ips[ip]['reasons'])
            self.block_ip(ip, f"Cumulative suspicious activity: {reasons}")
            
    def mitigate_ddos(self, source_ip, connection_data):
        """Mitigate a DDoS attack"""
        connection_count = len(connection_data)
        
        self.log_manager.log_event(
            "defense", 
            f"Mitigating DDoS from {source_ip} ({connection_count} connections)", 
            "WARNING"
        )
        
        # Block the attacking IP
        self.block_ip(source_ip, f"DDoS attack ({connection_count} connections/min)")
        
        # Apply additional protection if needed
        if connection_count > 1000:  # Severe attack
            self._apply_ddos_protection()
            
    def mitigate_brute_force(self, source_ip, service, failure_count):
        """Mitigate a brute force attack"""
        self.log_manager.log_event(
            "defense", 
            f"Mitigating brute force on {service} from {source_ip} ({failure_count} failures)", 
            "WARNING"
        )
        
        # For lower counts, just monitor
        if failure_count < 10:
            self.monitor_ip(source_ip, f"Brute force attempt on {service}", threat_score=2)
        else:
            # For higher counts, block immediately
            self.block_ip(source_ip, f"Brute force attack on {service} ({failure_count} failures)")
            
    def mitigate_traffic_spike(self, interface, traffic_data):
        """Mitigate a suspicious traffic spike"""
        # This is more complex as we need to identify the source
        # For now, just log it and apply general protection
        avg_rx = sum(spike['rx_rate'] for spike in traffic_data) / len(traffic_data)
        avg_tx = sum(spike['tx_rate'] for spike in traffic_data) / len(traffic_data)
        
        self.log_manager.log_event(
            "defense", 
            f"Mitigating traffic spike on {interface} (Avg: {avg_rx:.2f} KB/s RX, {avg_tx:.2f} KB/s TX)", 
            "WARNING"
        )
        
        # Try to identify sources of high traffic
        self._identify_traffic_sources(interface)
        
    def get_blocked_count(self):
        """Get the count of threats that have been blocked"""
        return self.blocked_count
        
    def _apply_ddos_protection(self):
        """Apply emergency DDoS protection measures"""
        # Apply rate limiting for all incoming connections
        try:
            # Limit incoming TCP connections
            subprocess.run([
                "iptables", "-A", "PHANTOM_INPUT", "-p", "tcp", 
                "--syn", "-m", "limit", "--limit", "20/s", 
                "--limit-burst", "100", "-j", "ACCEPT"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Drop excessive SYN packets
            subprocess.run([
                "iptables", "-A", "PHANTOM_INPUT", "-p", "tcp", 
                "--syn", "-j", "DROP"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Limit ICMP
            subprocess.run([
                "iptables", "-A", "PHANTOM_INPUT", "-p", "icmp", 
                "-m", "limit", "--limit", "1/s", 
                "--limit-burst", "10", "-j", "ACCEPT"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            subprocess.run([
                "iptables", "-A", "PHANTOM_INPUT", "-p", "icmp", 
                "-j", "DROP"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.log_manager.log_event(
                "defense", 
                "Applied emergency DDoS protection measures", 
                "WARNING"
            )
            
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to apply DDoS protection: {e}")
            
    def _identify_traffic_sources(self, interface):
        """Try to identify sources of high traffic"""
        try:
            # Use iftop to find top bandwidth consumers
            output = subprocess.check_output(
                ["timeout", "5", "iftop", "-i", interface, "-t", "-n", "-s", "2"],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Parse iftop output
            high_traffic_ips = []
            for line in output.split('\n'):
                if "=>" in line or "<=" in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        ip = parts[1].split(':')[0]
                        rate = parts[2]
                        
                        # Add to list if rate seems high
                        if 'MB' in rate or ('KB' in rate and float(rate.replace('KB', '')) > 1000):
                            high_traffic_ips.append(ip)
                            
            # Take action on high traffic sources
            for ip in set(high_traffic_ips):
                if ip not in self.blocked_ips:
                    self.monitor_ip(ip, f"High bandwidth usage on {interface}", threat_score=2)
                    
                    self.log_manager.log_event(
                        "defense", 
                        f"Monitoring IP {ip} due to high traffic on {interface}", 
                        "INFO"
                    )
            
        except Exception as e:
            logger.error(f"Failed to identify traffic sources: {e}")
            
    def _monitor_threats(self):
        """Periodically review and update threat monitoring"""
        logger.info("Threat monitoring thread started")
        
        while self.running:
            try:
                current_time = datetime.now()
                
                # Clean up old monitoring entries
                for ip in list(self.monitored_ips.keys()):
                    # If not updated in 24 hours, remove from monitoring
                    if current_time - self.monitored_ips[ip]['last_updated'] > timedelta(hours=24):
                        del self.monitored_ips[ip]
                        self.threat_scores[ip] = 0
                        logger.info(f"Removed {ip} from monitoring (inactive for 24 hours)")
                        
                # Reduce threat scores over time (natural decay)
                if current_time.hour % 1 == 0 and current_time.minute == 0 and current_time.second < 5:
                    for ip in list(self.threat_scores.keys()):
                        self.threat_scores[ip] = max(0, self.threat_scores[ip] - 1)
                    time.sleep(5)  # Ensure we don't trigger multiple times
                    
                # Clean up expired blocks
                for ip in list(self.blocked_ips.keys()):
                    block_info = self.blocked_ips[ip]
                    elapsed = (current_time - block_info['blocked_at']).total_seconds()
                    
                    # If block has expired and it hasn't been auto-unblocked
                    if elapsed > block_info['duration'] and ip in self.blocked_ips:
                        self.unblock_ip(ip, "Block duration expired")
                        
                # Sleep for a bit
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in threat monitoring: {e}")
                time.sleep(60)
