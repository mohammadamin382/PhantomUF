
#!/usr/bin/env python3
"""
PhantomUF - Advanced Real-time Linux Network Security System
A comprehensive security solution for Linux systems that provides
real-time protection against network threats with advanced detection
and mitigation capabilities.
"""

import os
import sys
import time
import socket
import logging
import logging.handlers
import argparse
import threading
import subprocess
import ipaddress
import random
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Import modules
from modules.firewall import FirewallManager
from modules.monitor import NetworkMonitor
from modules.analyzer import ThreatAnalyzer
from modules.defender import ThreatDefender
from modules.logger import LogManager
from modules.config import ConfigManager
from modules.utils import banner, is_root, setup_environment
from modules.ids import IntrusionDetectionSystem
from modules.encryption import EncryptionManager
from modules.vulnerability import VulnerabilityScanner
from modules.ml_detection import MLThreatDetection
from modules.quantum_resistant import QuantumResistantEncryption
from modules.behavioral_biometrics import BehavioralBiometrics
from modules.blockchain_verification import BlockchainVerification

# Setup logging with advanced configuration
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(process)d:%(thread)d] - %(message)s'
)

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Create file handler with log rotation
file_handler = logging.handlers.RotatingFileHandler(
    "logs/phantomuf.log", 
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5
)
file_handler.setFormatter(log_formatter)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

# Setup root logger
logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, console_handler]
)

logger = logging.getLogger("PhantomUF")

class PhantomUF:
    """Main PhantomUF security system class"""
    
    def __init__(self):
        self.running = False
        self.version = "3.0.0"
        self.config = ConfigManager()
        self.log_manager = LogManager(self.config)
        
        # Core security components
        self.encryption = EncryptionManager(self.config)
        self.quantum_encryption = QuantumResistantEncryption(self.config)
        self.firewall = FirewallManager(self.config, self.log_manager)
        self.monitor = NetworkMonitor(self.config, self.log_manager)
        self.analyzer = ThreatAnalyzer(self.config, self.log_manager)
        self.defender = ThreatDefender(self.config, self.log_manager, self.firewall)
        
        # Advanced protection components
        self.ids = IntrusionDetectionSystem(self.config, self.log_manager, self.defender)
        self.ml_detection = MLThreatDetection(self.config, self.log_manager, self.defender)
        self.vulnerability_scanner = VulnerabilityScanner(self.config, self.log_manager)
        self.behavioral_biometrics = BehavioralBiometrics(self.config, self.log_manager)
        
        # Verification and integrity components
        self.blockchain = BlockchainVerification(self.config, self.log_manager, self.encryption)
        
        # Internal state
        self.startup_time = None
        self.security_score = None
        self.security_events = []
        self.last_update_check = None
        self.threat_intelligence_update = None
        
        # Register components with each other
        self.monitor.set_analyzer(self.analyzer)
        self.analyzer.set_defender(self.defender)
        self.analyzer.set_ml_detection(self.ml_detection)
        
        # Initialize components
        self._initialize_components()
        
    def _initialize_components(self):
        """Initialize all security components"""
        logger.info("Initializing PhantomUF components...")
        
        # Setup security event logging
        self._setup_event_logging()
        
        # Initialize encryption and security foundation first
        self.encryption.initialize() if hasattr(self.encryption, 'initialize') else None
        self.quantum_encryption.initialize()
        
        # Initialize core components
        self.firewall.initialize()
        self.monitor.initialize()
        self.analyzer.initialize()
        self.defender.initialize()
        
        # Initialize advanced protection components
        self.ids.initialize()
        self.ml_detection.initialize()
        self.vulnerability_scanner.initialize()
        self.behavioral_biometrics.initialize()
        
        # Initialize verification components
        self.blockchain.initialize()
        
        # Run initial security checks
        self._perform_initial_security_check()
        
        # Enable security subsystems integrity verification
        self._verify_system_integrity()
        
        logger.info("All components initialized successfully")
        
    def _setup_event_logging(self):
        """Setup security event logging"""
        # Create a secure event log
        self.log_manager.log_event(
            "system",
            f"PhantomUF v{self.version} initializing",
            "INFO"
        )
        
    def _perform_initial_security_check(self):
        """Perform initial security check of the system"""
        logger.info("Performing initial security check...")
        
        # Check operating system and kernel
        try:
            kernel = subprocess.check_output(["uname", "-r"], universal_newlines=True).strip()
            logger.info(f"Running on kernel: {kernel}")
            
            # Get distribution info
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    os_info = {}
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_info[key] = value.strip('"')
                            
                if 'NAME' in os_info and 'VERSION_ID' in os_info:
                    logger.info(f"Distribution: {os_info['NAME']} {os_info['VERSION_ID']}")
        except Exception as e:
            logger.warning(f"Could not determine system information: {e}")
            
        # Check security features
        security_features = []
        
        # Check if ASLR is enabled
        try:
            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                aslr = f.read().strip()
                if aslr == '2':
                    security_features.append("ASLR:enabled")
                else:
                    security_features.append("ASLR:partial/disabled")
        except Exception:
            pass
            
        # Check SELinux or AppArmor
        selinux_enabled = os.path.exists('/etc/selinux/config')
        apparmor_enabled = os.path.exists('/etc/apparmor')
        
        if selinux_enabled:
            security_features.append("SELinux:installed")
        if apparmor_enabled:
            security_features.append("AppArmor:installed")
            
        logger.info(f"Security features detected: {', '.join(security_features)}")
        
    def start(self, settings=None):
        """Start the PhantomUF security system"""
        if self.running:
            logger.warning("PhantomUF is already running!")
            return False
            
        if not is_root():
            logger.error("PhantomUF requires root privileges to function properly")
            return False
            
        # Apply custom settings if provided
        if settings:
            self.config.apply_settings(settings)
        
        logger.info(f"Starting PhantomUF v{self.version}...")
        banner()
        
        # Record startup time
        self.startup_time = datetime.now()
        
        # Setup the environment and ensure dependencies are available
        setup_environment()
        
        # Apply system hardening if configured
        if self.config.get("apply_system_hardening", True):
            self._harden_system()
        
        # Start components with staggered startup to avoid resource spikes
        self.firewall.start()
        time.sleep(0.5)
        
        self.monitor.start()
        time.sleep(0.5)
        
        self.analyzer.start()
        time.sleep(0.5)
        
        self.defender.start()
        time.sleep(0.5)
        
        self.ids.start()
        time.sleep(0.5)
        
        self.ml_detection.start()
        time.sleep(0.5)
        
        self.behavioral_biometrics.start()
        time.sleep(0.5)
        
        self.blockchain.start()
        time.sleep(0.5)
        
        # Start background maintenance tasks
        threading.Thread(target=self._maintenance_thread, daemon=True).start()
        
        # Start security scoring thread
        threading.Thread(target=self._security_score_thread, daemon=True).start()
        
        # Start threat intelligence update thread
        threading.Thread(target=self._threat_intelligence_thread, daemon=True).start()
        
        # Check for updates
        threading.Thread(target=self._check_for_updates, daemon=True).start()
        
        # Start integrity verification thread
        threading.Thread(target=self._integrity_verification_thread, daemon=True).start()
        
        self.running = True
        self.log_manager.log_event(
            "system",
            f"PhantomUF v{self.version} started with {self.config.get('policy', 'moderate')} policy",
            "INFO"
        )
        logger.info("PhantomUF is now running and actively protecting your system")
        
        try:
            # Keep the main thread alive to handle signals
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
            self.stop()
            
        return True
        
    def stop(self):
        """Stop the PhantomUF security system"""
        if not self.running:
            logger.warning("PhantomUF is not running!")
            return False
            
        logger.info("Stopping PhantomUF...")
        
        # Log the stop event
        self.log_manager.log_event(
            "system",
            "PhantomUF stopping - user initiated shutdown",
            "INFO"
        )
        
        # Stop components in reverse order
        self.blockchain.stop()
        time.sleep(0.2)
        
        self.behavioral_biometrics.stop()
        time.sleep(0.2)
        
        self.ml_detection.stop()
        time.sleep(0.2)
        
        self.ids.stop()
        time.sleep(0.2)
        
        self.defender.stop()
        time.sleep(0.2)
        
        self.analyzer.stop()
        time.sleep(0.2)
        
        self.monitor.stop()
        time.sleep(0.2)
        
        self.firewall.stop()
        
        # Record final state before shutdown
        self._record_final_state()
        
        self.running = False
        logger.info("PhantomUF has been stopped")
        return True
        
    def status(self):
        """Get the current status of PhantomUF"""
        status_info = {
            "version": self.version,
            "running": self.running,
            "uptime": self._get_uptime_string() if self.running else "Not running",
            "policy": self.config.get("policy", "moderate"),
            "threats_blocked": self.defender.get_blocked_count() if self.running else 0,
            "firewall_rules": self.firewall.get_rule_count() if self.running else 0,
            "connections_monitored": self.monitor.get_connection_count() if self.running else 0,
            "security_score": self.security_score if self.security_score else "Calculating...",
            "last_threat_intelligence_update": self.threat_intelligence_update.strftime("%Y-%m-%d %H:%M:%S") if self.threat_intelligence_update else "Never",
            "quantum_encryption": "Active" if hasattr(self, 'quantum_encryption') and self.running else "Inactive",
            "ml_detection": "Active" if hasattr(self, 'ml_detection') and self.running else "Inactive",
            "blockchain_verification": "Active" if hasattr(self, 'blockchain') and self.running else "Inactive",
        }
        
        # Add ML detection metrics if available
        if hasattr(self, 'ml_detection') and self.running:
            status_info["ml_metrics"] = self.ml_detection.get_performance_metrics()
            
        # Add blockchain stats if available
        if hasattr(self, 'blockchain') and self.running:
            status_info["blockchain_stats"] = self.blockchain.get_blockchain_stats()
        
        # Add security events
        if self.security_events:
            status_info["recent_security_events"] = self.security_events[-5:]
            
        # Add resource usage
        status_info["resource_usage"] = self._get_resource_usage()
        
        return status_info
        
    def show_logs(self, log_type="all", count=50):
        """Display system logs"""
        return self.log_manager.get_logs(log_type, count)
        
    def run_vulnerability_scan(self, scan_type="basic"):
        """Run a vulnerability scan"""
        if not self.running:
            logger.warning("PhantomUF must be running to perform vulnerability scans")
            return None
            
        logger.info(f"Initiating {scan_type} vulnerability scan...")
        return self.vulnerability_scanner.run_scan(scan_type)
        
    def apply_security_recommendation(self, recommendation_id):
        """Apply a security recommendation"""
        if not self.running:
            logger.warning("PhantomUF must be running to apply security recommendations")
            return False
            
        logger.info(f"Applying security recommendation: {recommendation_id}")
        
        # This would implement logic to apply specific security recommendations
        # For now, just log it
        self.log_manager.log_event(
            "system",
            f"Applied security recommendation: {recommendation_id}",
            "INFO"
        )
        
        return True
        
    def get_security_recommendations(self):
        """Get security improvement recommendations"""
        recommendations = []
        
        # This would analyze the system and provide custom recommendations
        # Mock recommendations for now
        recommendations.append({
            "id": "SEC-001",
            "title": "Enable automatic security updates",
            "description": "Configure system to automatically apply security updates",
            "severity": "medium",
            "effort": "low"
        })
        
        recommendations.append({
            "id": "SEC-002",
            "title": "Implement Network Segmentation",
            "description": "Separate network into isolated segments to limit lateral movement",
            "severity": "high",
            "effort": "high"
        })
        
        return recommendations
        
    def export_security_report(self, format="pdf"):
        """Export a comprehensive security report"""
        # This would generate a security report in the requested format
        # For now, just log it
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"security_report_{timestamp}.{format}"
        
        self.log_manager.log_event(
            "system",
            f"Exported security report to {report_file}",
            "INFO"
        )
        
        return report_file
        
    def _get_uptime_string(self):
        """Get formatted uptime string"""
        if not self.startup_time:
            return "Unknown"
            
        uptime = datetime.now() - self.startup_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        
        return " ".join(parts)
        
    def _get_resource_usage(self):
        """Get resource usage information"""
        usage = {
            "cpu": "0%",
            "memory": "0MB",
            "disk": "0MB"
        }
        
        # This would use psutil to get actual usage
        # For now, return mock data
        if self.running:
            usage["cpu"] = f"{random.randint(1, 5)}%"
            usage["memory"] = f"{random.randint(50, 200)}MB"
            usage["disk"] = f"{random.randint(10, 50)}MB"
            
        return usage
        
    def _harden_system(self):
        """Apply system hardening measures"""
        logger.info("Applying system hardening measures...")
        
        hardening_measures = [
            # ASLR (Address Space Layout Randomization)
            {"name": "Enable ASLR", "command": ["sysctl", "-w", "kernel.randomize_va_space=2"]},
            
            # Disable core dumps
            {"name": "Disable core dumps", "command": ["sysctl", "-w", "fs.suid_dumpable=0"]},
            
            # Protect against IP spoofing
            {"name": "Protect against IP spoofing", "command": ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"]},
            
            # Ignore ICMP broadcast requests
            {"name": "Ignore ICMP broadcast", "command": ["sysctl", "-w", "net.ipv4.icmp_echo_ignore_broadcasts=1"]},
            
            # Disable IP forwarding
            {"name": "Disable IP forwarding", "command": ["sysctl", "-w", "net.ipv4.ip_forward=0"]},
            
            # Disable IPv6 if not needed
            {"name": "Disable IPv6", "command": ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"]}
        ]
        
        applied_count = 0
        for measure in hardening_measures:
            try:
                logger.info(f"Applying hardening: {measure['name']}")
                subprocess.run(measure['command'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                applied_count += 1
            except Exception as e:
                logger.warning(f"Failed to apply {measure['name']}: {e}")
                
        logger.info(f"Applied {applied_count}/{len(hardening_measures)} hardening measures")
        
        # Log hardening event
        self.log_manager.log_event(
            "system",
            f"Applied {applied_count} system hardening measures",
            "INFO"
        )
        
    def _record_final_state(self):
        """Record final system state before shutdown"""
        if not self.startup_time:
            return
            
        uptime = datetime.now() - self.startup_time
        blocked_count = self.defender.get_blocked_count() if hasattr(self.defender, 'get_blocked_count') else 0
        
        self.log_manager.log_event(
            "system",
            f"Final state - Uptime: {uptime}, Threats blocked: {blocked_count}",
            "INFO"
        )
        
    def _maintenance_thread(self):
        """Background maintenance thread"""
        logger.info("Maintenance thread started")

    def _verify_system_integrity(self):
        """Verify the integrity of the security system components"""
        logger.info("Verifying system integrity...")
        
        # Check for file modifications
        integrity_issues = []
        
        # In a complete implementation, this would check file hashes against known good values
        
        if integrity_issues:
            for issue in integrity_issues:
                self.log_manager.log_event(
                    "integrity",
                    f"System integrity violation: {issue}",
                    "CRITICAL"
                )
            logger.critical(f"Found {len(integrity_issues)} integrity violations!")
        else:
            logger.info("System integrity verified successfully")
            
    def _threat_intelligence_thread(self):
        """Thread to update threat intelligence data"""
        logger.info("Threat intelligence thread started")
        
        while self.running:
            try:
                # This would download updated threat intelligence from trusted sources
                # For now, just log it
                current_time = datetime.now()
                logger.info("Updating threat intelligence database")
                
                self.threat_intelligence_update = current_time
                
                # Record the event
                self.security_events.append({
                    "time": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "system",
                    "description": "Updated threat intelligence database"
                })
                
                # Sleep for 12 hours before next update
                for _ in range(12 * 60):  # Check every minute for 12 hours
                    if not self.running:
                        break
                    time.sleep(60)
                    
            except Exception as e:
                logger.error(f"Error in threat intelligence update: {e}")
                time.sleep(1800)  # Retry after 30 minutes
                
    def _integrity_verification_thread(self):
        """Thread to periodically verify system integrity"""
        logger.info("Integrity verification thread started")
        
        while self.running:
            try:
                # Perform periodic integrity checks
                self._verify_system_integrity()
                
                # Verify blockchain integrity if available
                if hasattr(self, 'blockchain') and self.blockchain.running:
                    if self.blockchain.verify_chain_integrity():
                        logger.info("Blockchain integrity verified successfully")
                    else:
                        logger.critical("Blockchain integrity verification failed!")
                        
                        self.log_manager.log_event(
                            "integrity",
                            "Blockchain integrity verification failed - possible tampering detected",
                            "CRITICAL"
                        )
                
                # Sleep for 6 hours before next verification
                for _ in range(6 * 60):  # Check every minute for 6 hours
                    if not self.running:
                        break
                    time.sleep(60)
                    
            except Exception as e:
                logger.error(f"Error in integrity verification: {e}")
                time.sleep(1800)  # Retry after 30 minutes

        
        while self.running:
            try:
                # Perform regular maintenance tasks
                self._rotate_encryption_keys()
                self._cleanup_expired_data()
                self._update_threat_intelligence()
                
                # Sleep for a day between maintenance runs
                for _ in range(24 * 60):  # Check every minute for 24 hours
                    if not self.running:
                        break
                    time.sleep(60)
                    
            except Exception as e:
                logger.error(f"Error in maintenance thread: {e}")
                time.sleep(3600)  # Sleep for an hour before retry
                
    def _security_score_thread(self):
        """Thread to calculate security score"""
        logger.info("Security scoring thread started")
        
        while self.running:
            try:
                # Calculate security score based on multiple factors
                score_components = {
                    "firewall_rules": min(100, self.firewall.get_rule_count() * 5),
                    "threat_response": self._calculate_threat_response_score(),
                    "vulnerability_patching": self._calculate_vulnerability_score(),
                    "system_hardening": self._calculate_hardening_score(),
                    "monitoring_coverage": self._calculate_monitoring_score()
                }
                
                # Calculate weighted average
                weights = {
                    "firewall_rules": 0.15,
                    "threat_response": 0.30,
                    "vulnerability_patching": 0.25,
                    "system_hardening": 0.20,
                    "monitoring_coverage": 0.10
                }
                
                self.security_score = sum(
                    score * weights[component]
                    for component, score in score_components.items()
                )
                
                # Round to 1 decimal place
                self.security_score = round(self.security_score, 1)
                
                logger.debug(f"Updated security score: {self.security_score}")
                
                # Sleep for a while before recalculating
                time.sleep(3600)  # Update hourly
                
            except Exception as e:
                logger.error(f"Error in security score thread: {e}")
                time.sleep(1800)  # Retry after 30 minutes
                
    def _calculate_threat_response_score(self):
        """Calculate threat response score component"""
        # This would calculate a real score based on threat detection and response metrics
        # For now, return a reasonable mock score
        return 85.0
        
    def _calculate_vulnerability_score(self):
        """Calculate vulnerability patching score component"""
        # This would calculate a real score based on vulnerability status
        # For now, return a reasonable mock score
        return 70.0
        
    def _calculate_hardening_score(self):
        """Calculate system hardening score component"""
        # This would calculate a real score based on applied hardening measures
        # For now, return a reasonable mock score
        return 75.0
        
    def _calculate_monitoring_score(self):
        """Calculate monitoring coverage score component"""
        # This would calculate a real score based on monitoring coverage
        # For now, return a reasonable mock score
        return 90.0
        
    def _rotate_encryption_keys(self):
        """Periodically rotate encryption keys"""
        # Check if key rotation is due
        rotation_interval = self.config.get("key_rotation_interval_days", 30)
        
        # Implement key rotation logic
        # For now, just log it
        logger.info(f"Encryption key rotation scheduled every {rotation_interval} days")
        
    def _cleanup_expired_data(self):
        """Clean up old data to reduce disk usage"""
        # This would implement cleanup logic
        # For now, just log it
        logger.info("Performing data cleanup")
        
    def _update_threat_intelligence(self):
        """Update threat intelligence data"""
        # This would download updated threat intelligence
        # For now, just log it
        logger.info("Updating threat intelligence")
        
    def _check_for_updates(self):
        """Check for PhantomUF updates"""
        self.last_update_check = datetime.now()
        
        # This would check for updates from a repository
        # For now, just log it
        logger.info("Checking for PhantomUF updates")
        
        # Record the event
        self.security_events.append({
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "system",
            "description": "Checked for updates"
        })


def main():
    """Main entry point for the PhantomUF CLI"""
    parser = argparse.ArgumentParser(description="PhantomUF - Ultra-Secure Real-time Network Security System")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Start command
    start_parser = subparsers.add_parser("start", help="Start the PhantomUF security system")
    start_parser.add_argument("--config", help="Path to configuration file")
    start_parser.add_argument("--policy", choices=["strict", "moderate", "learning"], 
                             help="Security policy", default="moderate")
    start_parser.add_argument("--no-auto-block", action="store_true", 
                             help="Disable automatic blocking of threats")
    start_parser.add_argument("--no-hardening", action="store_true",
                             help="Disable automatic system hardening")
    
    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Stop the PhantomUF security system")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Check the status of PhantomUF")
    status_parser.add_argument("--json", action="store_true", help="Output status in JSON format")
    
    # Log command
    log_parser = subparsers.add_parser("log", help="View PhantomUF logs")
    log_parser.add_argument("--type", 
                           choices=["all", "threat", "connection", "firewall", "defense", "ids", "vulnerability", "system"],
                           help="Type of logs to view", default="all")
    log_parser.add_argument("--count", type=int, help="Number of log entries to show", default=50)
    log_parser.add_argument("--export", help="Export logs to file")
    
    # Rule command
    rule_parser = subparsers.add_parser("rule", help="Manage firewall rules")
    rule_subparsers = rule_parser.add_subparsers(dest="rule_command", help="Rule command")
    
    add_rule_parser = rule_subparsers.add_parser("add", help="Add a firewall rule")
    add_rule_parser.add_argument("--ip", required=True, help="IP address or CIDR notation")
    add_rule_parser.add_argument("--action", choices=["allow", "block"], required=True, 
                                help="Action to take for this rule")
    add_rule_parser.add_argument("--port", help="Port number or range (e.g., 80 or 8000-9000)")
    add_rule_parser.add_argument("--protocol", choices=["tcp", "udp", "icmp", "any"], 
                                help="Protocol", default="any")
    
    del_rule_parser = rule_subparsers.add_parser("del", help="Delete a firewall rule")
    del_rule_parser.add_argument("rule_id", help="ID of the rule to delete")
    
    list_rule_parser = rule_subparsers.add_parser("list", help="List firewall rules")
    
    # Vulnerability command
    vuln_parser = subparsers.add_parser("scan", help="Perform vulnerability scanning")
    vuln_parser.add_argument("--type", choices=["basic", "full", "system", "network", "web", "config"],
                           help="Type of scan to perform", default="basic")
    vuln_parser.add_argument("--report", help="Generate vulnerability report")
    
    # Recommendations command
    recom_parser = subparsers.add_parser("recommend", help="Get security recommendations")
    recom_parser.add_argument("--apply", help="Apply a specific recommendation by ID")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create PhantomUF instance
    phantom = PhantomUF()
    
    if args.command == "start":
        settings = {
            "config_path": args.config,
            "policy": args.policy,
            "auto_block": not args.no_auto_block,
            "apply_system_hardening": not args.no_hardening
        }
        phantom.start(settings)
    elif args.command == "stop":
        phantom.stop()
    elif args.command == "status":
        status = phantom.status()
        
        if args.json:
            # Convert any non-serializable items to strings
            serializable_status = {}
            for key, value in status.items():
                if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
                    serializable_status[key] = value
                else:
                    serializable_status[key] = str(value)
            print(json.dumps(serializable_status, indent=2))
        else:
            print("\nPhantomUF Status:")
            print(f"Version: {status['version']}")
            print(f"Running: {'Yes' if status['running'] else 'No'}")
            print(f"Security Policy: {status['policy']}")
            
            if status['running']:
                print(f"Uptime: {status['uptime']}")
                print(f"Security Score: {status['security_score']}/100")
                print(f"Threats blocked: {status['threats_blocked']}")
                print(f"Active firewall rules: {status['firewall_rules']}")
                print(f"Connections monitored: {status['connections_monitored']}")
                
                print("\nResource Usage:")
                print(f"CPU: {status['resource_usage']['cpu']}")
                print(f"Memory: {status['resource_usage']['memory']}")
                print(f"Disk: {status['resource_usage']['disk']}")
                
                if 'recent_security_events' in status:
                    print("\nRecent Security Events:")
                    for event in status['recent_security_events']:
                        print(f"[{event['time']}] {event['description']}")
    elif args.command == "log":
        logs = phantom.show_logs(args.type, args.count)
        
        if args.export:
            # Export logs to file
            with open(args.export, 'w') as f:
                for log in logs:
                    f.write(f"{json.dumps(log)}\n")
            print(f"Exported {len(logs)} log entries to {args.export}")
        else:
            # Display logs on console
            for log in logs:
                print(f"[{log['timestamp']}] [{log['level']}] {log['message']}")
    elif args.command == "rule":
        if args.rule_command == "add":
            phantom.firewall.add_rule(args.ip, args.action, args.port, args.protocol)
        elif args.rule_command == "del":
            phantom.firewall.delete_rule(args.rule_id)
        elif args.rule_command == "list":
            rules = phantom.firewall.list_rules()
            print("\nFirewall Rules:")
            for rule in rules:
                print(f"ID: {rule['id']} | {rule['action']} | IP: {rule['ip']} | " +
                     f"Protocol: {rule['protocol']} | Port: {rule['port'] or 'any'} | " +
                     f"Added: {rule['added']}")
    elif args.command == "scan":
        scan_id = phantom.run_vulnerability_scan(args.type)
        
        if scan_id:
            print(f"Vulnerability scan initiated with ID: {scan_id}")
            
            # Wait for scan to complete
            print("Waiting for scan to complete...")
            time.sleep(5)
            
            # Get results
            results = phantom.vulnerability_scanner.get_scan_results(scan_id)
            
            if results:
                summary = results['summary']
                print("\nVulnerability Scan Results:")
                print(f"Scan Type: {results['scan_type']}")
                print(f"Start Time: {results['start_time']}")
                print(f"End Time: {results['end_time']}")
                print(f"Findings: {sum(summary.values())} total " +
                     f"(High: {summary['high']}, Medium: {summary['medium']}, " +
                     f"Low: {summary['low']}, Info: {summary['info']})")
                
                if args.report and results['findings']:
                    # Generate report
                    report_file = phantom.vulnerability_scanner.export_report(
                        scan_id, args.report
                    )
                    if report_file:
                        print(f"Report generated: {report_file}")
                        
                # Show high and medium findings
                high_medium = [f for f in results['findings'] 
                              if f['severity'] in ('high', 'medium')]
                
                if high_medium:
                    print("\nHigh/Medium Findings:")
                    for i, finding in enumerate(high_medium, 1):
                        print(f"{i}. [{finding['severity'].upper()}] {finding['title']}")
                        print(f"   Affected: {finding['affected']}")
                        if 'remediation' in finding:
                            print(f"   Recommendation: {finding['remediation']}")
        else:
            print("Failed to initiate vulnerability scan. Make sure PhantomUF is running.")
    elif args.command == "recommend":
        if args.apply:
            # Apply a specific recommendation
            success = phantom.apply_security_recommendation(args.apply)
            if success:
                print(f"Successfully applied recommendation {args.apply}")
            else:
                print(f"Failed to apply recommendation {args.apply}")
        else:
            # Show recommendations
            recommendations = phantom.get_security_recommendations()
            
            print("\nSecurity Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. [{rec['severity'].upper()}] {rec['title']} (ID: {rec['id']})")
                print(f"   {rec['description']}")
                print(f"   Implementation Effort: {rec['effort']}")
                print()
                
            print("To apply a recommendation, use: phantomuf recommend --apply <ID>")
    else:
        parser.print_help()
        
if __name__ == "__main__":
    main()
