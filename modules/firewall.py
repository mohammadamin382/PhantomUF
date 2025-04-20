
"""
Firewall Manager Module for PhantomUF
Manages firewall rules and interfaces with iptables
"""

import os
import re
import time
import logging
import subprocess
from datetime import datetime

logger = logging.getLogger("PhantomUF.Firewall")

class FirewallManager:
    """Manages Linux firewall rules using iptables"""
    
    def __init__(self, config, log_manager):
        self.config = config
        self.log_manager = log_manager
        self.active_rules = []
        self.rule_counter = 0
        self.running = False
        
    def initialize(self):
        """Initialize the firewall component"""
        logger.info("Initializing Firewall Manager...")
        self._check_iptables()
        self._backup_existing_rules()
        
    def _check_iptables(self):
        """Check if iptables is installed and available"""
        try:
            subprocess.run(["iptables", "--version"], 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE, 
                          check=True)
            logger.info("iptables is available")
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("iptables is not available! PhantomUF requires iptables.")
            raise RuntimeError("iptables is required for PhantomUF")
            
    def _backup_existing_rules(self):
        """Backup existing iptables rules"""
        backup_file = f"iptables_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rules"
        try:
            with open(backup_file, 'w') as f:
                subprocess.run(["iptables-save"], stdout=f, check=True)
            logger.info(f"Existing firewall rules backed up to {backup_file}")
        except Exception as e:
            logger.warning(f"Failed to backup existing firewall rules: {e}")
    
    def start(self):
        """Start the firewall management service"""
        if self.running:
            logger.warning("Firewall Manager is already running")
            return
            
        logger.info("Starting Firewall Manager...")
        
        # Set up PhantomUF chains
        self._setup_chains()
        
        # Apply default rules
        self._apply_default_rules()
        
        self.running = True
        logger.info("Firewall Manager started successfully")
        
    def stop(self):
        """Stop the firewall management service"""
        if not self.running:
            logger.warning("Firewall Manager is not running")
            return
            
        logger.info("Stopping Firewall Manager...")
        
        # Clean up PhantomUF chains
        self._cleanup_chains()
        
        self.running = False
        logger.info("Firewall Manager stopped successfully")
        
    def _setup_chains(self):
        """Set up custom iptables chains for PhantomUF"""
        chains = ["PHANTOM_INPUT", "PHANTOM_FORWARD", "PHANTOM_OUTPUT", "PHANTOM_BLACKLIST"]
        
        # Create chains if they don't exist
        for chain in chains:
            try:
                subprocess.run(["iptables", "-N", chain], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
            except subprocess.SubprocessError:
                # Chain may already exist, flush it
                subprocess.run(["iptables", "-F", chain], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
                
        # Add jumps to our chains from the built-in chains
        subprocess.run(["iptables", "-A", "INPUT", "-j", "PHANTOM_INPUT"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["iptables", "-A", "FORWARD", "-j", "PHANTOM_FORWARD"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["iptables", "-A", "OUTPUT", "-j", "PHANTOM_OUTPUT"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Setup blacklist chain to be checked first
        subprocess.run(["iptables", "-I", "PHANTOM_INPUT", "1", "-j", "PHANTOM_BLACKLIST"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                      
        logger.info("PhantomUF iptables chains created and configured")
        
    def _cleanup_chains(self):
        """Clean up custom iptables chains when shutting down"""
        chains = ["PHANTOM_INPUT", "PHANTOM_FORWARD", "PHANTOM_OUTPUT", "PHANTOM_BLACKLIST"]
        
        # Remove jumps to our chains
        subprocess.run(["iptables", "-D", "INPUT", "-j", "PHANTOM_INPUT"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["iptables", "-D", "FORWARD", "-j", "PHANTOM_FORWARD"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "PHANTOM_OUTPUT"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Flush and delete chains
        for chain in chains:
            subprocess.run(["iptables", "-F", chain], 
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["iptables", "-X", chain], 
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                          
        logger.info("PhantomUF iptables chains removed")
        
    def _apply_default_rules(self):
        """Apply default security rules based on configuration"""
        policy = self.config.get("policy", "moderate")
        
        # Allow established connections
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-m", "conntrack", 
            "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Allow loopback
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-i", "lo", "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Set default rules based on policy
        if policy == "strict":
            # Block all incoming by default, only allow specific services
            self._apply_strict_rules()
        elif policy == "moderate":
            # Allow common services, block known dangerous ports
            self._apply_moderate_rules()
        elif policy == "learning":
            # Allow most traffic but monitor and learn
            self._apply_learning_rules()
            
        logger.info(f"Applied default firewall rules with {policy} policy")
        
    def _apply_strict_rules(self):
        """Apply strict security rules"""
        # Allow SSH (can be customized in config)
        ssh_port = self.config.get("ssh_port", 22)
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-p", "tcp", 
            "--dport", str(ssh_port), "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Allow HTTP/HTTPS
        for port in [80, 443]:
            subprocess.run([
                "iptables", "-A", "PHANTOM_INPUT", "-p", "tcp", 
                "--dport", str(port), "-j", "ACCEPT"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
        # Drop all other incoming traffic
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-j", "DROP"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
    def _apply_moderate_rules(self):
        """Apply moderate security rules"""
        # Allow SSH
        ssh_port = self.config.get("ssh_port", 22)
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-p", "tcp", 
            "--dport", str(ssh_port), "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Allow HTTP/HTTPS
        for port in [80, 443]:
            subprocess.run([
                "iptables", "-A", "PHANTOM_INPUT", "-p", "tcp", 
                "--dport", str(port), "-j", "ACCEPT"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
        # Allow DNS
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-p", "udp", 
            "--dport", "53", "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Allow ping (ICMP echo)
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-p", "icmp", 
            "--icmp-type", "echo-request", "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Drop invalid packets
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-m", "conntrack", 
            "--ctstate", "INVALID", "-j", "DROP"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Drop suspicious scans
        for port in [23, 445, 135, 137, 138, 139, 1433, 3306, 3389]:
            subprocess.run([
                "iptables", "-A", "PHANTOM_INPUT", "-p", "tcp", 
                "--dport", str(port), "-j", "DROP"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
        # Default to accept other traffic
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
    def _apply_learning_rules(self):
        """Apply learning mode rules (permissive but monitored)"""
        # Just log everything but don't block
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-j", "ACCEPT"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Add logging rule before acceptance
        subprocess.run([
            "iptables", "-A", "PHANTOM_INPUT", "-m", "limit", 
            "--limit", "5/min", "-j", "LOG", "--log-prefix", "PhantomUF-Learning: "
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
    def add_rule(self, ip, action, port=None, protocol="any"):
        """Add a custom firewall rule"""
        rule_id = self._generate_rule_id()
        chain = "PHANTOM_BLACKLIST" if action == "block" else "PHANTOM_INPUT"
        
        cmd = ["iptables", "-A", chain, "-s", ip]
        
        if protocol != "any":
            cmd.extend(["-p", protocol])
            
        if port:
            if "-" in str(port):  # Port range
                start_port, end_port = port.split("-")
                cmd.extend(["--match", "multiport", "--dports", f"{start_port}:{end_port}"])
            else:
                cmd.extend(["--dport", str(port)])
                
        target = "DROP" if action == "block" else "ACCEPT"
        cmd.extend(["-j", target])
        
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
            rule = {
                "id": rule_id,
                "ip": ip,
                "action": action,
                "port": port,
                "protocol": protocol,
                "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.active_rules.append(rule)
            
            self.log_manager.log_event(
                "firewall", 
                f"Added {action} rule for {ip} ({protocol}/{port})", 
                "INFO"
            )
            
            logger.info(f"Added firewall rule: {action} {ip} {protocol} {port}")
            return rule_id
            
        except subprocess.SubprocessError as e:
            error_msg = f"Failed to add firewall rule: {e}"
            logger.error(error_msg)
            self.log_manager.log_event("firewall", error_msg, "ERROR")
            return None
            
    def delete_rule(self, rule_id):
        """Delete a firewall rule by ID"""
        for i, rule in enumerate(self.active_rules):
            if rule["id"] == rule_id:
                chain = "PHANTOM_BLACKLIST" if rule["action"] == "block" else "PHANTOM_INPUT"
                
                cmd = ["iptables", "-D", chain, "-s", rule["ip"]]
                
                if rule["protocol"] != "any":
                    cmd.extend(["-p", rule["protocol"]])
                    
                if rule["port"]:
                    if "-" in str(rule["port"]):  # Port range
                        start_port, end_port = rule["port"].split("-")
                        cmd.extend(["--match", "multiport", "--dports", f"{start_port}:{end_port}"])
                    else:
                        cmd.extend(["--dport", str(rule["port"])])
                        
                target = "DROP" if rule["action"] == "block" else "ACCEPT"
                cmd.extend(["-j", target])
                
                try:
                    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                    
                    self.log_manager.log_event(
                        "firewall", 
                        f"Deleted {rule['action']} rule for {rule['ip']}", 
                        "INFO"
                    )
                    
                    del self.active_rules[i]
                    logger.info(f"Deleted firewall rule: {rule_id}")
                    return True
                    
                except subprocess.SubprocessError as e:
                    error_msg = f"Failed to delete firewall rule {rule_id}: {e}"
                    logger.error(error_msg)
                    self.log_manager.log_event("firewall", error_msg, "ERROR")
                    return False
                    
        logger.warning(f"No rule found with ID {rule_id}")
        return False
        
    def list_rules(self):
        """List all active firewall rules"""
        return self.active_rules
        
    def get_rule_count(self):
        """Get the count of active firewall rules"""
        return len(self.active_rules)
        
    def block_ip(self, ip, reason, duration=None):
        """Block an IP address due to malicious activity"""
        # Check if IP is already blocked
        for rule in self.active_rules:
            if rule["ip"] == ip and rule["action"] == "block":
                logger.info(f"IP {ip} is already blocked")
                return rule["id"]
                
        rule_id = self.add_rule(ip, "block")
        
        if rule_id:
            self.log_manager.log_event(
                "threat", 
                f"Blocked IP {ip} for {reason}", 
                "WARNING"
            )
            
            # If temporary block, schedule unblock
            if duration:
                def unblock_later():
                    time.sleep(duration)
                    self.delete_rule(rule_id)
                    logger.info(f"Temporary block of {ip} expired after {duration} seconds")
                    
                threading.Thread(target=unblock_later, daemon=True).start()
                
        return rule_id
        
    def _generate_rule_id(self):
        """Generate a unique rule ID"""
        self.rule_counter += 1
        return f"rule_{datetime.now().strftime('%Y%m%d%H%M%S')}_{self.rule_counter}"
