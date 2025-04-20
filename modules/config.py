
"""
Configuration Manager Module for PhantomUF
Manages system configuration settings
"""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("PhantomUF.Config")

class ConfigManager:
    """Manages configuration for the PhantomUF system"""
    
    def __init__(self):
        self.config_file = "phantomuf.conf"
        self.default_config = {
            # General Settings
            "version": "1.0.0",
            "log_dir": "logs",
            "max_log_size": 10,  # MB
            "max_logs": 10,  # Number of rotated log files to keep
            
            # Security Policy Settings
            "policy": "moderate",  # strict, moderate, learning
            "auto_block": True,
            "block_duration": 3600,  # 1 hour in seconds
            
            # Threshold Settings
            "ddos_threshold": 100,  # connections per minute
            "brute_force_threshold": 5,  # failed auth attempts
            "port_scan_threshold": 15,  # ports tried
            "traffic_threshold_kb": 5000,  # KB/s
            
            # IP Whitelist/Blacklist
            "whitelist_ips": ["127.0.0.1"],
            "blacklist_ips": [],
            
            # Service Settings
            "ssh_port": 22,
            "protected_services": ["ssh", "http", "https", "dns"]
        }
        
        self.config = self.default_config.copy()
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    
                # Update config with loaded values
                self.config.update(loaded_config)
                logger.info(f"Loaded configuration from {self.config_file}")
                
            except Exception as e:
                logger.error(f"Failed to load configuration: {e}")
                logger.info("Using default configuration")
        else:
            logger.info(f"Configuration file {self.config_file} not found, using defaults")
            # Save default config
            self.save_config()
            
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Saved configuration to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
            
    def get(self, key, default=None):
        """Get a configuration value by key"""
        return self.config.get(key, default)
        
    def set(self, key, value):
        """Set a configuration value by key"""
        self.config[key] = value
        logger.info(f"Updated configuration: {key} = {value}")
        return self.save_config()
        
    def apply_settings(self, settings):
        """Apply multiple settings at once"""
        updated = False
        
        # Update config with provided settings
        for key, value in settings.items():
            if key in self.config and value is not None:
                self.config[key] = value
                updated = True
                logger.info(f"Updated configuration: {key} = {value}")
                
        # Save if changes were made
        if updated:
            self.save_config()
            
    def export_config(self):
        """Export current configuration to a backup file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"phantomuf_config_{timestamp}.backup"
        
        try:
            with open(backup_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Exported configuration to {backup_file}")
            return backup_file
        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            return None
            
    def import_config(self, filepath):
        """Import configuration from a backup file"""
        if not os.path.exists(filepath):
            logger.error(f"Configuration file {filepath} not found")
            return False
            
        try:
            with open(filepath, 'r') as f:
                imported_config = json.load(f)
                
            # Create a backup of current config before replacing
            self.export_config()
            
            # Update config with imported values
            self.config = imported_config
            self.save_config()
            
            logger.info(f"Imported configuration from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            return False
            
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self.config = self.default_config.copy()
        self.save_config()
        logger.info("Reset configuration to default values")
        return True
