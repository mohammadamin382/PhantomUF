
"""
Log Manager Module for PhantomUF
Manages and organizes security logs
"""

import os
import time
import json
import logging
import threading
from datetime import datetime
from collections import deque

logger = logging.getLogger("PhantomUF.Logger")

class LogManager:
    """Manages security logs for the PhantomUF system"""
    
    def __init__(self, config):
        self.config = config
        self.log_dir = self.config.get("log_dir", "logs")
        self.max_log_size = self.config.get("max_log_size", 10)  # MB
        self.max_logs = self.config.get("max_logs", 10)  # Number of rotated log files to keep
        
        # In-memory log buffer for quick access
        self.log_buffer = {
            'all': deque(maxlen=1000),
            'threat': deque(maxlen=500),
            'connection': deque(maxlen=500),
            'firewall': deque(maxlen=500),
            'defense': deque(maxlen=500),
            'traffic': deque(maxlen=500),
            'system': deque(maxlen=500)
        }
        
        # Create log directory if it doesn't exist
        self._ensure_log_dir()
        
        # Start log rotation thread
        threading.Thread(target=self._log_maintenance, daemon=True).start()
        
    def _ensure_log_dir(self):
        """Ensure the log directory exists"""
        if not os.path.exists(self.log_dir):
            try:
                os.makedirs(self.log_dir)
                logger.info(f"Created log directory: {self.log_dir}")
            except Exception as e:
                logger.error(f"Failed to create log directory: {e}")
                
    def log_event(self, event_type, message, level="INFO"):
        """Log a security event"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_entry = {
            "timestamp": timestamp,
            "type": event_type,
            "level": level,
            "message": message
        }
        
        # Add to in-memory buffer
        self.log_buffer['all'].append(log_entry)
        if event_type in self.log_buffer:
            self.log_buffer[event_type].append(log_entry)
            
        # Write to log file
        log_file = os.path.join(self.log_dir, f"phantomuf_{event_type}.log")
        
        try:
            with open(log_file, 'a') as f:
                f.write(f"{timestamp} [{level}] {message}\n")
        except Exception as e:
            logger.error(f"Failed to write to log file {log_file}: {e}")
            
        # For high severity events, also write to alerts log
        if level in ["WARNING", "ERROR", "CRITICAL"]:
            alerts_file = os.path.join(self.log_dir, "phantomuf_alerts.log")
            try:
                with open(alerts_file, 'a') as f:
                    f.write(f"{timestamp} [{event_type}] {message}\n")
            except Exception as e:
                logger.error(f"Failed to write to alerts log: {e}")
                
    def get_logs(self, log_type="all", count=50):
        """Get recent logs of the specified type"""
        if log_type not in self.log_buffer:
            return []
            
        # Get logs from buffer
        logs = list(self.log_buffer[log_type])
        
        # Return most recent logs first
        return sorted(logs, key=lambda x: x["timestamp"], reverse=True)[:count]
        
    def export_logs(self, start_time=None, end_time=None, log_types=None):
        """Export logs for the specified time period and types"""
        if not log_types:
            log_types = ['threat', 'connection', 'firewall', 'defense', 'traffic', 'system']
            
        if not start_time:
            # Default to last 24 hours
            start_time = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
            
        if not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        export_data = {
            "export_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "start_time": start_time,
            "end_time": end_time,
            "logs": {}
        }
        
        for log_type in log_types:
            export_data["logs"][log_type] = []
            log_file = os.path.join(self.log_dir, f"phantomuf_{log_type}.log")
            
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            # Parse log line to check timestamp
                            parts = line.strip().split(' ', 2)
                            if len(parts) >= 3:
                                timestamp = parts[0] + ' ' + parts[1]
                                if start_time <= timestamp <= end_time:
                                    export_data["logs"][log_type].append(line.strip())
                except Exception as e:
                    logger.error(f"Failed to read log file {log_file}: {e}")
                    
        # Write export to file
        export_file = os.path.join(
            self.log_dir, 
            f"phantomuf_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        try:
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            return export_file
        except Exception as e:
            logger.error(f"Failed to export logs: {e}")
            return None
            
    def _log_maintenance(self):
        """Perform log maintenance tasks like rotation"""
        logger.info("Log maintenance thread started")
        
        while True:
            try:
                # Check log sizes
                for log_type in ['all', 'threat', 'connection', 'firewall', 'defense', 'traffic', 'system']:
                    log_file = os.path.join(self.log_dir, f"phantomuf_{log_type}.log")
                    
                    if os.path.exists(log_file) and os.path.getsize(log_file) > (self.max_log_size * 1024 * 1024):
                        self._rotate_log(log_file)
                        
                # Clean up old rotated logs
                self._cleanup_old_logs()
                
                # Sleep for an hour
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error in log maintenance: {e}")
                time.sleep(3600)
                
    def _rotate_log(self, log_file):
        """Rotate a log file when it gets too large"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_file = f"{log_file}.{timestamp}"
            
            # Rename current log to rotated name
            os.rename(log_file, rotated_file)
            
            logger.info(f"Rotated log file {log_file} to {rotated_file}")
            
            # Create new empty log file
            with open(log_file, 'w') as f:
                f.write(f"# Log started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
        except Exception as e:
            logger.error(f"Failed to rotate log file {log_file}: {e}")
            
    def _cleanup_old_logs(self):
        """Clean up old rotated log files"""
        try:
            # Get all log files
            all_logs = []
            for filename in os.listdir(self.log_dir):
                if filename.startswith("phantomuf_") and ".log." in filename:
                    filepath = os.path.join(self.log_dir, filename)
                    all_logs.append((filepath, os.path.getmtime(filepath)))
                    
            # Group by log type
            log_groups = {}
            for filepath, mtime in all_logs:
                basename = filepath.split(".log.")[0] + ".log"
                if basename not in log_groups:
                    log_groups[basename] = []
                log_groups[basename].append((filepath, mtime))
                
            # For each group, keep only the most recent ones
            for basename, logs in log_groups.items():
                # Sort by modification time (newest first)
                logs.sort(key=lambda x: x[1], reverse=True)
                
                # Remove old logs beyond the max count
                for filepath, _ in logs[self.max_logs:]:
                    try:
                        os.remove(filepath)
                        logger.info(f"Removed old log file: {filepath}")
                    except Exception as e:
                        logger.error(f"Failed to remove old log file {filepath}: {e}")
                        
        except Exception as e:
            logger.error(f"Error cleaning up old logs: {e}")
