
"""
Machine Learning Threat Detection Module for PhantomUF
Uses advanced ML algorithms to detect zero-day attacks and sophisticated threats
"""

import os
import time
import logging
import threading
import numpy as np
from datetime import datetime
from collections import defaultdict, deque

logger = logging.getLogger("PhantomUF.MLDetection")

class MLThreatDetection:
    """Machine learning-based threat detection for advanced zero-day protection"""
    
    def __init__(self, config, log_manager, defender):
        self.config = config
        self.log_manager = log_manager
        self.defender = defender
        self.running = False
        
        # Model state
        self.model_loaded = False
        self.feature_vectors = defaultdict(list)
        self.anomaly_thresholds = {}
        self.detection_confidence = defaultdict(float)
        
        # Performance metrics
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        
        # Feature extraction settings
        self.time_window = self.config.get("ml_time_window", 300)  # 5 minutes
        self.min_samples = self.config.get("ml_min_samples", 100)
        
    def initialize(self):
        """Initialize the ML detection module"""
        logger.info("Initializing Machine Learning Threat Detection...")
        
        # Initialize models
        self._initialize_models()
        
        logger.info("Machine Learning Threat Detection initialized")
        
    def start(self):
        """Start the ML detection service"""
        if self.running:
            logger.warning("ML Threat Detection is already running")
            return
            
        logger.info("Starting Machine Learning Threat Detection...")
        self.running = True
        
        # Start analysis threads
        threading.Thread(target=self._analyze_network_patterns, daemon=True).start()
        threading.Thread(target=self._anomaly_detection, daemon=True).start()
        threading.Thread(target=self._model_update, daemon=True).start()
        
        logger.info("Machine Learning Threat Detection started successfully")
        
    def stop(self):
        """Stop the ML detection service"""
        if not self.running:
            logger.warning("ML Threat Detection is not running")
            return
            
        logger.info("Stopping Machine Learning Threat Detection...")
        self.running = False
        
        # Save model state
        self._save_model_state()
        
        logger.info("Machine Learning Threat Detection stopped successfully")
        
    def analyze_traffic(self, traffic_data):
        """Analyze traffic data using ML algorithms"""
        if not self.running or not self.model_loaded:
            return
            
        source_ip = traffic_data.get('source_ip', '')
        traffic_type = traffic_data.get('type', '')
        features = self._extract_features(traffic_data)
        
        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly(source_ip, features)
        
        # Update detection confidence
        self.detection_confidence[source_ip] = max(
            0.7 * self.detection_confidence[source_ip] + 0.3 * anomaly_score,
            anomaly_score
        )
        
        # Take action based on confidence
        if self.detection_confidence[source_ip] >= 0.85:
            threat_description = f"ML-detected advanced threat ({traffic_type})"
            self.log_manager.log_event(
                "ml_detection",
                f"High confidence threat from {source_ip}: {self.detection_confidence[source_ip]:.2f} - {threat_description}",
                "CRITICAL"
            )
            
            if self.defender:
                self.defender.block_ip(source_ip, threat_description)
                
        elif self.detection_confidence[source_ip] >= 0.7:
            threat_description = f"ML-detected potential threat ({traffic_type})"
            self.log_manager.log_event(
                "ml_detection",
                f"Medium confidence threat from {source_ip}: {self.detection_confidence[source_ip]:.2f} - {threat_description}",
                "WARNING"
            )
            
            if self.defender:
                self.defender.monitor_ip(source_ip, threat_description, 4)
                
    def get_performance_metrics(self):
        """Get performance metrics of the ML detection system"""
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        
        if total == 0:
            return {
                "accuracy": 0,
                "precision": 0,
                "recall": 0,
                "f1_score": 0,
                "total_samples": 0
            }
            
        accuracy = (self.true_positives + self.true_negatives) / total
        
        precision = 0
        if (self.true_positives + self.false_positives) > 0:
            precision = self.true_positives / (self.true_positives + self.false_positives)
            
        recall = 0
        if (self.true_positives + self.false_negatives) > 0:
            recall = self.true_positives / (self.true_positives + self.false_negatives)
            
        f1_score = 0
        if (precision + recall) > 0:
            f1_score = 2 * (precision * recall) / (precision + recall)
            
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "total_samples": total
        }
        
    def _initialize_models(self):
        """Initialize machine learning models"""
        try:
            # In a production system, this would load actual ML models
            # For prototype, we'll use statistical anomaly detection
            self.model_loaded = True
            
            # Set initial anomaly thresholds
            self.anomaly_thresholds = {
                'connection_rate': 10,
                'bytes_per_second': 1000000,
                'packet_size_variance': 5000,
                'port_entropy': 0.7,
                'protocol_entropy': 0.6,
                'payload_entropy': 0.8
            }
            
            logger.info("ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            
    def _extract_features(self, traffic_data):
        """Extract features from traffic data for ML analysis"""
        features = {
            'connection_rate': 0,
            'bytes_per_second': 0,
            'packet_size_variance': 0,
            'port_entropy': 0,
            'protocol_entropy': 0,
            'payload_entropy': 0,
            'timestamp': datetime.now()
        }
        
        # Extract connection rate
        if 'connections' in traffic_data:
            features['connection_rate'] = len(traffic_data['connections'])
            
        # Extract bytes per second
        if 'bytes' in traffic_data and 'duration' in traffic_data:
            if traffic_data['duration'] > 0:
                features['bytes_per_second'] = traffic_data['bytes'] / traffic_data['duration']
                
        # Extract packet size variance
        if 'packet_sizes' in traffic_data:
            if len(traffic_data['packet_sizes']) > 1:
                features['packet_size_variance'] = np.var(traffic_data['packet_sizes'])
                
        # Calculate entropy measures
        if 'ports' in traffic_data:
            features['port_entropy'] = self._calculate_entropy(traffic_data['ports'])
            
        if 'protocols' in traffic_data:
            features['protocol_entropy'] = self._calculate_entropy(traffic_data['protocols'])
            
        if 'payload' in traffic_data:
            features['payload_entropy'] = self._calculate_byte_entropy(traffic_data['payload'])
            
        return features
        
    def _calculate_entropy(self, values):
        """Calculate Shannon entropy of a list of values"""
        if not values:
            return 0
            
        # Count occurrences
        value_counts = {}
        total = 0
        
        for value in values:
            if value in value_counts:
                value_counts[value] += 1
            else:
                value_counts[value] = 1
            total += 1
            
        # Calculate entropy
        entropy = 0
        for count in value_counts.values():
            probability = count / total
            entropy -= probability * np.log2(probability)
            
        # Normalize entropy (0-1)
        max_entropy = np.log2(len(value_counts))
        if max_entropy > 0:
            entropy /= max_entropy
            
        return entropy
        
    def _calculate_byte_entropy(self, data):
        """Calculate entropy of byte data"""
        if not data:
            return 0
            
        # Count occurrences of each byte
        byte_counts = defaultdict(int)
        total = len(data)
        
        for byte in data:
            byte_counts[byte] += 1
            
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / total
            entropy -= probability * np.log2(probability)
            
        # Normalize entropy (0-1)
        return entropy / 8  # Maximum entropy for a byte is 8 bits
        
    def _calculate_anomaly(self, source_ip, features):
        """Calculate anomaly score based on feature vector"""
        # Add feature vector to history
        self.feature_vectors[source_ip].append(features)
        
        # Keep only recent data
        cutoff_time = datetime.now() - timedelta(seconds=self.time_window)
        self.feature_vectors[source_ip] = [
            f for f in self.feature_vectors[source_ip]
            if f['timestamp'] > cutoff_time
        ]
        
        # Need enough samples for reliable detection
        if len(self.feature_vectors[source_ip]) < self.min_samples:
            return 0.0
            
        # Calculate anomaly score as normalized distance from baseline
        anomaly_scores = []
        
        for feature, threshold in self.anomaly_thresholds.items():
            if feature == 'timestamp':
                continue
                
            # Get current value
            current = features[feature]
            
            # Calculate history stats
            history = [f[feature] for f in self.feature_vectors[source_ip][:-1]]
            mean = np.mean(history)
            std = max(np.std(history), 0.01)  # Avoid division by zero
            
            # Z-score (how many standard deviations from mean)
            z_score = abs(current - mean) / std
            
            # Normalize to 0-1 scale
            normalized_score = min(1.0, z_score / 5.0)
            
            # Weight features differently
            if feature in ('payload_entropy', 'port_entropy'):
                normalized_score *= 1.5
                
            anomaly_scores.append(normalized_score)
            
        # Overall anomaly score
        if anomaly_scores:
            return sum(anomaly_scores) / len(anomaly_scores)
        return 0.0
        
    def _analyze_network_patterns(self):
        """Thread to analyze network patterns"""
        logger.info("ML network pattern analysis thread started")
        
        while self.running:
            try:
                # This would collect and analyze real network data
                # Sleep between analyses
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in ML network pattern analysis: {e}")
                time.sleep(30)
                
    def _anomaly_detection(self):
        """Thread to perform anomaly detection"""
        logger.info("ML anomaly detection thread started")
        
        while self.running:
            try:
                # This would run anomaly detection on collected data
                # Sleep between detections
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in ML anomaly detection: {e}")
                time.sleep(60)
                
    def _model_update(self):
        """Thread to periodically update ML models"""
        logger.info("ML model update thread started")
        
        update_interval = self.config.get("ml_model_update_interval", 3600)  # 1 hour
        
        while self.running:
            try:
                # Wait for the update interval
                for _ in range(update_interval // 10):
                    if not self.running:
                        break
                    time.sleep(10)
                    
                if not self.running:
                    break
                    
                logger.info("Updating ML models")
                
                # This would update models with new training data
                # For prototype, adjust thresholds based on observations
                self._adaptive_threshold_update()
                
                logger.info("ML models updated successfully")
                
            except Exception as e:
                logger.error(f"Error in ML model update: {e}")
                time.sleep(600)  # Retry after 10 minutes
                
    def _adaptive_threshold_update(self):
        """Update detection thresholds adaptively based on observations"""
        # This would adjust thresholds based on false positives/negatives
        # For prototype, make small random adjustments
        for feature in self.anomaly_thresholds:
            # Adjust by small random amount (±5%)
            adjustment = 1.0 + (np.random.random() * 0.1 - 0.05)
            self.anomaly_thresholds[feature] *= adjustment
            
    def _save_model_state(self):
        """Save ML model state"""
        logger.info("Saving ML model state")
        # This would save model weights, thresholds, etc.
