
"""
Behavioral Biometrics Module for PhantomUF
Implements advanced user authentication through behavioral patterns analysis
"""

import time
import logging
import threading
import numpy as np
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger("PhantomUF.BehavioralBiometrics")

class BehavioralBiometrics:
    """Uses behavioral biometrics for advanced user authentication"""
    
    def __init__(self, config, log_manager):
        self.config = config
        self.log_manager = log_manager
        self.running = False
        
        # User profiles
        self.user_profiles = {}
        self.temp_profiles = defaultdict(list)
        self.auth_confidence = {}
        
        # Settings
        self.min_samples = self.config.get("biometrics_min_samples", 100)
        self.confidence_threshold = self.config.get("biometrics_confidence_threshold", 0.8)
        self.auth_window = self.config.get("biometrics_auth_window", 300)  # 5 minutes
        
    def initialize(self):
        """Initialize the behavioral biometrics system"""
        logger.info("Initializing Behavioral Biometrics...")
        
        # Load existing user profiles
        self._load_profiles()
        
        logger.info("Behavioral Biometrics initialized")
        
    def start(self):
        """Start the behavioral biometrics service"""
        if self.running:
            logger.warning("Behavioral Biometrics is already running")
            return
            
        logger.info("Starting Behavioral Biometrics...")
        self.running = True
        
        # Start analysis thread
        threading.Thread(target=self._analyze_behaviors, daemon=True).start()
        
        logger.info("Behavioral Biometrics started successfully")
        
    def stop(self):
        """Stop the behavioral biometrics service"""
        if not self.running:
            logger.warning("Behavioral Biometrics is not running")
            return
            
        logger.info("Stopping Behavioral Biometrics...")
        self.running = False
        
        # Save profiles
        self._save_profiles()
        
        logger.info("Behavioral Biometrics stopped successfully")
        
    def add_sample(self, user_id, sample_type, sample_data):
        """Add a behavioral sample for a user"""
        if not self.running:
            return
            
        # Extract features from raw sample data
        features = self._extract_features(sample_type, sample_data)
        
        # Add to temporary profile
        self.temp_profiles[user_id].append({
            'type': sample_type,
            'features': features,
            'timestamp': datetime.now()
        })
        
        # If we have enough samples, update the user profile
        if len(self.temp_profiles[user_id]) >= self.min_samples:
            self._update_user_profile(user_id)
            
    def authenticate(self, user_id, sample_type, sample_data):
        """Authenticate a user based on behavioral biometrics"""
        if not self.running or user_id not in self.user_profiles:
            return False
            
        # Extract features from sample
        features = self._extract_features(sample_type, sample_data)
        
        # Calculate authentication confidence
        confidence = self._calculate_auth_confidence(user_id, sample_type, features)
        
        # Update rolling confidence score
        if user_id in self.auth_confidence:
            self.auth_confidence[user_id] = 0.7 * self.auth_confidence[user_id] + 0.3 * confidence
        else:
            self.auth_confidence[user_id] = confidence
            
        # Log unusual behavior
        if confidence < 0.5 and user_id in self.auth_confidence:
            self.log_manager.log_event(
                "biometrics",
                f"Unusual behavior detected for user {user_id}: confidence {confidence:.2f}",
                "WARNING"
            )
            
        # Authentication successful if confidence is above threshold
        return self.auth_confidence[user_id] >= self.confidence_threshold
        
    def get_confidence(self, user_id):
        """Get the authentication confidence for a user"""
        return self.auth_confidence.get(user_id, 0.0)
        
    def _extract_features(self, sample_type, sample_data):
        """Extract features from a behavioral sample"""
        features = {}
        
        if sample_type == 'keystroke':
            # Keystroke dynamics features
            if 'intervals' in sample_data:
                features['avg_interval'] = np.mean(sample_data['intervals'])
                features['std_interval'] = np.std(sample_data['intervals'])
                
            if 'hold_times' in sample_data:
                features['avg_hold_time'] = np.mean(sample_data['hold_times'])
                features['std_hold_time'] = np.std(sample_data['hold_times'])
                
            if 'flight_times' in sample_data:
                features['avg_flight_time'] = np.mean(sample_data['flight_times'])
                
        elif sample_type == 'mouse':
            # Mouse movement features
            if 'speeds' in sample_data:
                features['avg_speed'] = np.mean(sample_data['speeds'])
                features['max_speed'] = np.max(sample_data['speeds'])
                
            if 'angles' in sample_data:
                features['angle_distribution'] = np.histogram(
                    sample_data['angles'], bins=8, range=(0, 360)
                )[0].tolist()
                
            if 'click_intervals' in sample_data:
                features['avg_click_interval'] = np.mean(sample_data['click_intervals'])
                
        elif sample_type == 'command':
            # Command usage features
            if 'commands' in sample_data:
                # Create frequency distribution of commands
                commands = sample_data['commands']
                unique_commands = set(commands)
                
                cmd_freq = {}
                for cmd in unique_commands:
                    cmd_freq[cmd] = commands.count(cmd) / len(commands)
                    
                features['command_frequencies'] = cmd_freq
                
            if 'timestamps' in sample_data:
                # Calculate time intervals between commands
                timestamps = sorted(sample_data['timestamps'])
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
                if intervals:
                    features['avg_command_interval'] = np.mean(intervals)
                    features['std_command_interval'] = np.std(intervals)
                    
        return features
        
    def _update_user_profile(self, user_id):
        """Update a user's behavioral profile with new samples"""
        # Get temporary profile samples
        temp_samples = self.temp_profiles[user_id]
        
        # Group by sample type
        samples_by_type = defaultdict(list)
        for sample in temp_samples:
            samples_by_type[sample['type']].append(sample)
            
        # Process each sample type
        profile = self.user_profiles.get(user_id, {})
        
        for sample_type, samples in samples_by_type.items():
            # Create or update profile for this sample type
            type_profile = profile.get(sample_type, {'features': {}, 'variance': {}})
            
            # Extract all feature names
            feature_names = set()
            for sample in samples:
                feature_names.update(sample['features'].keys())
                
            # Calculate average and variance for each feature
            for feature in feature_names:
                # Get all values for this feature
                values = []
                for sample in samples:
                    if feature in sample['features']:
                        if isinstance(sample['features'][feature], list):
                            # Skip list features for now (handled separately)
                            continue
                        values.append(sample['features'][feature])
                        
                if values:
                    type_profile['features'][feature] = np.mean(values)
                    type_profile['variance'][feature] = np.var(values)
                    
            # Handle special cases for list features
            for sample in samples:
                for feature, value in sample['features'].items():
                    if isinstance(value, list):
                        # For lists like histograms, we store the average
                        if feature not in type_profile['features']:
                            type_profile['features'][feature] = np.array(value)
                        else:
                            type_profile['features'][feature] = (
                                type_profile['features'][feature] + np.array(value)
                            ) / 2
                            
            # Update the profile
            profile[sample_type] = type_profile
            
        # Update the user profile
        self.user_profiles[user_id] = profile
        
        # Clear temporary samples
        self.temp_profiles[user_id] = []
        
        # Log the update
        self.log_manager.log_event(
            "biometrics",
            f"Updated behavioral profile for user {user_id}",
            "INFO"
        )
        
    def _calculate_auth_confidence(self, user_id, sample_type, features):
        """Calculate authentication confidence for a sample"""
        if user_id not in self.user_profiles or sample_type not in self.user_profiles[user_id]:
            return 0.0
            
        profile = self.user_profiles[user_id][sample_type]
        profile_features = profile['features']
        profile_variance = profile['variance']
        
        # Calculate Mahalanobis distance for numerical features
        distances = []
        
        for feature, value in features.items():
            if feature in profile_features and feature in profile_variance:
                if isinstance(value, list) or isinstance(profile_features[feature], np.ndarray):
                    # For list features, calculate cosine similarity
                    if isinstance(value, list):
                        value = np.array(value)
                    profile_value = profile_features[feature]
                    
                    # Normalize vectors
                    norm_value = np.linalg.norm(value)
                    norm_profile = np.linalg.norm(profile_value)
                    
                    if norm_value > 0 and norm_profile > 0:
                        similarity = np.dot(value, profile_value) / (norm_value * norm_profile)
                        # Convert similarity (1 is perfect) to distance (0 is perfect)
                        distances.append(1.0 - similarity)
                else:
                    # For numerical features, calculate Mahalanobis-like distance
                    mean = profile_features[feature]
                    variance = max(profile_variance[feature], 1e-10)  # Prevent division by zero
                    distance = abs(value - mean) / np.sqrt(variance)
                    distances.append(min(distance, 5.0))  # Cap at 5 standard deviations
                    
        if not distances:
            return 0.0
            
        # Calculate confidence from average distance
        avg_distance = sum(distances) / len(distances)
        confidence = max(0.0, 1.0 - (avg_distance / 5.0))
        
        return confidence
        
    def _analyze_behaviors(self):
        """Background thread to analyze user behaviors"""
        logger.info("Behavioral analysis thread started")
        
        while self.running:
            try:
                # Periodically analyze all users' behavior
                for user_id in list(self.auth_confidence.keys()):
                    # Check for sudden behavioral changes
                    if user_id in self.user_profiles and self.auth_confidence[user_id] < 0.6:
                        self.log_manager.log_event(
                            "biometrics",
                            f"Possible account compromise for user {user_id}: confidence {self.auth_confidence[user_id]:.2f}",
                            "WARNING"
                        )
                        
                # Sleep for a while
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in behavioral analysis: {e}")
                time.sleep(60)
                
    def _load_profiles(self):
        """Load user behavioral profiles"""
        # In a real implementation, this would load from a secure database
        # For prototype, we'll use empty profiles
        self.user_profiles = {}
        logger.info("Loaded user behavioral profiles")
        
    def _save_profiles(self):
        """Save user behavioral profiles"""
        # In a real implementation, this would save to a secure database
        logger.info(f"Saved {len(self.user_profiles)} user behavioral profiles")
