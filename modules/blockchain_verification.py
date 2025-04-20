
"""
Blockchain Verification Module for PhantomUF
Uses blockchain technology for tamper-proof security event logging and verification
"""

import time
import hashlib
import logging
import threading
import json
from datetime import datetime
from collections import deque

logger = logging.getLogger("PhantomUF.Blockchain")

class BlockchainVerification:
    """Implements blockchain-based verification for security events"""
    
    def __init__(self, config, log_manager, encryption):
        self.config = config
        self.log_manager = log_manager
        self.encryption = encryption
        self.running = False
        
        # Blockchain state
        self.blockchain = []
        self.pending_events = deque()
        self.last_block_hash = None
        self.block_interval = self.config.get("blockchain_block_interval", 60)  # 1 minute
        self.difficulty = self.config.get("blockchain_difficulty", 4)  # Number of leading zeros
        
        # Genesis block creation
        self._create_genesis_block()
        
    def initialize(self):
        """Initialize the blockchain verification system"""
        logger.info("Initializing Blockchain Verification...")
        
        # Load existing blockchain if available
        self._load_blockchain()
        
        logger.info("Blockchain Verification initialized")
        
    def start(self):
        """Start the blockchain verification service"""
        if self.running:
            logger.warning("Blockchain Verification is already running")
            return
            
        logger.info("Starting Blockchain Verification...")
        self.running = True
        
        # Start blockchain maintenance thread
        threading.Thread(target=self._blockchain_maintenance, daemon=True).start()
        
        logger.info("Blockchain Verification started successfully")
        
    def stop(self):
        """Stop the blockchain verification service"""
        if not self.running:
            logger.warning("Blockchain Verification is not running")
            return
            
        logger.info("Stopping Blockchain Verification...")
        self.running = False
        
        # Save blockchain state
        self._save_blockchain()
        
        logger.info("Blockchain Verification stopped successfully")
        
    def add_event(self, event_type, event_data):
        """Add a security event to the blockchain"""
        if not self.running:
            return False
            
        # Create event record
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': event_data,
            'hash': self._hash_event(event_type, event_data)
        }
        
        # Add to pending events
        self.pending_events.append(event)
        
        # If we have too many pending events, create a block immediately
        if len(self.pending_events) >= 100:
            threading.Thread(target=self._create_block, daemon=True).start()
            
        return True
        
    def verify_event(self, event_hash):
        """Verify that an event exists in the blockchain (tamper check)"""
        if not self.running:
            return False
            
        # Check pending events first
        for event in self.pending_events:
            if event['hash'] == event_hash:
                return True
                
        # Search through blockchain
        for block in self.blockchain:
            for event in block['events']:
                if event['hash'] == event_hash:
                    return True
                    
        return False
        
    def verify_chain_integrity(self):
        """Verify the integrity of the entire blockchain"""
        if not self.blockchain:
            return True
            
        for i in range(1, len(self.blockchain)):
            current = self.blockchain[i]
            previous = self.blockchain[i-1]
            
            # Verify previous hash reference
            if current['previous_hash'] != previous['hash']:
                logger.error(f"Blockchain integrity error: block {i} has invalid previous_hash")
                return False
                
            # Verify block hash
            calculated_hash = self._calculate_block_hash(current)
            if calculated_hash != current['hash']:
                logger.error(f"Blockchain integrity error: block {i} has invalid hash")
                return False
                
            # Verify proof of work
            if not self._is_valid_proof(calculated_hash):
                logger.error(f"Blockchain integrity error: block {i} has invalid proof of work")
                return False
                
        return True
        
    def get_blockchain_stats(self):
        """Get statistics about the blockchain"""
        if not self.running:
            return {}
            
        return {
            'block_count': len(self.blockchain),
            'pending_events': len(self.pending_events),
            'last_block_time': self.blockchain[-1]['timestamp'] if self.blockchain else None,
            'total_events': sum(len(block['events']) for block in self.blockchain),
            'difficulty': self.difficulty
        }
        
    def _create_genesis_block(self):
        """Create the genesis block if blockchain is empty"""
        if not self.blockchain:
            genesis_block = {
                'index': 0,
                'timestamp': datetime.now().isoformat(),
                'events': [{
                    'timestamp': datetime.now().isoformat(),
                    'type': 'system',
                    'data': 'PhantomUF Blockchain Genesis Block',
                    'hash': self._hash_event('system', 'PhantomUF Blockchain Genesis Block')
                }],
                'previous_hash': '0' * 64,
                'nonce': 0
            }
            
            # Mine the genesis block
            self._mine_block(genesis_block)
            
            # Add to blockchain
            self.blockchain.append(genesis_block)
            self.last_block_hash = genesis_block['hash']
            
            logger.info("Created blockchain genesis block")
            
    def _hash_event(self, event_type, event_data):
        """Create a hash for an event"""
        # Convert event data to string if it's not already
        if not isinstance(event_data, str):
            event_data = str(event_data)
            
        # Create a hash of the event
        event_string = f"{datetime.now().isoformat()}:{event_type}:{event_data}"
        return hashlib.sha256(event_string.encode()).hexdigest()
        
    def _create_block(self):
        """Create a new block with pending events"""
        if not self.pending_events:
            return
            
        # Get events to include in this block
        events = []
        while self.pending_events and len(events) < 100:
            events.append(self.pending_events.popleft())
            
        # Create block
        block = {
            'index': len(self.blockchain),
            'timestamp': datetime.now().isoformat(),
            'events': events,
            'previous_hash': self.last_block_hash,
            'nonce': 0
        }
        
        # Mine the block
        self._mine_block(block)
        
        # Add to blockchain
        self.blockchain.append(block)
        self.last_block_hash = block['hash']
        
        # Log the event
        self.log_manager.log_event(
            "blockchain",
            f"Created new block #{block['index']} with {len(events)} events",
            "INFO"
        )
        
        # Save blockchain periodically
        if block['index'] % 10 == 0:
            self._save_blockchain()
            
    def _mine_block(self, block):
        """Mine a block (proof of work)"""
        # Calculate initial hash
        block_hash = self._calculate_block_hash(block)
        
        # Mine until we find a valid hash
        while not self._is_valid_proof(block_hash):
            block['nonce'] += 1
            block_hash = self._calculate_block_hash(block)
            
        # Set the block hash
        block['hash'] = block_hash
        
    def _calculate_block_hash(self, block):
        """Calculate the hash of a block"""
        # Create a copy without the hash field
        block_copy = block.copy()
        if 'hash' in block_copy:
            del block_copy['hash']
            
        # Convert to JSON string
        block_string = json.dumps(block_copy, sort_keys=True)
        
        # Calculate SHA-256 hash
        return hashlib.sha256(block_string.encode()).hexdigest()
        
    def _is_valid_proof(self, block_hash):
        """Check if a hash satisfies the proof of work requirement"""
        return block_hash.startswith('0' * self.difficulty)
        
    def _blockchain_maintenance(self):
        """Background thread for blockchain maintenance"""
        logger.info("Blockchain maintenance thread started")
        
        last_block_time = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Create a new block at regular intervals
                if current_time - last_block_time >= self.block_interval and self.pending_events:
                    self._create_block()
                    last_block_time = current_time
                    
                # Periodically verify chain integrity
                if int(current_time) % 3600 < 10 and self.blockchain:  # Once per hour
                    if self.verify_chain_integrity():
                        logger.info("Blockchain integrity verified successfully")
                    else:
                        logger.critical("Blockchain integrity verification failed!")
                        
                # Adjust difficulty every 100 blocks
                if len(self.blockchain) % 100 == 0 and len(self.blockchain) > 0:
                    self._adjust_difficulty()
                    
                # Sleep for a bit
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in blockchain maintenance: {e}")
                time.sleep(30)
                
    def _adjust_difficulty(self):
        """Dynamically adjust mining difficulty"""
        # Calculate average block time for the last 10 blocks
        if len(self.blockchain) < 11:
            return
            
        recent_blocks = self.blockchain[-10:]
        timestamps = [datetime.fromisoformat(block['timestamp']) for block in recent_blocks]
        
        # Calculate average time between blocks
        time_diffs = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i-1]).total_seconds()
            time_diffs.append(diff)
            
        avg_time = sum(time_diffs) / len(time_diffs)
        
        # Adjust difficulty based on target block interval
        if avg_time < self.block_interval * 0.75:
            # Blocks are being created too quickly, increase difficulty
            self.difficulty += 1
            logger.info(f"Increased blockchain mining difficulty to {self.difficulty}")
        elif avg_time > self.block_interval * 1.5:
            # Blocks are being created too slowly, decrease difficulty
            self.difficulty = max(1, self.difficulty - 1)
            logger.info(f"Decreased blockchain mining difficulty to {self.difficulty}")
            
    def _load_blockchain(self):
        """Load blockchain from storage"""
        # In a real implementation, this would load from a file or database
        # For prototype, we'll just use the genesis block
        logger.info("Blockchain loaded")
        
    def _save_blockchain(self):
        """Save blockchain to storage"""
        # In a real implementation, this would save to a file or database
        logger.info(f"Saved blockchain with {len(self.blockchain)} blocks")
