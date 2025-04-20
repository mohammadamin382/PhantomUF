
"""
Encryption Module for PhantomUF
Provides encryption utilities for secure communications and data storage
"""

import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger("PhantomUF.Encryption")

class EncryptionManager:
    """Manages encryption for PhantomUF system"""
    
    def __init__(self, config):
        self.config = config
        self.key_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")
        
        # Ensure key directory exists
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir, exist_ok=True)
            
        # Initialize encryption keys
        self.symmetric_key = self._load_or_create_symmetric_key()
        self.rsa_private_key, self.rsa_public_key = self._load_or_create_rsa_keypair()
        
        # Initialize Fernet cipher for symmetric encryption
        self.fernet = Fernet(self.symmetric_key)
        
    def encrypt_data(self, data):
        """Encrypt data using symmetric encryption"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        try:
            encrypted_data = self.fernet.encrypt(data)
            return encrypted_data
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}")
            return None
            
    def decrypt_data(self, encrypted_data):
        """Decrypt data using symmetric encryption"""
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data
        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}")
            return None
            
    def encrypt_with_public_key(self, data, public_key=None):
        """Encrypt data using RSA public key"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if public_key is None:
            public_key = self.rsa_public_key
            
        try:
            ciphertext = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            logger.error(f"Failed to encrypt with public key: {e}")
            return None
            
    def decrypt_with_private_key(self, ciphertext):
        """Decrypt data using RSA private key"""
        try:
            plaintext = self.rsa_private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            logger.error(f"Failed to decrypt with private key: {e}")
            return None
            
    def generate_hash(self, data, salt=None):
        """Generate a secure hash of data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if salt is None:
            salt = os.urandom(16)
            
        try:
            hashed = hashlib.sha256(salt + data).digest()
            return {
                'hash': base64.b64encode(hashed).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Failed to generate hash: {e}")
            return None
            
    def verify_hash(self, data, hash_data):
        """Verify data against a stored hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        try:
            salt = base64.b64decode(hash_data['salt'])
            stored_hash = base64.b64decode(hash_data['hash'])
            
            calculated_hash = hashlib.sha256(salt + data).digest()
            
            return calculated_hash == stored_hash
        except Exception as e:
            logger.error(f"Failed to verify hash: {e}")
            return False
            
    def encrypt_file(self, filepath, encrypted_filepath=None):
        """Encrypt a file"""
        if encrypted_filepath is None:
            encrypted_filepath = filepath + '.enc'
            
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            encrypted_data = self.encrypt_data(data)
            
            with open(encrypted_filepath, 'wb') as f:
                f.write(encrypted_data)
                
            return encrypted_filepath
        except Exception as e:
            logger.error(f"Failed to encrypt file {filepath}: {e}")
            return None
            
    def decrypt_file(self, encrypted_filepath, output_filepath=None):
        """Decrypt a file"""
        if output_filepath is None:
            output_filepath = encrypted_filepath.replace('.enc', '')
            
        try:
            with open(encrypted_filepath, 'rb') as f:
                encrypted_data = f.read()
                
            decrypted_data = self.decrypt_data(encrypted_data)
            
            with open(output_filepath, 'wb') as f:
                f.write(decrypted_data)
                
            return output_filepath
        except Exception as e:
            logger.error(f"Failed to decrypt file {encrypted_filepath}: {e}")
            return None
            
    def rotate_keys(self):
        """Rotate encryption keys"""
        logger.info("Rotating encryption keys")
        
        # Create new symmetric key
        new_symmetric_key = Fernet.generate_key()
        
        # Create new RSA keypair
        new_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        new_public_key = new_private_key.public_key()
        
        # Save new keys
        self._save_symmetric_key(new_symmetric_key)
        self._save_rsa_keypair(new_private_key, new_public_key)
        
        # Update current keys
        self.symmetric_key = new_symmetric_key
        self.fernet = Fernet(self.symmetric_key)
        self.rsa_private_key = new_private_key
        self.rsa_public_key = new_public_key
        
        logger.info("Encryption keys rotated successfully")
        
    def _load_or_create_symmetric_key(self):
        """Load symmetric key or create if it doesn't exist"""
        key_path = os.path.join(self.key_dir, "symmetric.key")
        
        if os.path.exists(key_path):
            try:
                with open(key_path, 'rb') as f:
                    key = f.read()
                logger.info("Loaded existing symmetric key")
                return key
            except Exception as e:
                logger.error(f"Failed to load symmetric key: {e}")
                
        # Create new key if loading failed or file doesn't exist
        key = Fernet.generate_key()
        self._save_symmetric_key(key)
        logger.info("Created new symmetric key")
        return key
        
    def _save_symmetric_key(self, key):
        """Save symmetric key to file"""
        key_path = os.path.join(self.key_dir, "symmetric.key")
        
        try:
            with open(key_path, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(key_path, 0o600)
            return True
        except Exception as e:
            logger.error(f"Failed to save symmetric key: {e}")
            return False
            
    def _load_or_create_rsa_keypair(self):
        """Load RSA keypair or create if it doesn't exist"""
        private_key_path = os.path.join(self.key_dir, "private.key")
        public_key_path = os.path.join(self.key_dir, "public.key")
        
        # Try to load existing keypair
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                # This would load serialized keys
                # For now, just create new ones
                logger.info("RSA keys exist but loading not implemented, creating new ones")
            except Exception as e:
                logger.error(f"Failed to load RSA keypair: {e}")
                
        # Create new keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        public_key = private_key.public_key()
        
        self._save_rsa_keypair(private_key, public_key)
        logger.info("Created new RSA keypair")
        
        return private_key, public_key
        
    def _save_rsa_keypair(self, private_key, public_key):
        """Save RSA keypair to files"""
        private_key_path = os.path.join(self.key_dir, "private.key")
        public_key_path = os.path.join(self.key_dir, "public.key")
        
        try:
            # This would serialize the keys
            # For now, just mock the save
            with open(private_key_path, 'w') as f:
                f.write("MOCK PRIVATE KEY")
            with open(public_key_path, 'w') as f:
                f.write("MOCK PUBLIC KEY")
                
            # Set restrictive permissions for private key
            os.chmod(private_key_path, 0o600)
            
            return True
        except Exception as e:
            logger.error(f"Failed to save RSA keypair: {e}")
            return False
            
    def derive_key_from_password(self, password, salt=None):
        """Derive encryption key from password"""
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        if salt is None:
            salt = os.urandom(16)
            
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            return {
                'key': key,
                'salt': base64.b64encode(salt).decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Failed to derive key from password: {e}")
            return None
