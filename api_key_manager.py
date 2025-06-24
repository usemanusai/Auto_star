#!/usr/bin/env python3
##"
Multi-Account GitHub API Key Management System
Handles storage, validation, and management of multiple GitHub API keys
##"

import json
import os
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from cryptography.fernet import Fernet
import base64
import hashlib

class APIKeyManager:
    """
    Manages multiple GitHub API keys with encryption, validation, and usage tracking
    """
    
    def __init__(self, storage_file: str = "api_keys.json", encryption_key: Optional[str] = None):
        self.storage_file = storage_file
        self.keys_data = {}
        self.encryption_key = encryption_key
        self.cipher_suite = None
        
        # Initialize encryption if key provided
        if encryption_key:
            self._setup_encryption(encryption_key)
        
        # Load existing keys
        self.load_keys()
    
    def _setup_encryption(self, password: str):
        """Setup encryption using password-derived key"""
        # Derive key from password
        password_bytes = password.encode()
        key = base64.urlsafe_b64encode(hashlib.sha256(password_bytes).digest())
        self.cipher_suite = Fernet(key)
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if self.cipher_suite:
            return self.cipher_suite.encrypt(data.encode()).decode()
        return data
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if self.cipher_suite:
            try:
                return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
            except Exception:
                return encrypted_data  # Return as-is if decryption fails
        return encrypted_data
    
    def add_api_key(self, account_name: str, api_key: str, notes: str = "") -> bool:
        """
        Add a new API key with validation
        
        Args:
            account_name: Friendly name for the account
            api_key: GitHub personal access token
            notes: Optional notes about the key
            
        Returns:
            bool: True if key was added successfully
        """
        # Validate the API key first
        validation_result = self.validate_api_key(api_key)
        if not validation_result['valid']:
            raise ValueError(f"Invalid API key: {validation_result['error']}")
        
        # Create key entry
        key_entry = {
            'account_name': account_name,
            'api_key': self._encrypt_data(api_key),
            'notes': notes,
            'date_added': datetime.now().isoformat(),
            'last_used': None,
            'usage_count': 0,
            'success_count': 0,
            'failure_count': 0,
            'rate_limit_remaining': validation_result.get('rate_limit_remaining', 0),
            'rate_limit_reset': validation_result.get('rate_limit_reset', 0),
            'scopes': validation_result.get('scopes', []),
            'username': validation_result.get('username', 'Unknown'),
            'status': 'active'
        }
        
        # Generate unique key ID
        key_id = f"{account_name}_{int(time.time())}"
        self.keys_data[key_id] = key_entry
        
        # Save to storage
        self.save_keys()
        return True