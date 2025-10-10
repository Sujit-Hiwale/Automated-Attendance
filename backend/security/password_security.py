"""
Password Security Module
Implements Argon2id hashing, pepper support, password strength validation,
and Have I Been Pwned (HIBP) checking.
"""
import os
import re
import hashlib
import requests
from typing import Tuple, Optional
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHash


class PasswordSecurity:
    """Handles all password security operations"""
    
    def __init__(self, pepper: Optional[str] = None, config: dict = None):
        """
        Initialize password security handler
        
        Args:
            pepper: Optional pepper value for additional security
            config: Configuration dictionary with password policy settings
        """
        self.pepper = pepper or ""
        self.config = config or {}
        
        # Initialize Argon2id hasher with secure parameters
        self.hasher = PasswordHasher(
            time_cost=3,           # Number of iterations
            memory_cost=65536,     # Memory usage in KiB (64 MB)
            parallelism=4,         # Number of parallel threads
            hash_len=32,           # Length of the hash in bytes
            salt_len=16,           # Length of the salt in bytes
            encoding='utf-8',
            type=Type.ID           # Use Argon2id variant
        )
        
        # Password policy configuration
        self.min_length = int(self.config.get('MIN_PASSWORD_LENGTH', 12))
        self.require_uppercase = self.config.get('REQUIRE_UPPERCASE', 'true').lower() == 'true'
        self.require_lowercase = self.config.get('REQUIRE_LOWERCASE', 'true').lower() == 'true'
        self.require_digits = self.config.get('REQUIRE_DIGITS', 'true').lower() == 'true'
        self.require_special = self.config.get('REQUIRE_SPECIAL', 'true').lower() == 'true'
        self.check_hibp = self.config.get('CHECK_HIBP', 'true').lower() == 'true'
    
    def _apply_pepper(self, password: str) -> str:
        """Apply pepper to password before hashing"""
        if self.pepper:
            return password + self.pepper
        return password
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id with optional pepper
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Hashed password string
        """
        peppered = self._apply_pepper(password)
        return self.hasher.hash(peppered)
    
    def verify_password(self, password: str, hash_stored: str) -> Tuple[bool, bool]:
        """
        Verify a password against a stored hash
        
        Args:
            password: Plain text password to verify
            hash_stored: Stored password hash
            
        Returns:
            Tuple of (is_valid, needs_rehash)
        """
        try:
            peppered = self._apply_pepper(password)
            self.hasher.verify(hash_stored, peppered)
            
            # Check if rehashing is needed (parameters changed)
            needs_rehash = self.hasher.check_needs_rehash(hash_stored)
            
            return True, needs_rehash
        except (VerifyMismatchError, InvalidHash):
            return False, False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, list]:
        """
        Validate password against security policy
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check minimum length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        # Check for uppercase letters
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letters
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for digits
        if self.require_digits and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        # Check for special characters
        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;\'`~]', password):
            errors.append("Password must contain at least one special character")
        
        # Check for common patterns
        if self._contains_common_patterns(password):
            errors.append("Password contains common patterns (e.g., '123', 'abc', 'qwerty')")
        
        return len(errors) == 0, errors
    
    def _contains_common_patterns(self, password: str) -> bool:
        """Check for common weak patterns in password"""
        common_patterns = [
            r'123', r'234', r'345', r'456', r'567', r'678', r'789',
            r'abc', r'bcd', r'cde', r'def',
            r'qwerty', r'asdf', r'zxcv',
            r'password', r'admin', r'user', r'root',
        ]
        
        password_lower = password.lower()
        return any(pattern in password_lower for pattern in common_patterns)
    
    def check_pwned_password(self, password: str) -> Tuple[bool, int]:
        """
        Check if password has been compromised using Have I Been Pwned API
        Uses k-anonymity model - only first 5 chars of SHA-1 hash are sent
        
        Args:
            password: Password to check
            
        Returns:
            Tuple of (is_pwned, occurrence_count)
        """
        if not self.check_hibp:
            return False, 0
        
        try:
            # Hash password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HIBP API with first 5 characters
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                # Check if our hash suffix is in the results
                hashes = response.text.split('\r\n')
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)
            
            return False, 0
        except Exception as e:
            # If API is unavailable, log error but don't block registration
            print(f"HIBP API error: {e}")
            return False, 0
    
    def validate_and_check_password(self, password: str) -> Tuple[bool, list]:
        """
        Complete password validation including strength and HIBP check
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        # First check password strength
        is_strong, errors = self.validate_password_strength(password)
        
        if not is_strong:
            return False, errors
        
        # Check if password is pwned
        if self.check_hibp:
            is_pwned, count = self.check_pwned_password(password)
            if is_pwned:
                errors.append(
                    f"This password has been exposed in {count} data breaches. "
                    "Please choose a different password."
                )
                return False, errors
        
        return True, []


# Convenience functions for use throughout the application
def create_password_security(config: dict = None) -> PasswordSecurity:
    """Create a PasswordSecurity instance with environment configuration"""
    pepper = os.getenv('PASSWORD_PEPPER')
    return PasswordSecurity(pepper=pepper, config=config or {})
