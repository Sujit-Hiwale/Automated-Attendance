"""
Enhanced Rate Limiting and Brute-Force Protection
Implements per-IP and per-user rate limiting with Redis backend and exponential lockout
"""
import time
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict
from functools import wraps
from flask import request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import logging

# Import our enhanced brute force protection
try:
    from .bruteforce import BruteForceProtection
except ImportError:
    BruteForceProtection = None

load_dotenv()
logger = logging.getLogger(__name__)


class RateLimitManager:
    """Enhanced rate limiting and brute-force protection with Redis backend"""
    
    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize rate limit manager
        
        Args:
            redis_url: Redis connection URL (optional, uses in-memory if not provided)
        """
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.failed_attempts: Dict[str, list] = {}  # In-memory fallback
        self.lockouts: Dict[str, datetime] = {}
        
        # Rate limiting configuration
        self.login_rate_limit = os.getenv("LOGIN_RATE_LIMIT", "20 per minute")
        self.registration_rate_limit = os.getenv("REGISTRATION_RATE_LIMIT", "5 per hour")
        self.api_rate_limit = os.getenv("API_RATE_LIMIT", "100 per minute")
        
        # Initialize Redis-backed brute force protection if available
        self.brute_force_protection = None
        if BruteForceProtection:
            try:
                self.brute_force_protection = BruteForceProtection()
                logger.info("Redis-backed brute force protection initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Redis brute force protection: {e}")
        
        # Fallback exponential backoff settings for in-memory mode
        self.max_attempts = int(os.getenv("MAX_LOGIN_FAILS", 5))
        self.lockout_durations = [
            60,      # 1 minute after 5 failures
            300,     # 5 minutes after 10 failures
            900,     # 15 minutes after 15 failures
            3600,    # 1 hour after 20 failures
            86400    # 24 hours after 25+ failures
        ]
    
    def create_limiter(self, app) -> Limiter:
        """
        Create Flask-Limiter instance
        
        Args:
            app: Flask application instance
            
        Returns:
            Configured Limiter instance
        """
        storage_uri = self.redis_url if self.redis_url else "memory://"
        
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            storage_uri=storage_uri,
            default_limits=["200 per day", "50 per hour"],
            headers_enabled=True,
            swallow_errors=True  # Don't crash if Redis is down
        )
        
        return limiter
    
    def record_failed_attempt(self, identifier: str) -> None:
        """
        Record a failed login attempt
        
        Args:
            identifier: User email or IP address
        """
        now = datetime.now()
        
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        # Clean up old attempts (older than 24 hours)
        self.failed_attempts[identifier] = [
            attempt for attempt in self.failed_attempts[identifier]
            if (now - attempt).total_seconds() < 86400
        ]
        
        # Add new attempt
        self.failed_attempts[identifier].append(now)
        
        # Check if lockout is needed
        attempt_count = len(self.failed_attempts[identifier])
        if attempt_count >= self.max_attempts:
            self._apply_lockout(identifier, attempt_count)
    
    def _apply_lockout(self, identifier: str, attempt_count: int) -> None:
        """Apply exponential lockout based on failed attempts"""
        # Calculate lockout duration based on attempt count
        lockout_index = min((attempt_count - self.max_attempts) // 5, len(self.lockout_durations) - 1)
        lockout_seconds = self.lockout_durations[lockout_index]
        
        self.lockouts[identifier] = datetime.now() + timedelta(seconds=lockout_seconds)
    
    def is_locked_out(self, identifier: str) -> tuple[bool, Optional[int]]:
        """
        Check if an identifier is locked out
        
        Args:
            identifier: User email or IP address
            
        Returns:
            Tuple of (is_locked, seconds_remaining)
        """
        if identifier in self.lockouts:
            now = datetime.now()
            lockout_until = self.lockouts[identifier]
            
            if now < lockout_until:
                seconds_remaining = int((lockout_until - now).total_seconds())
                return True, seconds_remaining
            else:
                # Lockout expired, clean up
                del self.lockouts[identifier]
        
        return False, None
    
    def reset_failed_attempts(self, identifier: str) -> None:
        """
        Reset failed attempts after successful login
        
        Args:
            identifier: User email or IP address
        """
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]
        if identifier in self.lockouts:
            del self.lockouts[identifier]
    
    def get_attempt_count(self, identifier: str) -> int:
        """Get the number of recent failed attempts"""
        if identifier not in self.failed_attempts:
            return 0
        
        # Clean up old attempts
        now = datetime.now()
        self.failed_attempts[identifier] = [
            attempt for attempt in self.failed_attempts[identifier]
            if (now - attempt).total_seconds() < 3600  # Last hour
        ]
        
        return len(self.failed_attempts[identifier])
    
    def get_status(self, identifier: str) -> dict:
        """Get the current rate limit status for an identifier"""
        is_locked, seconds_remaining = self.is_locked_out(identifier)
        attempt_count = self.get_attempt_count(identifier)
        
        return {
            'is_locked': is_locked,
            'seconds_remaining': seconds_remaining,
            'recent_attempts': attempt_count,
            'max_attempts': self.max_attempts
        }


def check_rate_limit(rate_limit_manager: RateLimitManager):
    """
    Decorator to check rate limits before processing requests
    
    Args:
        rate_limit_manager: RateLimitManager instance
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get identifier from request (IP address)
            ip_address = get_remote_address()
            
            # Check if IP is locked out
            is_locked, seconds_remaining = rate_limit_manager.is_locked_out(ip_address)
            if is_locked:
                return jsonify({
                    'error': 'Too many failed attempts',
                    'message': f'Account temporarily locked. Try again in {seconds_remaining} seconds.',
                    'locked_until': seconds_remaining
                }), 429
            
            # Check for user identifier in request
            data = request.get_json() or {}
            if 'email' in data:
                user_identifier = data['email'].lower()
                is_locked, seconds_remaining = rate_limit_manager.is_locked_out(user_identifier)
                if is_locked:
                    return jsonify({
                        'error': 'Too many failed attempts',
                        'message': f'Account temporarily locked. Try again in {seconds_remaining} seconds.',
                        'locked_until': seconds_remaining
                    }), 429
            
            return f(*args, **kwargs)
        return wrapped
    return decorator


class SecurityLogger:
    """Logs security events for auditing"""
    
    def __init__(self, log_file: str = 'logs/security.log'):
        """Initialize security logger"""
        self.log_file = log_file
        self._ensure_log_directory()
    
    def _ensure_log_directory(self):
        """Create log directory if it doesn't exist"""
        import os
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    def log_event(self, event_type: str, details: dict) -> None:
        """
        Log a security event
        
        Args:
            event_type: Type of event (login_success, login_failure, etc.)
            details: Dictionary with event details
        """
        timestamp = datetime.now().isoformat()
        ip_address = get_remote_address()
        
        log_entry = {
            'timestamp': timestamp,
            'event_type': event_type,
            'ip_address': ip_address,
            'details': details
        }
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Failed to write to security log: {e}")
    
    def log_failed_login(self, email: str, reason: str) -> None:
        """Log a failed login attempt"""
        self.log_event('login_failure', {
            'email': email,
            'reason': reason
        })
    
    def log_successful_login(self, email: str, user_id: int) -> None:
        """Log a successful login"""
        self.log_event('login_success', {
            'email': email,
            'user_id': user_id
        })
    
    def log_registration(self, email: str, user_id: int) -> None:
        """Log a new user registration"""
        self.log_event('registration', {
            'email': email,
            'user_id': user_id
        })
    
    def log_password_change(self, email: str, user_id: int) -> None:
        """Log a password change"""
        self.log_event('password_change', {
            'email': email,
            'user_id': user_id
        })
    
    def log_lockout(self, identifier: str, attempt_count: int) -> None:
        """Log an account lockout"""
        self.log_event('account_lockout', {
            'identifier': identifier,
            'attempt_count': attempt_count
        })
