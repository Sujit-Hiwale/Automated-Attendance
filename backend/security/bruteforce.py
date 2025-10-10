import time
import redis
import logging
from datetime import timedelta, datetime
from typing import Tuple, Optional
import os
from dotenv import load_dotenv

load_dotenv()

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Configurable thresholds (can be overridden via environment)
MAX_FAILS = int(os.getenv("MAX_LOGIN_FAILS", 5))
LOCKOUT_BASE_SECONDS = int(os.getenv("LOCKOUT_BASE_SECONDS", 60))  # 1 minute base
MAX_LOCK_SECONDS = int(os.getenv("MAX_LOCK_SECONDS", 24 * 3600))  # max 24 hours
CAPTCHA_THRESHOLD = int(os.getenv("CAPTCHA_THRESHOLD", 3))  # Show CAPTCHA after 3 fails

# Initialize Redis connection
try:
    r = redis.from_url(REDIS_URL, decode_responses=True)
    # Test connection
    r.ping()
except redis.ConnectionError as e:
    logging.error(f"Redis connection failed: {e}")
    r = None

logger = logging.getLogger(__name__)

class BruteForceProtection:
    """
    Redis-backed brute force protection with exponential backoff.
    Provides account-level and IP-level protection against credential stuffing.
    """
    
    def __init__(self, redis_client=None):
        self.redis = redis_client or r
        if not self.redis:
            raise RuntimeError("Redis connection is required for brute force protection")
    
    def incr_failed_attempts(self, admin_id: str) -> int:
        """
        Increment failed login attempts for an admin account.
        Returns the current failure count.
        """
        key = f"admin:fail:{admin_id}"
        fails = self.redis.incr(key)
        # Keep count rolling for 24 hours
        self.redis.expire(key, 24 * 3600)
        
        logger.warning(f"Failed login attempt for admin {admin_id}. Count: {fails}")
        return int(fails)
    
    def incr_ip_attempts(self, ip_address: str) -> int:
        """
        Increment failed login attempts for an IP address.
        Returns the current failure count for this IP.
        """
        key = f"ip:fail:{ip_address}"
        fails = self.redis.incr(key)
        # Keep IP failure count for 1 hour
        self.redis.expire(key, 3600)
        
        logger.warning(f"Failed login attempt from IP {ip_address}. Count: {fails}")
        return int(fails)
    
    def compute_lock_seconds(self, fails: int) -> int:
        """
        Calculate lockout duration using exponential backoff.
        Formula: 2^(fails - MAX_FAILS) * base_seconds (capped at max)
        """
        if fails <= MAX_FAILS:
            return 0
        
        expo = 2 ** (fails - MAX_FAILS)
        lock_duration = min(expo * LOCKOUT_BASE_SECONDS, MAX_LOCK_SECONDS)
        return int(lock_duration)
    
    def lock_account(self, admin_id: str, seconds: int) -> None:
        """
        Lock an admin account for the specified duration.
        """
        lock_key = f"admin:lock:{admin_id}"
        self.redis.set(lock_key, "1", ex=seconds)
        
        logger.error(f"Account {admin_id} locked for {seconds} seconds due to repeated failures")
        
        # Send alert email (implement based on your email service)
        self._send_lockout_alert(admin_id, seconds)
    
    def lock_ip(self, ip_address: str, seconds: int = 3600) -> None:
        """
        Temporarily block an IP address (default 1 hour).
        """
        lock_key = f"ip:lock:{ip_address}"
        self.redis.set(lock_key, "1", ex=seconds)
        
        logger.error(f"IP {ip_address} blocked for {seconds} seconds due to repeated failures")
    
    def is_account_locked(self, admin_id: str) -> Tuple[bool, int]:
        """
        Check if an admin account is locked.
        Returns (is_locked, remaining_seconds)
        """
        lock_key = f"admin:lock:{admin_id}"
        ttl = self.redis.ttl(lock_key)
        return (ttl > 0, ttl if ttl > 0 else 0)
    
    def is_ip_locked(self, ip_address: str) -> Tuple[bool, int]:
        """
        Check if an IP address is blocked.
        Returns (is_blocked, remaining_seconds)
        """
        lock_key = f"ip:lock:{ip_address}"
        ttl = self.redis.ttl(lock_key)
        return (ttl > 0, ttl if ttl > 0 else 0)
    
    def reset_failed_attempts(self, admin_id: str) -> None:
        """
        Reset failed attempt counter for successful login.
        """
        self.redis.delete(f"admin:fail:{admin_id}")
        logger.info(f"Reset failed attempts for admin {admin_id} after successful login")
    
    def get_failed_attempts(self, admin_id: str) -> int:
        """
        Get current failed attempt count for an admin.
        """
        key = f"admin:fail:{admin_id}"
        count = self.redis.get(key)
        return int(count) if count else 0
    
    def should_show_captcha(self, admin_id: str) -> bool:
        """
        Determine if CAPTCHA should be shown based on failure count.
        """
        fails = self.get_failed_attempts(admin_id)
        return fails >= CAPTCHA_THRESHOLD
    
    def record_suspicious_activity(self, admin_id: str, ip_address: str, activity_type: str) -> None:
        """
        Record suspicious login activity for monitoring.
        """
        timestamp = datetime.utcnow().isoformat()
        activity_key = f"suspicious:{admin_id}:{timestamp}"
        
        activity_data = {
            'admin_id': admin_id,
            'ip_address': ip_address,
            'activity_type': activity_type,
            'timestamp': timestamp
        }
        
        # Store for 7 days
        self.redis.hmset(activity_key, activity_data)
        self.redis.expire(activity_key, 7 * 24 * 3600)
        
        logger.warning(f"Suspicious activity recorded: {activity_type} for {admin_id} from {ip_address}")
    
    def _send_lockout_alert(self, admin_id: str, duration: int) -> None:
        """
        Send email alert for account lockout.
        Implement based on your email service (SendGrid, SES, etc.)
        """
        # TODO: Implement email alert
        # This is a placeholder for your email service integration
        logger.info(f"TODO: Send lockout alert email for admin {admin_id} (locked for {duration}s)")
    
    def get_lockout_info(self, admin_id: str) -> dict:
        """
        Get comprehensive lockout information for an admin account.
        """
        is_locked, remaining_time = self.is_account_locked(admin_id)
        failed_count = self.get_failed_attempts(admin_id)
        needs_captcha = self.should_show_captcha(admin_id)
        
        return {
            'is_locked': is_locked,
            'remaining_lock_time': remaining_time,
            'failed_attempts': failed_count,
            'needs_captcha': needs_captcha,
            'max_attempts': MAX_FAILS
        }

# Global instance for easy importing
brute_force_protection = BruteForceProtection() if r else None

# Utility functions for backward compatibility
def incr_failed_attempts(admin_id: str) -> int:
    if not brute_force_protection:
        return 0
    return brute_force_protection.incr_failed_attempts(admin_id)

def compute_lock_seconds(fails: int) -> int:
    if not brute_force_protection:
        return 0
    return brute_force_protection.compute_lock_seconds(fails)

def lock_account(admin_id: str, seconds: int) -> None:
    if brute_force_protection:
        brute_force_protection.lock_account(admin_id, seconds)

def is_locked(admin_id: str) -> Tuple[bool, int]:
    if not brute_force_protection:
        return (False, 0)
    return brute_force_protection.is_account_locked(admin_id)

def reset_failed_attempts(admin_id: str) -> None:
    if brute_force_protection:
        brute_force_protection.reset_failed_attempts(admin_id)