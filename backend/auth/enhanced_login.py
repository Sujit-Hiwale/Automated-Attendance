"""
Enhanced Login Handler with Brute Force Protection and Rate Limiting

Integrates all security measures:
- Account-level lockout with exponential backoff
- IP-based rate limiting
- Progressive CAPTCHA
- Password breach checking
- Legacy hash migration
"""

import os
import logging
from datetime import datetime
from flask import request, jsonify, session
from functools import wraps

# Import our security modules
from backend.auth.auth_utils import verify_password, hash_password, is_password_pwned
from backend.security.bruteforce import brute_force_protection
from backend.security.rate_limiting import RateLimitManager

logger = logging.getLogger(__name__)

class EnhancedLoginHandler:
    """
    Comprehensive login handler with all security measures integrated.
    """
    
    def __init__(self, db_manager, rate_limit_manager=None):
        """
        Initialize the login handler.
        
        Args:
            db_manager: Database manager instance
            rate_limit_manager: Optional rate limiting manager
        """
        self.db = db_manager
        self.rate_limiter = rate_limit_manager or RateLimitManager()
        self.brute_force = brute_force_protection
    
    def register_admin(self, email: str, password: str, **kwargs) -> dict:
        """
        Register a new admin with comprehensive security checks.
        
        Args:
            email: Admin email address
            password: Plain text password
            **kwargs: Additional admin data
            
        Returns:
            Dict with registration result
        """
        try:
            # 1. Check password against breach database
            if self.brute_force:
                pwned_count = is_password_pwned(password)
                threshold = int(os.getenv("PWNED_THRESHOLD", 0))
                
                if pwned_count > threshold:
                    logger.warning(f"Registration blocked: password found in {pwned_count} breaches")
                    return {
                        'success': False,
                        'error': 'password_compromised',
                        'message': f'This password has been found in {pwned_count} data breaches. Please choose a different password.',
                        'breach_count': pwned_count
                    }
            
            # 2. Hash the password securely
            password_hash = hash_password(password)
            
            # 3. Create admin user in database
            admin_data = {
                'email': email.lower().strip(),
                'password_hash': password_hash,
                'created_at': datetime.utcnow(),
                **kwargs
            }
            
            admin_id = self.db.create_admin_user(admin_data)
            
            logger.info(f"New admin registered: {email}")
            return {
                'success': True,
                'admin_id': admin_id,
                'message': 'Admin registered successfully'
            }
            
        except Exception as e:
            logger.error(f"Registration error for {email}: {str(e)}")
            return {
                'success': False,
                'error': 'registration_failed',
                'message': 'Registration failed. Please try again.'
            }
    
    def login_admin(self, email: str, password: str, captcha_response: str = None) -> dict:
        """
        Comprehensive admin login with all security measures.
        
        Args:
            email: Admin email
            password: Plain text password
            captcha_response: CAPTCHA response (if required)
            
        Returns:
            Dict with login result and security info
        """
        email = email.lower().strip()
        ip_address = request.remote_addr
        
        try:
            # 1. Check IP-based rate limiting first
            if self.brute_force:
                ip_locked, ip_remaining = self.brute_force.is_ip_locked(ip_address)
                if ip_locked:
                    logger.warning(f"Login blocked: IP {ip_address} is locked for {ip_remaining}s")
                    return {
                        'success': False,
                        'error': 'ip_locked',
                        'message': f'Too many requests from this IP. Try again in {ip_remaining} seconds.',
                        'remaining_time': ip_remaining
                    }
            
            # 2. Get admin from database
            admin = self.db.get_admin_by_email(email)
            if not admin:
                # Record failed attempt for non-existent email
                if self.brute_force:
                    self.brute_force.incr_ip_attempts(ip_address)
                
                logger.warning(f"Login attempt for non-existent admin: {email}")
                return {
                    'success': False,
                    'error': 'invalid_credentials',
                    'message': 'Invalid email or password'
                }
            
            admin_id = str(admin['id'])
            
            # 3. Check account-level lockout
            if self.brute_force:
                account_locked, lock_remaining = self.brute_force.is_account_locked(admin_id)
                if account_locked:
                    logger.warning(f"Login blocked: Account {admin_id} locked for {lock_remaining}s")
                    return {
                        'success': False,
                        'error': 'account_locked',
                        'message': f'Account temporarily locked. Try again in {lock_remaining} seconds.',
                        'remaining_time': lock_remaining,
                        'lockout_info': self.brute_force.get_lockout_info(admin_id)
                    }
            
            # 4. Check if CAPTCHA is required
            needs_captcha = False
            if self.brute_force:
                needs_captcha = self.brute_force.should_show_captcha(admin_id)
                
                if needs_captcha and not captcha_response:
                    return {
                        'success': False,
                        'error': 'captcha_required',
                        'message': 'CAPTCHA verification required due to multiple failed attempts',
                        'needs_captcha': True
                    }
                
                # TODO: Validate CAPTCHA response here
                # if needs_captcha and not self._validate_captcha(captcha_response):
                #     return {
                #         'success': False,
                #         'error': 'captcha_invalid',
                #         'message': 'Invalid CAPTCHA. Please try again.',
                #         'needs_captcha': True
                #     }
            
            # 5. Verify password (with legacy migration support)
            password_valid = False
            
            if admin.get('legacy_hash'):
                # Try legacy verification first
                if self._verify_legacy_password(admin['legacy_hash'], password):
                    # Migrate to Argon2
                    new_hash = hash_password(password)
                    self.db.update_admin_password(admin['id'], new_hash, clear_legacy=True)
                    password_valid = True
                    logger.info(f"Password migrated to Argon2 for admin {admin_id}")
            else:
                # Use modern Argon2 verification
                password_valid = verify_password(admin['password_hash'], password)
            
            # 6. Handle login result
            if password_valid:
                # Successful login - reset counters
                if self.brute_force:
                    self.brute_force.reset_failed_attempts(admin_id)
                
                # Create session
                session['admin_id'] = admin['id']
                session['admin_email'] = admin['email']
                session['login_time'] = datetime.utcnow().isoformat()
                session['ip_address'] = ip_address
                
                logger.info(f"Successful login for admin {admin_id}")
                return {
                    'success': True,
                    'admin_id': admin['id'],
                    'email': admin['email'],
                    'message': 'Login successful'
                }
            else:
                # Failed login - increment counters and check for lockout
                return self._handle_failed_login(admin_id, email, ip_address)
                
        except Exception as e:
            logger.error(f"Login error for {email}: {str(e)}")
            return {
                'success': False,
                'error': 'login_error',
                'message': 'Login failed. Please try again.'
            }
    
    def _handle_failed_login(self, admin_id: str, email: str, ip_address: str) -> dict:
        """
        Handle failed login attempt with comprehensive tracking.
        """
        if self.brute_force:
            # Increment failed attempts for both account and IP
            account_fails = self.brute_force.incr_failed_attempts(admin_id)
            ip_fails = self.brute_force.incr_ip_attempts(ip_address)
            
            # Check if account should be locked
            lock_duration = self.brute_force.compute_lock_seconds(account_fails)
            if lock_duration > 0:
                self.brute_force.lock_account(admin_id, lock_duration)
                
                # Send alert email for account lockout
                self._send_lockout_alert(admin_id, email, lock_duration)
            
            # Check if IP should be blocked (more aggressive for IPs)
            if ip_fails >= 20:  # Block IP after 20 failures
                self.brute_force.lock_ip(ip_address, 3600)  # 1 hour IP block
            
            # Record suspicious activity
            self.brute_force.record_suspicious_activity(
                admin_id, ip_address, 'failed_login_attempt'
            )
            
            # Get current status for response
            lockout_info = self.brute_force.get_lockout_info(admin_id)
        else:
            lockout_info = {'failed_attempts': 0, 'needs_captcha': False}
        
        logger.warning(f"Failed login for admin {admin_id} from IP {ip_address}")
        
        return {
            'success': False,
            'error': 'invalid_credentials',
            'message': 'Invalid email or password',
            'lockout_info': lockout_info
        }
    
    def _verify_legacy_password(self, legacy_hash: str, password: str) -> bool:
        """
        Verify password against legacy hash format.
        Implement based on your existing hash format.
        """
        # TODO: Implement based on your legacy hash format
        # Examples:
        # - MD5: return hashlib.md5(password.encode()).hexdigest() == legacy_hash
        # - bcrypt: return bcrypt.checkpw(password.encode(), legacy_hash.encode())
        # - SHA256: return hashlib.sha256(password.encode()).hexdigest() == legacy_hash
        
        logger.warning("Legacy password verification not implemented")
        return False
    
    def _send_lockout_alert(self, admin_id: str, email: str, duration: int) -> None:
        """
        Send email alert for account lockout.
        """
        # TODO: Implement email service integration
        logger.info(f"TODO: Send lockout alert for {email} (locked for {duration}s)")
    
    def logout_admin(self) -> dict:
        """
        Logout admin and clear session.
        """
        admin_id = session.get('admin_id')
        if admin_id:
            logger.info(f"Admin {admin_id} logged out")
        
        session.clear()
        return {
            'success': True,
            'message': 'Logged out successfully'
        }
    
    def check_session(self) -> dict:
        """
        Check if current session is valid.
        """
        admin_id = session.get('admin_id')
        if not admin_id:
            return {
                'authenticated': False,
                'message': 'Not authenticated'
            }
        
        # Check if account is currently locked
        if self.brute_force:
            account_locked, _ = self.brute_force.is_account_locked(str(admin_id))
            if account_locked:
                session.clear()
                return {
                    'authenticated': False,
                    'message': 'Account is locked'
                }
        
        return {
            'authenticated': True,
            'admin_id': admin_id,
            'email': session.get('admin_email')
        }

# Decorator for routes requiring authentication
def require_auth(f):
    """
    Decorator to require admin authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({
                'error': 'authentication_required',
                'message': 'Please log in to access this resource'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

# Decorator for brute force protection
def brute_force_protection(login_handler):
    """
    Decorator to add brute force protection to login routes.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            
            # Check IP lockout first
            if login_handler.brute_force:
                ip_locked, remaining = login_handler.brute_force.is_ip_locked(ip_address)
                if ip_locked:
                    return jsonify({
                        'error': 'ip_locked',
                        'message': f'Too many requests. Try again in {remaining} seconds.',
                        'remaining_time': remaining
                    }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator