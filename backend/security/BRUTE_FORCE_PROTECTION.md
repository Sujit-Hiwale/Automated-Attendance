# Brute Force Protection & Rate Limiting Documentation

This document provides comprehensive information about the enhanced security system implemented for the Automated Attendance application.

## Overview

The security system implements multiple layers of protection:

1. **Account-Level Protection**: Exponential lockout for failed login attempts
2. **IP-Level Protection**: Rate limiting and blocking for suspicious IPs
3. **Password Security**: Argon2 hashing with pepper and breach checking
4. **Progressive CAPTCHA**: Required after multiple failed attempts
5. **Legacy Migration**: Seamless upgrade from old password hashes

## Architecture

### Components

- **`bruteforce.py`**: Redis-backed account and IP protection
- **`rate_limiting.py`**: Flask-Limiter integration with Redis
- **`enhanced_login.py`**: Comprehensive login handler
- **`auth_utils.py`**: Password hashing and breach checking

### Dependencies

```bash
pip install flask-limiter redis argon2-cffi requests python-dotenv
```

## Configuration

### Environment Variables (.env)

```bash
# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Brute Force Protection
MAX_LOGIN_FAILS=5              # Attempts before lockout
LOCKOUT_BASE_SECONDS=60        # Base lockout duration (1 minute)
MAX_LOCK_SECONDS=86400         # Maximum lockout (24 hours)
CAPTCHA_THRESHOLD=3            # Failed attempts before CAPTCHA

# Password Security
PEPPER_SECRET=<base64-secret>   # Password pepper (base64 encoded)
HIBP_USER_AGENT="YourAppName"  # User agent for breach checking
PWNED_THRESHOLD=0              # Max allowed breach count

# Rate Limiting
LOGIN_RATE_LIMIT=20 per minute
REGISTRATION_RATE_LIMIT=5 per hour
API_RATE_LIMIT=100 per minute
```

## Implementation Guide

### 1. Basic Flask App Setup

```python
from flask import Flask
from backend.security.bruteforce import brute_force_protection
from backend.security.rate_limiting import RateLimitManager
from backend.auth.enhanced_login import EnhancedLoginHandler

app = Flask(__name__)

# Initialize rate limiting
rate_limiter = RateLimitManager()
limiter = rate_limiter.create_limiter(app)

# Initialize login handler
login_handler = EnhancedLoginHandler(db_manager, rate_limiter)
```

### 2. Login Endpoint

```python
@app.route('/admin/login', methods=['POST'])
@limiter.limit("20 per minute")  # IP-based rate limit
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    captcha = data.get('captcha_response')
    
    # Use enhanced login handler
    result = login_handler.login_admin(email, password, captcha)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 401
```

### 3. Registration Endpoint

```python
@app.route('/admin/register', methods=['POST'])
@limiter.limit("5 per hour")  # IP-based rate limit
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # Use enhanced registration
    result = login_handler.register_admin(email, password)
    
    if result['success']:
        return jsonify(result), 201
    else:
        return jsonify(result), 400
```

## Security Features

### 1. Account Lockout (Exponential Backoff)

**Thresholds:**
- 5 failed attempts: 1 minute lockout
- 10 failed attempts: 5 minutes lockout  
- 15 failed attempts: 15 minutes lockout
- 20 failed attempts: 1 hour lockout
- 25+ failed attempts: 24 hours lockout

**Implementation:**
```python
fails = brute_force_protection.incr_failed_attempts(admin_id)
lock_duration = brute_force_protection.compute_lock_seconds(fails)
if lock_duration > 0:
    brute_force_protection.lock_account(admin_id, lock_duration)
```

### 2. IP-Based Protection

**Features:**
- Rate limiting per IP address
- Temporary IP blocking after excessive failures
- Whitelist support for internal IPs

**Usage:**
```python
# Check if IP is blocked
ip_locked, remaining = brute_force_protection.is_ip_locked(ip_address)
if ip_locked:
    return {"error": "ip_blocked", "remaining": remaining}

# Block IP after too many failures
brute_force_protection.lock_ip(ip_address, 3600)  # 1 hour
```

### 3. Progressive CAPTCHA

**Trigger:** After 3 failed login attempts
**Implementation:** Frontend shows CAPTCHA, backend validates

```python
if brute_force_protection.should_show_captcha(admin_id):
    return {"error": "captcha_required", "needs_captcha": True}
```

### 4. Password Security

**Features:**
- Argon2 hashing with configurable parameters
- Pepper for additional security
- Have I Been Pwned breach checking
- Legacy hash migration

```python
# Registration with breach check
pwned_count = is_password_pwned(password)
if pwned_count > PWNED_THRESHOLD:
    return {"error": "password_compromised"}

# Secure hashing
password_hash = hash_password(password)
```

## Monitoring & Alerts

### 1. Security Events Logged

- Failed login attempts
- Account lockouts
- IP blocks
- Password migrations
- Suspicious activities

### 2. Alert Triggers

- Account locked due to repeated failures
- High failure rate from single IP
- Password found in breaches during registration
- Legacy password migration completed

### 3. Log Format

```json
{
    "timestamp": "2025-10-10T15:30:00Z",
    "event_type": "account_lockout",
    "admin_id": "12345",
    "ip_address": "192.168.1.100",
    "details": {
        "failed_attempts": 5,
        "lock_duration": 60
    }
}
```

## Redis Data Structure

### Keys Used

```
admin:fail:{admin_id}     # Failed attempt counter
admin:lock:{admin_id}     # Account lockout flag
ip:fail:{ip_address}      # IP failure counter  
ip:lock:{ip_address}      # IP block flag
suspicious:{admin_id}:{timestamp}  # Suspicious activity records
```

### TTL (Time To Live)

- Failed attempts: 24 hours rolling window
- Account locks: Variable (60s to 24h)
- IP blocks: 1 hour default
- Suspicious records: 7 days

## Performance Considerations

### Redis Configuration

```conf
# redis.conf optimizations
maxmemory 100mb
maxmemory-policy allkeys-lru
timeout 300
tcp-keepalive 60
```

### Connection Pooling

```python
import redis.connection
pool = redis.ConnectionPool.from_url(REDIS_URL, max_connections=20)
r = redis.Redis(connection_pool=pool)
```

## Testing

### Unit Tests

```python
def test_account_lockout():
    # Test exponential backoff
    for i in range(5):
        brute_force_protection.incr_failed_attempts("test_admin")
    
    is_locked, remaining = brute_force_protection.is_account_locked("test_admin")
    assert is_locked
    assert remaining > 0

def test_ip_blocking():
    # Test IP rate limiting
    for i in range(20):
        brute_force_protection.incr_ip_attempts("192.168.1.100")
    
    is_blocked, remaining = brute_force_protection.is_ip_locked("192.168.1.100")
    assert is_blocked
```

### Load Testing

```bash
# Test rate limiting with Apache Bench
ab -n 100 -c 10 -H "Content-Type: application/json" \
   -p login_data.json http://localhost:5000/admin/login
```

## Production Deployment

### 1. Redis Setup

```bash
# Install Redis
sudo apt-get install redis-server

# Configure Redis for production
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

### 2. Environment Security

```bash
# Generate secure pepper
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Set environment variables securely
export PEPPER_SECRET="your-secure-pepper-here"
export REDIS_URL="redis://redis.yourdomain.com:6379/0"
```

### 3. Monitoring

```bash
# Redis monitoring
redis-cli monitor

# Check memory usage
redis-cli info memory

# View active keys
redis-cli --scan --pattern "admin:*"
```

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```
   Solution: Check REDIS_URL and Redis server status
   Command: redis-cli ping
   ```

2. **High Memory Usage**
   ```
   Solution: Implement key expiration and cleanup
   Command: redis-cli flushdb (development only)
   ```

3. **False Positives**
   ```
   Solution: Adjust thresholds in .env file
   Monitor: Check logs for legitimate users getting blocked
   ```

### Debug Mode

```python
# Enable detailed logging
import logging
logging.getLogger('backend.security').setLevel(logging.DEBUG)

# Check lockout status
info = brute_force_protection.get_lockout_info(admin_id)
print(f"Lockout info: {info}")
```

## Security Best Practices

1. **Secrets Management**
   - Use environment variables or secure vaults
   - Rotate pepper secrets periodically
   - Monitor access to configuration files

2. **Rate Limiting**
   - Adjust limits based on legitimate usage patterns
   - Consider geographic distribution of users
   - Implement different limits for different user types

3. **Monitoring**
   - Set up alerts for unusual activity
   - Review security logs regularly
   - Monitor Redis performance and memory usage

4. **Updates**
   - Keep dependencies updated
   - Monitor security advisories
   - Test security measures regularly

## License & Support

This security implementation is part of the Automated Attendance System. For support or questions, refer to the main project documentation or contact the development team.