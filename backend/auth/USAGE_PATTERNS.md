# Password Security Usage Patterns

This document outlines the recommended usage patterns for the `auth_utils.py` module in the Automated Attendance System.

## Registration Flow

When a new admin user registers, implement the following security checks:

```python
from backend.auth.auth_utils import hash_password, is_password_pwned

def register_admin(email, password):
    # 1. Check if password has been compromised
    pwned_count = is_password_pwned(password)
    
    # Policy: Reject passwords found in breaches
    # Adjust threshold based on your security policy:
    # - > 0: Reject any password found in breaches (strict)
    # - > 50: Allow passwords with low breach counts (moderate)
    if pwned_count > 0:  # or > 50 for moderate policy
        raise ValueError(f"Password has been found in {pwned_count} data breaches. Please choose a different password.")
    
    # 2. Hash the password securely
    password_hash = hash_password(password)
    
    # 3. Store in database
    save_admin_user(email, password_hash)
    
    return {"status": "success", "message": "Admin registered successfully"}
```

## Login Flow with Legacy Hash Migration

For systems with existing password hashes, implement gradual migration to Argon2:

```python
from backend.auth.auth_utils import verify_password, hash_password

def login_admin(email, attempt_password):
    admin = get_admin_by_email(email)
    if not admin:
        return {"status": "error", "message": "Invalid credentials"}
    
    # Check if using legacy hash format
    if admin.legacy_hash:
        # Attempt legacy verification first
        if verify_legacy_hash(admin.legacy_hash, attempt_password):
            # Migration: Re-hash with Argon2 and update database
            new_hash = hash_password(attempt_password)
            update_admin_password_hash(admin.id, new_hash, clear_legacy=True)
            return {"status": "success", "message": "Login successful (password upgraded)"}
        else:
            return {"status": "error", "message": "Invalid credentials"}
    else:
        # Use modern Argon2 verification
        if verify_password(admin.password_hash, attempt_password):
            return {"status": "success", "message": "Login successful"}
        else:
            return {"status": "error", "message": "Invalid credentials"}
```

## Database Schema Considerations

Your admin_users table should support both legacy and modern hashes during migration:

```sql
CREATE TABLE admin_users (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,        -- Modern Argon2 hash
    legacy_hash TEXT,          -- Old hash format (NULL after migration)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Security Policy Examples

### Strict Policy (Recommended)
```python
PWNED_THRESHOLD = 0  # Reject any password found in breaches
```

### Moderate Policy
```python
PWNED_THRESHOLD = 50  # Allow passwords with low breach counts
```

### Enterprise Policy
```python
PWNED_THRESHOLD = 10  # Balance between security and usability
```

## Implementation Checklist

- [ ] Set proper `PEPPER_SECRET` in environment (base64-encoded random bytes)
- [ ] Configure `HIBP_USER_AGENT` with your application name
- [ ] Implement breach checking in registration flow
- [ ] Set up legacy hash migration for existing users
- [ ] Add proper error handling for network failures (HIBP API)
- [ ] Log security events (failed logins, password migrations, etc.)
- [ ] Consider rate limiting for login attempts

## Error Handling

```python
def safe_password_check(password):
    try:
        return is_password_pwned(password)
    except requests.RequestException:
        # HIBP API unavailable - log warning but don't block registration
        logger.warning("HIBP API unavailable during password check")
        return 0  # Assume password is safe
```

## Logging Security Events

```python
import logging

logger = logging.getLogger(__name__)

def log_security_event(event_type, user_id, details):
    logger.info(f"Security Event: {event_type} | User: {user_id} | Details: {details}")

# Usage examples:
log_security_event("password_migration", admin.id, "Legacy hash upgraded to Argon2")
log_security_event("pwned_password_rejected", None, f"Password found in {count} breaches")
```