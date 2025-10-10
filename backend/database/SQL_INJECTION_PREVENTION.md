# SQL Injection Prevention & Database Security Documentation

This document provides comprehensive guidance on preventing SQL injection attacks and implementing secure database access patterns in the Automated Attendance System.

## Table of Contents

1. [SQL Injection Prevention](#sql-injection-prevention)
2. [Database Access Patterns](#database-access-patterns)
3. [Security Configuration](#security-configuration)
4. [Encrypted Backups](#encrypted-backups)
5. [Audit & Monitoring](#audit--monitoring)
6. [Production Deployment](#production-deployment)

## SQL Injection Prevention

### Core Principles

1. **NEVER concatenate user input into SQL strings**
2. **ALWAYS use parameterized queries or ORM**
3. **Validate and sanitize ALL input**
4. **Apply principle of least privilege**
5. **Use prepared statements for raw SQL**

### SQLAlchemy ORM (Recommended)

The secure approach using SQLAlchemy ORM:

```python
from backend.database.secure_db_manager import SecureDatabaseManager

# Initialize secure database manager
db = SecureDatabaseManager()

# Safe ORM query - automatically parameterized
def get_admin_by_email(email: str):
    with db.get_session() as session:
        admin = session.query(AdminUser).filter(
            AdminUser.email == email  # Safe - uses parameters
        ).first()
        return admin

# Safe ORM update
def update_admin_status(admin_id: str, is_active: bool):
    with db.get_session() as session:
        admin = session.query(AdminUser).filter(
            AdminUser.id == admin_id
        ).first()
        
        if admin:
            admin.is_active = is_active
            # Automatically commits due to context manager
```

### Parameterized Raw SQL (When ORM Isn't Sufficient)

```python
# Safe raw SQL with named parameters
def get_attendance_stats(class_name: str, start_date: datetime):
    query = """
    SELECT 
        COUNT(*) as total_records,
        COUNT(CASE WHEN status = 'present' THEN 1 END) as present_count
    FROM attendance_records ar
    JOIN students s ON ar.student_id = s.id
    WHERE s.class_name = :class_name 
      AND ar.attendance_date >= :start_date
    """
    
    params = {
        'class_name': class_name,
        'start_date': start_date
    }
    
    return db.execute_raw_query(query, params)
```

### ❌ DANGEROUS Anti-Patterns (NEVER DO THIS)

```python
# INSECURE - String concatenation/formatting
def bad_login_check(email, password):
    # VULNERABLE TO SQL INJECTION!
    query = f"SELECT * FROM admin_users WHERE email = '{email}'"
    query = "SELECT * FROM admin_users WHERE email = '%s'" % email
    query = "SELECT * FROM admin_users WHERE email = " + email

# INSECURE - Using format() or f-strings with user input
def bad_search(search_term):
    # VULNERABLE!
    query = "SELECT * FROM students WHERE name LIKE '%{}%'".format(search_term)
    query = f"SELECT * FROM students WHERE name LIKE '%{search_term}%'"
```

## Database Access Patterns

### Secure Model Validation

```python
# Input validation using Marshmallow schemas
from marshmallow import Schema, fields, ValidationError

class StudentCreateSchema(Schema):
    student_id = fields.Str(required=True, validate=fields.Length(min=1, max=50))
    first_name = fields.Str(required=True, validate=fields.Length(min=1, max=50))
    email = fields.Email(allow_none=True)

def create_student_safely(student_data):
    try:
        # Validate input first
        schema = StudentCreateSchema()
        validated_data = schema.load(student_data)
        
        # Use ORM with validated data
        return db.create_student(validated_data)
        
    except ValidationError as e:
        raise ValueError(f"Invalid student data: {e.messages}")
```

### Connection Security

```python
# Secure database connection configuration
DATABASE_URLS = {
    'development': 'sqlite:///./data/attendance.db',
    'production': 'postgresql+psycopg2://app_user:secure_pass@db.internal:5432/attendance?sslmode=require'
}

# Connection with SSL and proper settings
engine = create_engine(
    DATABASE_URL,
    # Connection pooling
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,
    
    # SSL configuration for PostgreSQL
    connect_args={
        'sslmode': 'require',
        'sslcert': '/path/to/client-cert.pem',
        'sslkey': '/path/to/client-key.pem',
        'sslrootcert': '/path/to/ca-cert.pem'
    }
)
```

### Audit Trail Implementation

```python
# Automatic audit logging for sensitive operations
@event.listens_for(AdminUser, 'before_update')
def log_admin_changes(mapper, connection, target):
    # Log sensitive changes
    audit_entry = DatabaseAudit(
        table_name='admin_users',
        operation='UPDATE',
        record_id=str(target.id),
        admin_id=current_admin_id(),
        ip_address=current_ip_address()
    )
    # Logged automatically by event system
```

## Security Configuration

### Environment Variables (.env)

```bash
# Database Connection (Production)
DATABASE_URL=postgresql+psycopg2://app_user:${DB_PASSWORD}@db.internal:5432/attendance_db

# SSL Configuration
DB_SSL_MODE=require
DB_SSL_CERT=/etc/ssl/certs/client-cert.pem
DB_SSL_KEY=/etc/ssl/private/client-key.pem
DB_SSL_ROOT_CERT=/etc/ssl/certs/ca-cert.pem

# Encryption Keys (Generate with Fernet)
DB_ENCRYPTION_KEY=your-fernet-key-here
BACKUP_ENCRYPTION_KEY=your-backup-key-here

# Connection Security
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
DB_POOL_RECYCLE=3600
```

### PostgreSQL User Setup (Least Privilege)

```sql
-- Create application user with minimal privileges
CREATE USER app_user WITH PASSWORD 'secure_random_password';

-- Grant only necessary permissions
GRANT CONNECT ON DATABASE attendance_db TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;

-- Table-specific permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_users TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON students TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON attendance_records TO app_user;
GRANT SELECT, INSERT ON security_events TO app_user;
GRANT SELECT, INSERT ON database_audit TO app_user;

-- Sequence permissions for auto-increment IDs
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- Revoke dangerous permissions
REVOKE ALL ON pg_catalog FROM app_user;
REVOKE ALL ON information_schema FROM app_user;
```

### Network Security

```bash
# PostgreSQL pg_hba.conf (connection rules)
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   attendance_db   app_user                                md5
host    attendance_db   app_user        10.0.0.0/8              md5
hostssl attendance_db   app_user        0.0.0.0/0              md5

# Firewall rules (iptables)
# Allow application servers only
iptables -A INPUT -p tcp --dport 5432 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 5432 -j DROP
```

## Encrypted Backups

### Backup Creation

```python
from backend.database.backup_manager import EncryptedBackupManager

# Initialize backup manager
backup_manager = EncryptedBackupManager()

# Create encrypted backup
backup_info = backup_manager.create_backup('daily_backup_2025_10_10')

# Backup includes:
# - Full database dump (pg_dump or sqlite .dump)
# - Gzip compression
# - Fernet encryption
# - Integrity checksums
# - Metadata tracking
```

### Automated Backup Schedule

```bash
# Add to crontab for daily backups
0 2 * * * /usr/bin/python3 /app/backend/database/backup_manager.py --backup

# Weekly verification
0 3 * * 0 /usr/bin/python3 /app/backend/database/backup_manager.py --verify $(date -d 'yesterday' +backup_%Y%m%d_%H%M%S)
```

### Backup Security Features

- **Encryption**: AES-256 via Fernet (PBKDF2 key derivation)
- **Compression**: Gzip to reduce storage
- **Integrity**: SHA-256 checksums
- **Rotation**: Automatic cleanup of old backups
- **Verification**: Backup integrity checking

### Restore Process

```python
# List available backups
backups = backup_manager.list_backups()

# Verify backup integrity
result = backup_manager.verify_backup('backup_20251010_020000')

# Restore if needed
if result['valid']:
    backup_manager.restore_backup('backup_20251010_020000')
```

## Audit & Monitoring

### Security Event Logging

```python
# Automatic security event logging
def log_security_event(event_type: str, description: str, risk_level: str = 'low'):
    with db.get_session() as session:
        event = SecurityEvent(
            event_type=event_type,
            event_description=description,
            ip_address=request.remote_addr,
            risk_level=risk_level,
            admin_id=session.get('admin_id')
        )
        session.add(event)

# Usage examples
log_security_event('data_access', 'Student records accessed', 'low')
log_security_event('privilege_escalation', 'Admin role granted', 'high')
log_security_event('suspicious_activity', 'Multiple failed login attempts', 'medium')
```

### Database Operation Audit

```python
# All database modifications are automatically logged
class DatabaseAudit(Base):
    table_name = Column(String(100), nullable=False)
    operation = Column(String(20), nullable=False)  # INSERT, UPDATE, DELETE
    old_values = Column(Text, nullable=True)  # JSON of changes
    new_values = Column(Text, nullable=True)
    admin_id = Column(UUID, ForeignKey('admin_users.id'))
    ip_address = Column(String(45))
    created_at = Column(DateTime, default=datetime.utcnow)
```

### Monitoring Queries

```sql
-- Suspicious login patterns
SELECT ip_address, COUNT(*) as failed_attempts
FROM security_events 
WHERE event_type = 'login_failure' 
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(*) > 10;

-- Recent privilege changes
SELECT se.*, au.email
FROM security_events se
JOIN admin_users au ON se.admin_id = au.id
WHERE se.event_type IN ('privilege_escalation', 'admin_created')
  AND se.created_at > NOW() - INTERVAL '24 hours';

-- Data access patterns
SELECT table_name, operation, COUNT(*) as operations
FROM database_audit
WHERE created_at > NOW() - INTERVAL '1 day'
GROUP BY table_name, operation
ORDER BY operations DESC;
```

## Production Deployment

### Database Setup Checklist

- [ ] **Create dedicated database user** with minimal privileges
- [ ] **Enable SSL/TLS** for database connections
- [ ] **Configure firewall** to restrict database access
- [ ] **Set up connection pooling** with appropriate limits
- [ ] **Enable query logging** for audit purposes
- [ ] **Configure backup encryption** and test restore process
- [ ] **Set up monitoring** and alerting
- [ ] **Review and harden** database server configuration

### Security Hardening

```bash
# PostgreSQL security configuration
# postgresql.conf
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
ssl_ca_file = '/path/to/ca.crt'

log_statement = 'mod'  # Log all modifications
log_connections = on
log_disconnections = on
log_duration = on
log_min_duration_statement = 1000  # Log slow queries

# Limit connections
max_connections = 100
shared_preload_libraries = 'pg_stat_statements'
```

### Application Security

```python
# Production database manager initialization
class ProductionDatabaseManager(SecureDatabaseManager):
    def __init__(self):
        # Use production database URL
        super().__init__(os.getenv('DATABASE_URL'))
        
        # Enable strict validation in production
        self.strict_validation = True
        
        # Set up connection monitoring
        self._setup_connection_monitoring()
    
    def _setup_connection_monitoring(self):
        # Monitor for suspicious patterns
        @event.listens_for(self.engine, "connect")
        def monitor_connections(dbapi_connection, connection_record):
            logger.info(f"Database connection established from {os.getpid()}")
        
        @event.listens_for(self.engine, "checkout")
        def monitor_checkouts(dbapi_connection, connection_record, connection_proxy):
            # Track connection pool usage
            pool = self.engine.pool
            logger.debug(f"Connection pool: {pool.checkedin()}/{pool.size()}")
```

### Backup Strategy

1. **Daily encrypted backups** with 30-day retention
2. **Weekly verification** of backup integrity
3. **Monthly restore testing** to separate environment
4. **Offsite backup storage** (encrypted cloud storage)
5. **Disaster recovery plan** with RTO/RPO targets

### Monitoring & Alerting

```python
# Set up alerts for security events
def setup_security_alerts():
    # Alert on high-risk events
    if security_event.risk_level in ['high', 'critical']:
        send_immediate_alert(security_event)
    
    # Alert on unusual patterns
    failed_logins = count_recent_failed_logins()
    if failed_logins > 50:
        send_security_alert("High number of failed logins detected")
    
    # Alert on backup failures
    if backup_failed():
        send_critical_alert("Database backup failed")
```

## Testing & Validation

### SQL Injection Testing

```python
# Test input sanitization
def test_sql_injection_protection():
    # Malicious inputs that should be safely handled
    malicious_inputs = [
        "'; DROP TABLE students; --",
        "admin@test.com' OR '1'='1",
        "1' UNION SELECT password FROM admin_users --",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
    ]
    
    for malicious_input in malicious_inputs:
        try:
            # These should all be safely handled
            result = db.get_admin_by_email(malicious_input)
            assert result is None or isinstance(result, dict)
        except Exception as e:
            # Should not cause SQL errors
            assert "syntax error" not in str(e).lower()
            assert "sql" not in str(e).lower()
```

### Security Audit

```bash
# Run security audit tools
sqlmap -u "http://localhost:5000/api/login" --data="email=test&password=test" --level=5
nmap -sS -O target_host
nikto -h http://localhost:5000

# Database security scan
pg_audit_analyze --database attendance_db
```

This comprehensive security implementation provides multiple layers of protection against SQL injection and ensures secure database operations throughout the application lifecycle.

## Quick Reference

### Safe Practices ✅
- Use SQLAlchemy ORM queries
- Parameterized raw SQL with named parameters
- Input validation with Marshmallow schemas
- Encrypted backups with integrity checks
- Comprehensive audit logging
- SSL/TLS for database connections
- Least privilege database users

### Dangerous Practices ❌
- String concatenation with user input
- f-strings or % formatting with user data
- Direct SQL execution without parameters
- Unencrypted backups containing sensitive data
- Overprivileged database accounts
- Plaintext database connections
- Missing input validation