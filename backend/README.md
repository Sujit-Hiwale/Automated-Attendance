# Secure Authentication Backend

Enterprise-grade Flask authentication system with advanced security features for the Automated Attendance application.

## 🔒 Security Features

### Password Security
- **Argon2id Hashing**: Industry-standard password hashing with optimal parameters
- **Pepper Support**: Additional secret pepper for enhanced security
- **Automatic Rehashing**: Updates hashes when security parameters change
- **Strength Validation**: Enforces password complexity requirements
- **HIBP Integration**: Checks passwords against Have I Been Pwned database
- **Common Pattern Detection**: Blocks weak passwords with common patterns

### Rate Limiting & Brute-Force Protection
- **Per-IP Limiting**: Prevents abuse from single IP addresses
- **Per-User Limiting**: Protects individual accounts
- **Exponential Lockout**: Progressive lockout durations (1min → 24hr)
- **Redis Support**: Optional Redis backend for distributed rate limiting
- **Memory Fallback**: Works without Redis for development

### Database Security
- **Parameterized Queries**: Prevents SQL injection attacks
- **Optional Encryption**: Full database encryption with pysqlcipher3
- **Secure Schema**: No plaintext passwords, proper indexing
- **Audit Logging**: Comprehensive security event logging
- **Backup Support**: Encrypted backup capabilities

### Authentication & Authorization
- **JWT Tokens**: Stateless authentication with access & refresh tokens
- **Role-Based Access**: Admin and user roles with middleware
- **Token Expiration**: Short-lived access tokens (15min default)
- **Secure Headers**: CORS, CSRF, and security header protection

## 📁 Project Structure

```
backend/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── .env                        # Configuration (DO NOT COMMIT)
├── .env.example               # Configuration template
├── auth/
│   ├── __init__.py
│   └── jwt_utils.py           # JWT token management
├── database/
│   ├── __init__.py
│   └── db_manager.py          # Secure database operations
├── security/
│   ├── __init__.py
│   ├── password_security.py   # Password hashing & validation
│   └── rate_limiting.py       # Rate limiting & audit logging
├── data/
│   └── attendance.db          # SQLite database (auto-created)
└── logs/
    └── security.log           # Security audit logs (auto-created)
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

Or using the virtual environment:

```bash
/home/vishal/Desktop/prot/.venv/bin/pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env` and update values:

```bash
cp .env.example .env
# Edit .env with your secure keys
```

**Important**: Change all secrets in production!

```env
SECRET_KEY=your-super-secret-key-change-this
JWT_SECRET_KEY=your-jwt-secret-key-change-this
PASSWORD_PEPPER=your-optional-pepper-for-security
```

### 3. Run the Server

```bash
python app.py
```

Or using the virtual environment:

```bash
/home/vishal/Desktop/prot/.venv/bin/python app.py
```

Server runs on: **http://localhost:5001**

## 📡 API Endpoints

### Authentication

#### Register New Admin
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "SecurePassword123!",
  "full_name": "Admin User"
}
```

**Response (201)**:
```json
{
  "message": "Registration successful",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "full_name": "Admin User",
    "role": "admin"
  },
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200)**:
```json
{
  "message": "Login successful",
  "user": { ... },
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGc..."
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer <access_token>
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
```

#### Check Email Availability
```http
POST /api/auth/check-email
Content-Type: application/json

{
  "email": "test@example.com"
}
```

### Health Check
```http
GET /api/health
```

## 🔐 Password Requirements

Default password policy:
- Minimum 12 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character
- No common patterns (123, abc, qwerty, etc.)
- Not in HIBP breach database

Configure in `.env`:
```env
MIN_PASSWORD_LENGTH=12
REQUIRE_UPPERCASE=true
REQUIRE_LOWERCASE=true
REQUIRE_DIGITS=true
REQUIRE_SPECIAL=true
CHECK_HIBP=true
```

## 🛡️ Rate Limiting

Default limits:
- **Registration**: 5 per hour per IP
- **Login**: 10 per minute per IP
- **Global**: 200 per day, 50 per hour

**Exponential Lockout**:
- 5 failures → 1 minute lockout
- 10 failures → 5 minutes lockout
- 15 failures → 15 minutes lockout
- 20 failures → 1 hour lockout
- 25+ failures → 24 hours lockout

## 📊 Security Logging

All security events are logged to `logs/security.log`:

```json
{
  "timestamp": "2025-10-10T08:52:18.123456",
  "event_type": "login_success",
  "ip_address": "127.0.0.1",
  "details": {
    "email": "admin@example.com",
    "user_id": 1
  }
}
```

Event types:
- `registration`
- `login_success`
- `login_failure`
- `password_change`
- `account_lockout`
- `logout`

## 🔧 Configuration Options

### JWT Configuration
```env
JWT_ACCESS_TOKEN_EXPIRES=900      # 15 minutes
JWT_REFRESH_TOKEN_EXPIRES=2592000 # 30 days
```

### Database Encryption (Optional)
```env
DATABASE_ENCRYPTION=true
DATABASE_ENCRYPTION_KEY=your-32-byte-encryption-key
```

**Note**: Requires `pysqlcipher3` installation:
```bash
pip install pysqlcipher3
```

### Redis Rate Limiting (Optional)
```env
REDIS_URL=redis://localhost:6379/0
```

Falls back to in-memory storage if Redis is unavailable.

### CORS Configuration
```env
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

## 🧪 Testing with cURL

### Register
```bash
curl -X POST http://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com",
    "password": "SecurePass123!",
    "full_name": "Test Admin"
  }'
```

### Login
```bash
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.com",
    "password": "SecurePass123!"
  }'
```

### Get User Info
```bash
curl -X GET http://localhost:5001/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🔒 Production Deployment Checklist

- [ ] Change all secret keys in `.env`
- [ ] Set `DEBUG=false`
- [ ] Set `FLASK_ENV=production`
- [ ] Enable `SESSION_COOKIE_SECURE=true` (HTTPS only)
- [ ] Configure Redis for rate limiting
- [ ] Enable database encryption if needed
- [ ] Set up proper CORS origins
- [ ] Use a production WSGI server (gunicorn, uWSGI)
- [ ] Enable HTTPS/TLS
- [ ] Set up automated backups
- [ ] Configure log rotation
- [ ] Monitor security logs

### Production Server Setup (gunicorn)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5001 app:app
```

## 📝 Error Codes

- **200**: Success
- **201**: Created (registration)
- **400**: Bad request (validation error)
- **401**: Unauthorized (invalid credentials/token)
- **403**: Forbidden (insufficient permissions)
- **409**: Conflict (user already exists)
- **429**: Too many requests (rate limited)
- **500**: Internal server error

## 🆘 Troubleshooting

### Import Errors
```bash
# Ensure you're in the backend directory
cd backend
pip install -r requirements.txt
```

### Permission Denied (logs/data)
```bash
# Create directories manually
mkdir -p logs data
chmod 755 logs data
```

### Redis Connection Error
Rate limiting falls back to in-memory storage. For production, install Redis:
```bash
# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis
```

### HIBP API Timeout
If HIBP API is slow/unavailable, set:
```env
CHECK_HIBP=false
```

## 📚 Dependencies

- **Flask** 3.0.0 - Web framework
- **Flask-CORS** 4.0.0 - CORS handling
- **argon2-cffi** 23.1.0 - Password hashing
- **PyJWT** 2.8.0 - JWT tokens
- **Flask-Limiter** 3.5.0 - Rate limiting
- **redis** 5.0.1 - Redis client
- **requests** 2.31.0 - HTTP library (HIBP)
- **python-dotenv** 1.0.0 - Environment variables

## 🔗 Integration with Frontend

Use the following headers for authenticated requests:

```javascript
// Login/Register
const response = await fetch('http://localhost:5001/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ email, password })
});

const { access_token, refresh_token } = await response.json();

// Store tokens securely (localStorage or httpOnly cookies)
localStorage.setItem('access_token', access_token);
localStorage.setItem('refresh_token', refresh_token);

// Authenticated requests
const userResponse = await fetch('http://localhost:5001/api/auth/me', {
  headers: {
    'Authorization': `Bearer ${access_token}`
  }
});
```

## 📄 License

This is part of the Automated-Attendance project.

## 🤝 Support

For issues or questions, check the security logs at `logs/security.log` for detailed error information.
