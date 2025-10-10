# 🚀 Quick Start Guide - Secure Authentication Backend

## Start Server

```bash
cd /home/vishal/Desktop/prot/Automated-Attendance/backend
./start.sh
```

Server runs on: **http://localhost:5001**

## API Endpoints

### Register Admin
```bash
POST /api/auth/register
{
  "email": "admin@example.com",
  "password": "SecurePassword123!",
  "full_name": "Admin User"
}
```

### Login
```bash
POST /api/auth/login
{
  "email": "admin@example.com",
  "password": "SecurePassword123!"
}
```

### Get Current User (Protected)
```bash
GET /api/auth/me
Authorization: Bearer <access_token>
```

### Refresh Token
```bash
POST /api/auth/refresh
{
  "refresh_token": "<refresh_token>"
}
```

### Logout (Protected)
```bash
POST /api/auth/logout
Authorization: Bearer <access_token>
```

## Password Requirements

- ✅ Minimum 12 characters
- ✅ At least 1 uppercase letter
- ✅ At least 1 lowercase letter
- ✅ At least 1 digit
- ✅ At least 1 special character
- ✅ Not in breach database (HIBP)

## Rate Limits

- Registration: **5 per hour**
- Login: **10 per minute**
- Failed login lockout: **Exponential (1min → 24hr)**

## Security Features

✅ Argon2id password hashing  
✅ Optional pepper support  
✅ HIBP breach checking  
✅ Rate limiting & brute-force protection  
✅ JWT authentication  
✅ SQL injection prevention  
✅ Comprehensive audit logging  

## Files Created

```
backend/
├── app.py                     # Main application
├── requirements.txt           # Dependencies
├── .env                       # Configuration
├── README.md                  # Full documentation
├── IMPLEMENTATION_SUMMARY.md  # This guide
├── start.sh                   # Startup script
├── test_auth.py              # Test suite
├── auth/
│   └── jwt_utils.py          # JWT management
├── database/
│   └── db_manager.py         # Database layer
└── security/
    ├── password_security.py  # Password handling
    └── rate_limiting.py      # Rate limiting
```

## Configuration (.env)

```env
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
PASSWORD_PEPPER=your-pepper
MIN_PASSWORD_LENGTH=12
CHECK_HIBP=true
```

## Test

```bash
/home/vishal/Desktop/prot/.venv/bin/python test_auth.py
```

## Need Help?

- Check `README.md` for detailed documentation
- Review `IMPLEMENTATION_SUMMARY.md` for architecture
- Check `logs/security.log` for audit trail
