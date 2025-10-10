"""
Main Flask Application
Secure authentication system with admin registration and login
"""
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Import security modules
from security.password_security import create_password_security
from security.rate_limiting import RateLimitManager, check_rate_limit, SecurityLogger
from database.db_manager import DatabaseManager
from auth.jwt_utils import JWTManager, token_required, get_current_user

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-jwt-secret')

# Enable CORS
allowed_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',')
CORS(app, origins=allowed_origins, supports_credentials=True)

# Initialize security components
password_security = create_password_security({
    'MIN_PASSWORD_LENGTH': os.getenv('MIN_PASSWORD_LENGTH', '12'),
    'REQUIRE_UPPERCASE': os.getenv('REQUIRE_UPPERCASE', 'true'),
    'REQUIRE_LOWERCASE': os.getenv('REQUIRE_LOWERCASE', 'true'),
    'REQUIRE_DIGITS': os.getenv('REQUIRE_DIGITS', 'true'),
    'REQUIRE_SPECIAL': os.getenv('REQUIRE_SPECIAL', 'true'),
    'CHECK_HIBP': os.getenv('CHECK_HIBP', 'true')
})

rate_limit_manager = RateLimitManager(redis_url=os.getenv('REDIS_URL'))
security_logger = SecurityLogger(log_file=os.getenv('LOG_FILE', 'logs/security.log'))
db_manager = DatabaseManager(
    db_path='data/attendance.db',
    encryption_key=os.getenv('DATABASE_ENCRYPTION_KEY') if os.getenv('DATABASE_ENCRYPTION', 'false').lower() == 'true' else None
)
jwt_manager = JWTManager(app.config['JWT_SECRET_KEY'])

# Create rate limiter
limiter = rate_limit_manager.create_limiter(app)


# =====================================
# Authentication Routes
# =====================================

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")  # Limit registration attempts
@check_rate_limit(rate_limit_manager)
def register():
    """
    Register a new admin user
    
    Request JSON:
        {
            "email": "admin@example.com",
            "password": "SecurePassword123!",
            "full_name": "Admin User"
        }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'full_name']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'error': 'Missing required field',
                    'message': f'Field "{field}" is required'
                }), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        full_name = data['full_name'].strip()
        
        # Validate email format
        import re
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return jsonify({
                'error': 'Invalid email',
                'message': 'Please provide a valid email address'
            }), 400
        
        # Check if user already exists
        if db_manager.user_exists(email):
            security_logger.log_event('registration_failed', {
                'email': email,
                'reason': 'User already exists'
            })
            return jsonify({
                'error': 'User already exists',
                'message': 'An account with this email already exists'
            }), 409
        
        # Validate password strength and check HIBP
        is_valid, errors = password_security.validate_and_check_password(password)
        if not is_valid:
            return jsonify({
                'error': 'Weak password',
                'message': 'Password does not meet security requirements',
                'details': errors
            }), 400
        
        # Hash password
        password_hash = password_security.hash_password(password)
        
        # Create user
        user_id = db_manager.create_user(
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            role='admin'  # First users are admins
        )
        
        # Log successful registration
        security_logger.log_registration(email, user_id)
        db_manager.log_audit_event(
            user_id=user_id,
            event_type='registration',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Create tokens
        access_token = jwt_manager.create_access_token(user_id, email, 'admin')
        refresh_token = jwt_manager.create_refresh_token(user_id)
        
        return jsonify({
            'message': 'Registration successful',
            'user': {
                'id': user_id,
                'email': email,
                'full_name': full_name,
                'role': 'admin'
            },
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': jwt_manager.access_token_expires
        }), 201
    
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({
            'error': 'Registration failed',
            'message': 'An error occurred during registration'
        }), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")  # Limit login attempts
@check_rate_limit(rate_limit_manager)
def login():
    """
    Login with email and password
    
    Request JSON:
        {
            "email": "admin@example.com",
            "password": "SecurePassword123!"
        }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({
                'error': 'Missing credentials',
                'message': 'Email and password are required'
            }), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        ip_address = request.remote_addr
        
        # Check rate limits for this email
        is_locked, seconds_remaining = rate_limit_manager.is_locked_out(email)
        if is_locked:
            security_logger.log_failed_login(email, 'Account locked')
            return jsonify({
                'error': 'Account locked',
                'message': f'Too many failed attempts. Try again in {seconds_remaining} seconds.',
                'locked_until': seconds_remaining
            }), 429
        
        # Get user from database
        user = db_manager.get_user_by_email(email)
        
        if not user:
            # Record failed attempt
            rate_limit_manager.record_failed_attempt(email)
            rate_limit_manager.record_failed_attempt(ip_address)
            security_logger.log_failed_login(email, 'User not found')
            
            return jsonify({
                'error': 'Invalid credentials',
                'message': 'Email or password is incorrect'
            }), 401
        
        # Check if user is active
        if not user['is_active']:
            security_logger.log_failed_login(email, 'Account disabled')
            return jsonify({
                'error': 'Account disabled',
                'message': 'This account has been disabled'
            }), 403
        
        # Verify password
        is_valid, needs_rehash = password_security.verify_password(password, user['password_hash'])
        
        if not is_valid:
            # Record failed attempt
            rate_limit_manager.record_failed_attempt(email)
            rate_limit_manager.record_failed_attempt(ip_address)
            security_logger.log_failed_login(email, 'Invalid password')
            
            # Get remaining attempts
            attempt_count = rate_limit_manager.get_attempt_count(email)
            remaining = rate_limit_manager.max_attempts - attempt_count
            
            return jsonify({
                'error': 'Invalid credentials',
                'message': 'Email or password is incorrect',
                'attempts_remaining': max(0, remaining)
            }), 401
        
        # Rehash password if needed (security parameters changed)
        if needs_rehash:
            new_hash = password_security.hash_password(password)
            db_manager.update_password(user['id'], new_hash)
        
        # Reset failed attempts
        rate_limit_manager.reset_failed_attempts(email)
        rate_limit_manager.reset_failed_attempts(ip_address)
        
        # Update last login
        db_manager.update_last_login(user['id'])
        
        # Log successful login
        security_logger.log_successful_login(email, user['id'])
        db_manager.log_audit_event(
            user_id=user['id'],
            event_type='login',
            ip_address=ip_address,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Create tokens
        access_token = jwt_manager.create_access_token(user['id'], email, user['role'])
        refresh_token = jwt_manager.create_refresh_token(user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role']
            },
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': jwt_manager.access_token_expires
        }), 200
    
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({
            'error': 'Login failed',
            'message': 'An error occurred during login'
        }), 500


@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """
    Refresh access token using refresh token
    
    Request JSON:
        {
            "refresh_token": "<refresh_token>"
        }
    """
    try:
        data = request.get_json()
        
        if not data or 'refresh_token' not in data:
            return jsonify({
                'error': 'Missing refresh token',
                'message': 'Refresh token is required'
            }), 400
        
        # Verify refresh token
        payload = jwt_manager.verify_token(data['refresh_token'], 'refresh')
        
        if not payload:
            return jsonify({
                'error': 'Invalid refresh token',
                'message': 'Please login again'
            }), 401
        
        # Get user from database
        user = db_manager.get_user_by_id(payload['user_id'])
        
        if not user or not user['is_active']:
            return jsonify({
                'error': 'Invalid user',
                'message': 'User not found or inactive'
            }), 401
        
        # Create new access token
        access_token = jwt_manager.create_access_token(user['id'], user['email'], user['role'])
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': jwt_manager.access_token_expires
        }), 200
    
    except Exception as e:
        app.logger.error(f"Token refresh error: {e}")
        return jsonify({
            'error': 'Token refresh failed',
            'message': 'An error occurred'
        }), 500


@app.route('/api/auth/me', methods=['GET'])
@token_required(jwt_manager)
def get_current_user_info():
    """Get current authenticated user information"""
    try:
        user_payload = get_current_user()
        user = db_manager.get_user_by_id(user_payload['user_id'])
        
        if not user:
            return jsonify({
                'error': 'User not found'
            }), 404
        
        return jsonify({
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role'],
                'created_at': user['created_at'],
                'last_login': user['last_login']
            }
        }), 200
    
    except Exception as e:
        app.logger.error(f"Get user error: {e}")
        return jsonify({
            'error': 'Failed to get user information'
        }), 500


@app.route('/api/auth/logout', methods=['POST'])
@token_required(jwt_manager)
def logout():
    """
    Logout (client should delete tokens)
    """
    try:
        user_payload = get_current_user()
        
        # Log logout event
        security_logger.log_event('logout', {
            'user_id': user_payload['user_id'],
            'email': user_payload['email']
        })
        
        return jsonify({
            'message': 'Logout successful'
        }), 200
    
    except Exception as e:
        app.logger.error(f"Logout error: {e}")
        return jsonify({
            'error': 'Logout failed'
        }), 500


# =====================================
# Health Check Routes
# =====================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0'
    }), 200


@app.route('/api/auth/check-email', methods=['POST'])
def check_email():
    """Check if email is already registered"""
    try:
        data = request.get_json()
        
        if not data or 'email' not in data:
            return jsonify({
                'error': 'Missing email'
            }), 400
        
        email = data['email'].strip().lower()
        exists = db_manager.user_exists(email)
        
        return jsonify({
            'exists': exists
        }), 200
    
    except Exception as e:
        app.logger.error(f"Check email error: {e}")
        return jsonify({
            'error': 'Failed to check email'
        }), 500


# =====================================
# Error Handlers
# =====================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'error': 'Not found',
        'message': 'The requested resource was not found'
    }), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description)
    }), 429


# =====================================
# Run Application
# =====================================

if __name__ == '__main__':
    debug_mode = os.getenv('DEBUG', 'false').lower() == 'true'
    app.run(
        host='0.0.0.0',
        port=5001,  # Different port from facenet app
        debug=debug_mode
    )
