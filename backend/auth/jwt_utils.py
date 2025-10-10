"""
JWT Authentication Utilities
Handles JWT token creation, validation, and management
"""
import jwt
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from functools import wraps
from flask import request, jsonify


class JWTManager:
    """Manages JWT token operations"""
    
    def __init__(self, secret_key: str, algorithm: str = 'HS256'):
        """
        Initialize JWT manager
        
        Args:
            secret_key: Secret key for signing tokens
            algorithm: JWT algorithm (default: HS256)
        """
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expires = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 900))  # 15 minutes
        self.refresh_token_expires = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 2592000))  # 30 days
    
    def create_access_token(self, user_id: int, email: str, role: str) -> str:
        """
        Create a JWT access token
        
        Args:
            user_id: User ID
            email: User email
            role: User role
            
        Returns:
            JWT token string
        """
        payload = {
            'user_id': user_id,
            'email': email,
            'role': role,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(seconds=self.access_token_expires),
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user_id: int) -> str:
        """
        Create a JWT refresh token
        
        Args:
            user_id: User ID
            
        Returns:
            JWT refresh token string
        """
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + timedelta(seconds=self.refresh_token_expires),
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str, token_type: str = 'access') -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token
        
        Args:
            token: JWT token string
            token_type: Expected token type ('access' or 'refresh')
            
        Returns:
            Decoded payload or None if invalid
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get('type') != token_type:
                return None
            
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def decode_token_without_verification(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode token without verification (for debugging only)
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload or None
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None


def token_required(jwt_manager: JWTManager, required_role: Optional[str] = None):
    """
    Decorator to protect routes with JWT authentication
    
    Args:
        jwt_manager: JWTManager instance
        required_role: Optional role requirement (e.g., 'admin')
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                return jsonify({
                    'error': 'Missing authorization header',
                    'message': 'Please provide a valid access token'
                }), 401
            
            # Extract token (format: "Bearer <token>")
            try:
                token_type, token = auth_header.split(' ')
                if token_type.lower() != 'bearer':
                    raise ValueError("Invalid token type")
            except ValueError:
                return jsonify({
                    'error': 'Invalid authorization header',
                    'message': 'Format: Bearer <token>'
                }), 401
            
            # Verify token
            payload = jwt_manager.verify_token(token, 'access')
            
            if not payload:
                return jsonify({
                    'error': 'Invalid or expired token',
                    'message': 'Please login again'
                }), 401
            
            # Check role if required
            if required_role and payload.get('role') != required_role:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'This action requires {required_role} role'
                }), 403
            
            # Add user info to request context
            request.current_user = payload
            
            return f(*args, **kwargs)
        return wrapped
    return decorator


def get_current_user() -> Optional[Dict[str, Any]]:
    """
    Get current authenticated user from request context
    
    Returns:
        User payload from JWT or None
    """
    return getattr(request, 'current_user', None)
