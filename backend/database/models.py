"""
Secure SQLAlchemy Models for Automated Attendance System

Features:
- Proper field validation and constraints
- Encrypted sensitive data fields
- Audit trails for security events
- Biometric data protection
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text, 
    ForeignKey, LargeBinary, Index, CheckConstraint,
    UniqueConstraint, text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, validates
from sqlalchemy.dialects.postgresql import UUID
from cryptography.fernet import Fernet
import re
import logging

logger = logging.getLogger(__name__)

# Base class for all models
Base = declarative_base()

# Encryption key for sensitive data (should be in environment)
ENCRYPTION_KEY = os.getenv('DB_ENCRYPTION_KEY')
if ENCRYPTION_KEY:
    cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
else:
    cipher = None
    logger.warning("DB_ENCRYPTION_KEY not set - sensitive data will not be encrypted")

class TimestampMixin:
    """Mixin for created_at and updated_at timestamps"""
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), 
                       default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc), 
                       nullable=False)

class AdminUser(Base, TimestampMixin):
    """
    Admin user model with secure password storage and validation
    """
    __tablename__ = 'admin_users'
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Basic information
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(100), nullable=False)
    
    # Password fields
    password_hash = Column(String(255), nullable=True)  # Argon2 hash
    legacy_hash = Column(String(255), nullable=True)    # For migration
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_super_admin = Column(Boolean, default=False, nullable=False)
    
    # Security tracking
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)  # IPv6 compatible
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    
    # Password policy
    password_changed_at = Column(DateTime(timezone=True), 
                                default=lambda: datetime.now(timezone.utc), 
                                nullable=False)
    force_password_change = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    login_sessions = relationship("LoginSession", back_populates="admin", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="admin", cascade="all, delete-orphan")
    
    # Constraints
    __table_args__ = (
        CheckConstraint('char_length(email) >= 3', name='email_min_length'),
        CheckConstraint('char_length(full_name) >= 2', name='name_min_length'),
        CheckConstraint('failed_login_count >= 0', name='failed_count_non_negative'),
        Index('idx_admin_email_active', 'email', 'is_active'),
        Index('idx_admin_last_login', 'last_login'),
    )
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format"""
        if not email:
            raise ValueError("Email is required")
        
        email = email.lower().strip()
        
        # Basic email regex (RFC 5322 compliant)
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")
        
        if len(email) > 255:
            raise ValueError("Email too long (max 255 characters)")
            
        return email
    
    @validates('full_name')
    def validate_full_name(self, key, name):
        """Validate full name"""
        if not name or len(name.strip()) < 2:
            raise ValueError("Full name must be at least 2 characters")
        
        name = name.strip()
        if len(name) > 100:
            raise ValueError("Full name too long (max 100 characters)")
        
        # Only allow letters, spaces, hyphens, apostrophes
        if not re.match(r"^[a-zA-Z\s\-']+$", name):
            raise ValueError("Full name contains invalid characters")
            
        return name
    
    def is_locked(self) -> bool:
        """Check if account is currently locked"""
        if not self.locked_until:
            return False
        return datetime.now(timezone.utc) < self.locked_until
    
    def __repr__(self):
        return f"<AdminUser(id={self.id}, email='{self.email}')>"

class Student(Base, TimestampMixin):
    """
    Student model with encrypted biometric data
    """
    __tablename__ = 'students'
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Basic information
    student_id = Column(String(50), unique=True, nullable=False, index=True)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(255), unique=True, nullable=True, index=True)
    
    # Academic information
    class_name = Column(String(100), nullable=False)
    section = Column(String(20), nullable=True)
    roll_number = Column(String(50), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Encrypted biometric data (face embeddings)
    face_encoding = Column(LargeBinary, nullable=True)  # Encrypted face embedding
    
    # Relationships
    attendance_records = relationship("AttendanceRecord", back_populates="student")
    
    # Constraints
    __table_args__ = (
        CheckConstraint('char_length(student_id) >= 1', name='student_id_not_empty'),
        CheckConstraint('char_length(first_name) >= 1', name='first_name_not_empty'),
        CheckConstraint('char_length(last_name) >= 1', name='last_name_not_empty'),
        Index('idx_student_name', 'first_name', 'last_name'),
        Index('idx_student_class', 'class_name', 'section'),
        UniqueConstraint('class_name', 'roll_number', name='unique_roll_per_class')
    )
    
    @validates('student_id')
    def validate_student_id(self, key, student_id):
        """Validate student ID format"""
        if not student_id or len(student_id.strip()) == 0:
            raise ValueError("Student ID is required")
        
        student_id = student_id.strip().upper()
        
        if len(student_id) > 50:
            raise ValueError("Student ID too long (max 50 characters)")
        
        # Allow alphanumeric and basic punctuation
        if not re.match(r'^[A-Z0-9\-_]+$', student_id):
            raise ValueError("Student ID contains invalid characters")
            
        return student_id
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format if provided"""
        if not email:
            return None
            
        email = email.lower().strip()
        
        # Basic email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")
            
        return email
    
    def set_face_encoding(self, encoding_data: bytes) -> None:
        """Encrypt and store face encoding"""
        if cipher and encoding_data:
            self.face_encoding = cipher.encrypt(encoding_data)
        else:
            logger.warning("Face encoding stored unencrypted - encryption key not available")
            self.face_encoding = encoding_data
    
    def get_face_encoding(self) -> Optional[bytes]:
        """Decrypt and return face encoding"""
        if not self.face_encoding:
            return None
            
        if cipher:
            try:
                return cipher.decrypt(self.face_encoding)
            except Exception as e:
                logger.error(f"Failed to decrypt face encoding for student {self.id}: {e}")
                return None
        else:
            return self.face_encoding
    
    @property
    def full_name(self) -> str:
        """Get full name"""
        return f"{self.first_name} {self.last_name}"
    
    def __repr__(self):
        return f"<Student(id={self.id}, student_id='{self.student_id}', name='{self.full_name}')>"

class AttendanceRecord(Base, TimestampMixin):
    """
    Attendance record with audit trail
    """
    __tablename__ = 'attendance_records'
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign keys
    student_id = Column(UUID(as_uuid=True), ForeignKey('students.id'), nullable=False)
    
    # Attendance data
    attendance_date = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(String(20), nullable=False)  # 'present', 'absent', 'late'
    
    # Detection metadata
    confidence_score = Column(String(10), nullable=True)  # Face recognition confidence
    detection_method = Column(String(50), nullable=False, default='manual')  # 'face_recognition', 'manual', 'rfid'
    
    # Location/session info
    class_session = Column(String(100), nullable=True)
    location = Column(String(100), nullable=True)
    
    # Admin who recorded (for manual entries)
    recorded_by = Column(UUID(as_uuid=True), ForeignKey('admin_users.id'), nullable=True)
    
    # Relationships
    student = relationship("Student", back_populates="attendance_records")
    admin = relationship("AdminUser")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("status IN ('present', 'absent', 'late', 'excused')", name='valid_status'),
        CheckConstraint('confidence_score IS NULL OR confidence_score::float >= 0.0', name='valid_confidence'),
        Index('idx_attendance_date_student', 'attendance_date', 'student_id'),
        Index('idx_attendance_status', 'status'),
        UniqueConstraint('student_id', 'attendance_date', 'class_session', 
                        name='unique_attendance_per_session')
    )
    
    @validates('status')
    def validate_status(self, key, status):
        """Validate attendance status"""
        valid_statuses = {'present', 'absent', 'late', 'excused'}
        if status not in valid_statuses:
            raise ValueError(f"Status must be one of: {valid_statuses}")
        return status
    
    @validates('detection_method')
    def validate_detection_method(self, key, method):
        """Validate detection method"""
        valid_methods = {'face_recognition', 'manual', 'rfid', 'qr_code'}
        if method not in valid_methods:
            raise ValueError(f"Detection method must be one of: {valid_methods}")
        return method
    
    def __repr__(self):
        return f"<AttendanceRecord(id={self.id}, student_id={self.student_id}, status='{self.status}')>"

class LoginSession(Base, TimestampMixin):
    """
    Track admin login sessions for security
    """
    __tablename__ = 'login_sessions'
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key
    admin_id = Column(UUID(as_uuid=True), ForeignKey('admin_users.id'), nullable=False)
    
    # Session data
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    
    # Session status
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    logged_out_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    admin = relationship("AdminUser", back_populates="login_sessions")
    
    # Constraints
    __table_args__ = (
        Index('idx_session_token_active', 'session_token', 'is_active'),
        Index('idx_session_admin_active', 'admin_id', 'is_active'),
        Index('idx_session_expires', 'expires_at'),
    )
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.now(timezone.utc) > self.expires_at
    
    def __repr__(self):
        return f"<LoginSession(id={self.id}, admin_id={self.admin_id}, active={self.is_active})>"

class SecurityEvent(Base, TimestampMixin):
    """
    Security event audit log
    """
    __tablename__ = 'security_events'
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key (nullable for anonymous events)
    admin_id = Column(UUID(as_uuid=True), ForeignKey('admin_users.id'), nullable=True)
    
    # Event data
    event_type = Column(String(50), nullable=False, index=True)
    event_description = Column(Text, nullable=False)
    
    # Source information
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(Text, nullable=True)
    
    # Risk assessment
    risk_level = Column(String(20), nullable=False, default='low')  # low, medium, high, critical
    
    # Additional metadata (JSON-serialized)
    metadata = Column(Text, nullable=True)
    
    # Relationships
    admin = relationship("AdminUser", back_populates="security_events")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("risk_level IN ('low', 'medium', 'high', 'critical')", name='valid_risk_level'),
        Index('idx_security_event_type', 'event_type'),
        Index('idx_security_risk_level', 'risk_level'),
        Index('idx_security_created_at', 'created_at'),
    )
    
    @validates('event_type')
    def validate_event_type(self, key, event_type):
        """Validate event type"""
        valid_types = {
            'login_success', 'login_failure', 'logout', 'password_change',
            'account_locked', 'account_unlocked', 'failed_captcha',
            'suspicious_activity', 'data_access', 'data_modification',
            'privilege_escalation', 'session_hijack'
        }
        if event_type not in valid_types:
            logger.warning(f"Unknown event type: {event_type}")
        return event_type
    
    @validates('risk_level')
    def validate_risk_level(self, key, risk_level):
        """Validate risk level"""
        valid_levels = {'low', 'medium', 'high', 'critical'}
        if risk_level not in valid_levels:
            raise ValueError(f"Risk level must be one of: {valid_levels}")
        return risk_level
    
    def __repr__(self):
        return f"<SecurityEvent(id={self.id}, type='{self.event_type}', risk='{self.risk_level}')>"

class DatabaseAudit(Base):
    """
    Database operation audit trail
    """
    __tablename__ = 'database_audit'
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Audit data
    table_name = Column(String(100), nullable=False, index=True)
    operation = Column(String(20), nullable=False)  # INSERT, UPDATE, DELETE
    record_id = Column(String(255), nullable=True)  # ID of affected record
    
    # Change tracking
    old_values = Column(Text, nullable=True)  # JSON of old values
    new_values = Column(Text, nullable=True)  # JSON of new values
    
    # Source information
    admin_id = Column(UUID(as_uuid=True), ForeignKey('admin_users.id'), nullable=True)
    ip_address = Column(String(45), nullable=True)
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Constraints
    __table_args__ = (
        CheckConstraint("operation IN ('INSERT', 'UPDATE', 'DELETE')", name='valid_operation'),
        Index('idx_audit_table_operation', 'table_name', 'operation'),
        Index('idx_audit_created_at', 'created_at'),
    )
    
    def __repr__(self):
        return f"<DatabaseAudit(id={self.id}, table='{self.table_name}', op='{self.operation}')>"