"""
Secure Database Manager with SQL Injection Prevention

Features:
- SQLAlchemy ORM for safe database operations  
- Parameterized queries only
- Input validation and sanitization
- Connection pooling with security settings
- Audit logging for all operations
- Encrypted sensitive data handling
"""

import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Union
from contextlib import contextmanager
from sqlalchemy import create_engine, text, event, inspect
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.pool import QueuePool
from marshmallow import Schema, fields, ValidationError
import uuid
from dotenv import load_dotenv

# Import our secure models
from .models import (
    Base, AdminUser, Student, AttendanceRecord, 
    LoginSession, SecurityEvent, DatabaseAudit
)

load_dotenv()
logger = logging.getLogger(__name__)

# Input validation schemas
class AdminCreateSchema(Schema):
    email = fields.Email(required=True)
    full_name = fields.Str(required=True, validate=fields.Length(min=2, max=100))
    password_hash = fields.Str(required=True, validate=fields.Length(min=1, max=255))
    is_super_admin = fields.Bool(missing=False)

class StudentCreateSchema(Schema):
    student_id = fields.Str(required=True, validate=fields.Length(min=1, max=50))
    first_name = fields.Str(required=True, validate=fields.Length(min=1, max=50))
    last_name = fields.Str(required=True, validate=fields.Length(min=1, max=50))
    email = fields.Email(allow_none=True)
    class_name = fields.Str(required=True, validate=fields.Length(min=1, max=100))
    section = fields.Str(allow_none=True, validate=fields.Length(max=20))
    roll_number = fields.Str(allow_none=True, validate=fields.Length(max=50))

class AttendanceCreateSchema(Schema):
    student_id = fields.UUID(required=True)
    attendance_date = fields.DateTime(required=True)
    status = fields.Str(required=True, validate=fields.OneOf(['present', 'absent', 'late', 'excused']))
    detection_method = fields.Str(missing='manual', validate=fields.OneOf(['face_recognition', 'manual', 'rfid', 'qr_code']))
    confidence_score = fields.Str(allow_none=True)
    class_session = fields.Str(allow_none=True, validate=fields.Length(max=100))
    location = fields.Str(allow_none=True, validate=fields.Length(max=100))

class SecureDatabaseManager:
    """
    Secure database manager with comprehensive SQL injection prevention
    """
    
    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize secure database manager
        
        Args:
            database_url: Database connection URL (defaults to environment variable)
        """
        self.database_url = database_url or self._get_database_url()
        self.engine = None
        self.Session = None
        self._current_admin_id = None
        self._current_ip = None
        
        self._initialize_engine()
        self._setup_event_listeners()
    
    def _get_database_url(self) -> str:
        """Get database URL from environment with secure defaults"""
        # Default to PostgreSQL in production, SQLite for development
        default_url = os.getenv('DATABASE_URL')
        
        if not default_url:
            # Development default (SQLite with WAL mode for concurrency)
            db_path = os.path.join(os.getcwd(), 'data', 'attendance.db')
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            default_url = f'sqlite:///{db_path}?check_same_thread=False'
        
        return default_url
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine with security settings"""
        # Connection pool settings for security and performance
        pool_settings = {
            'poolclass': QueuePool,
            'pool_size': int(os.getenv('DB_POOL_SIZE', 10)),
            'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', 20)),
            'pool_pre_ping': True,  # Validate connections before use
            'pool_recycle': int(os.getenv('DB_POOL_RECYCLE', 3600))  # 1 hour
        }
        
        # SSL settings for PostgreSQL
        connect_args = {}
        if self.database_url.startswith('postgresql'):
            ssl_mode = os.getenv('DB_SSL_MODE', 'prefer')
            if ssl_mode != 'disable':
                connect_args['sslmode'] = ssl_mode
                if os.getenv('DB_SSL_CERT'):
                    connect_args['sslcert'] = os.getenv('DB_SSL_CERT')
                    connect_args['sslkey'] = os.getenv('DB_SSL_KEY')
                    connect_args['sslrootcert'] = os.getenv('DB_SSL_ROOT_CERT')
        
        # SQLite specific settings
        elif self.database_url.startswith('sqlite'):
            connect_args['check_same_thread'] = False
            # Enable WAL mode for better concurrency
            connect_args['isolation_level'] = None
        
        try:
            self.engine = create_engine(
                self.database_url,
                connect_args=connect_args,
                echo=os.getenv('DB_ECHO', 'false').lower() == 'true',
                **pool_settings
            )
            
            # Test connection
            with self.engine.connect() as conn:
                conn.execute(text('SELECT 1'))
            
            self.Session = sessionmaker(bind=self.engine)
            logger.info("Database engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database engine: {e}")
            raise
    
    def _setup_event_listeners(self):
        """Set up SQLAlchemy event listeners for security"""
        
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set SQLite security pragmas"""
            if self.database_url.startswith('sqlite'):
                cursor = dbapi_connection.cursor()
                # Security settings
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.execute("PRAGMA mmap_size=268435456")  # 256MB
                cursor.close()
        
        @event.listens_for(Session, "before_insert", propagate=True)
        @event.listens_for(Session, "before_update", propagate=True)
        @event.listens_for(Session, "before_delete", propagate=True)
        def audit_changes(mapper, connection, target):
            """Audit database changes"""
            self._log_database_operation(mapper.class_.__name__, 'MODIFY', target)
    
    def create_tables(self):
        """Create all database tables"""
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    @contextmanager
    def get_session(self) -> Session:
        """
        Context manager for database sessions with automatic cleanup
        """
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def set_current_user(self, admin_id: Optional[str], ip_address: Optional[str] = None):
        """Set current admin user for audit logging"""
        self._current_admin_id = admin_id
        self._current_ip = ip_address
    
    # Admin User Management
    def create_admin_user(self, admin_data: Dict[str, Any]) -> str:
        """
        Create new admin user with validation
        
        Args:
            admin_data: Admin user data dictionary
            
        Returns:
            Admin user ID
        """
        try:
            # Validate input data
            schema = AdminCreateSchema()
            validated_data = schema.load(admin_data)
            
            with self.get_session() as session:
                # Check if email already exists
                existing = session.query(AdminUser).filter(
                    AdminUser.email == validated_data['email']
                ).first()
                
                if existing:
                    raise ValueError("Email already exists")
                
                # Create new admin user
                admin = AdminUser(**validated_data)
                session.add(admin)
                session.flush()  # Get the ID
                
                # Log security event
                self._log_security_event(
                    session, 'admin_created', f"New admin created: {admin.email}",
                    admin_id=admin.id, risk_level='medium'
                )
                
                admin_id = str(admin.id)
                logger.info(f"Created admin user: {admin.email}")
                return admin_id
                
        except ValidationError as e:
            logger.warning(f"Invalid admin data: {e.messages}")
            raise ValueError(f"Invalid data: {e.messages}")
        except IntegrityError as e:
            logger.warning(f"Admin creation integrity error: {e}")
            raise ValueError("Email already exists or data conflict")
        except Exception as e:
            logger.error(f"Failed to create admin user: {e}")
            raise
    
    def get_admin_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get admin user by email with input validation
        
        Args:
            email: Admin email address
            
        Returns:
            Admin user data or None
        """
        if not email or len(email.strip()) == 0:
            return None
        
        email = email.lower().strip()
        
        try:
            with self.get_session() as session:
                admin = session.query(AdminUser).filter(
                    AdminUser.email == email
                ).first()
                
                if admin:
                    return {
                        'id': admin.id,
                        'email': admin.email,
                        'full_name': admin.full_name,
                        'password_hash': admin.password_hash,
                        'legacy_hash': admin.legacy_hash,
                        'is_active': admin.is_active,
                        'is_super_admin': admin.is_super_admin,
                        'last_login': admin.last_login,
                        'failed_login_count': admin.failed_login_count,
                        'locked_until': admin.locked_until,
                        'force_password_change': admin.force_password_change
                    }
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get admin by email: {e}")
            raise
    
    def update_admin_password(self, admin_id: str, password_hash: str, clear_legacy: bool = False) -> bool:
        """
        Update admin password hash safely
        
        Args:
            admin_id: Admin user ID
            password_hash: New password hash
            clear_legacy: Whether to clear legacy hash field
            
        Returns:
            Success status
        """
        try:
            with self.get_session() as session:
                admin = session.query(AdminUser).filter(
                    AdminUser.id == admin_id
                ).first()
                
                if not admin:
                    return False
                
                admin.password_hash = password_hash
                admin.password_changed_at = datetime.now(timezone.utc)
                admin.force_password_change = False
                
                if clear_legacy:
                    admin.legacy_hash = None
                
                # Log security event
                self._log_security_event(
                    session, 'password_changed', f"Password changed for admin: {admin.email}",
                    admin_id=admin.id, risk_level='medium'
                )
                
                logger.info(f"Updated password for admin: {admin.email}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update admin password: {e}")
            raise
    
    # Student Management
    def create_student(self, student_data: Dict[str, Any]) -> str:
        """
        Create new student with validation
        
        Args:
            student_data: Student data dictionary
            
        Returns:
            Student ID
        """
        try:
            # Validate input data
            schema = StudentCreateSchema()
            validated_data = schema.load(student_data)
            
            with self.get_session() as session:
                # Check for duplicate student ID
                existing = session.query(Student).filter(
                    Student.student_id == validated_data['student_id']
                ).first()
                
                if existing:
                    raise ValueError("Student ID already exists")
                
                # Create new student
                student = Student(**validated_data)
                session.add(student)
                session.flush()
                
                student_id = str(student.id)
                logger.info(f"Created student: {student.student_id}")
                return student_id
                
        except ValidationError as e:
            logger.warning(f"Invalid student data: {e.messages}")
            raise ValueError(f"Invalid data: {e.messages}")
        except IntegrityError as e:
            logger.warning(f"Student creation integrity error: {e}")
            raise ValueError("Student ID already exists or data conflict")
        except Exception as e:
            logger.error(f"Failed to create student: {e}")
            raise
    
    def get_student_by_id(self, student_id: str) -> Optional[Dict[str, Any]]:
        """
        Get student by student ID with validation
        
        Args:
            student_id: Student ID
            
        Returns:
            Student data or None
        """
        if not student_id or len(student_id.strip()) == 0:
            return None
        
        student_id = student_id.strip().upper()
        
        try:
            with self.get_session() as session:
                student = session.query(Student).filter(
                    Student.student_id == student_id
                ).first()
                
                if student:
                    return {
                        'id': student.id,
                        'student_id': student.student_id,
                        'first_name': student.first_name,
                        'last_name': student.last_name,
                        'email': student.email,
                        'class_name': student.class_name,
                        'section': student.section,
                        'roll_number': student.roll_number,
                        'is_active': student.is_active,
                        'full_name': student.full_name
                    }
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get student by ID: {e}")
            raise
    
    def get_students_by_class(self, class_name: str, section: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get students by class with validation
        
        Args:
            class_name: Class name
            section: Optional section filter
            
        Returns:
            List of student data
        """
        if not class_name or len(class_name.strip()) == 0:
            return []
        
        try:
            with self.get_session() as session:
                query = session.query(Student).filter(
                    Student.class_name == class_name.strip(),
                    Student.is_active == True
                )
                
                if section:
                    query = query.filter(Student.section == section.strip())
                
                students = query.order_by(Student.first_name, Student.last_name).all()
                
                return [
                    {
                        'id': s.id,
                        'student_id': s.student_id,
                        'first_name': s.first_name,
                        'last_name': s.last_name,
                        'email': s.email,
                        'class_name': s.class_name,
                        'section': s.section,
                        'roll_number': s.roll_number,
                        'full_name': s.full_name
                    }
                    for s in students
                ]
                
        except Exception as e:
            logger.error(f"Failed to get students by class: {e}")
            raise
    
    # Attendance Management
    def record_attendance(self, attendance_data: Dict[str, Any]) -> str:
        """
        Record attendance with validation
        
        Args:
            attendance_data: Attendance record data
            
        Returns:
            Attendance record ID
        """
        try:
            # Validate input data
            schema = AttendanceCreateSchema()
            validated_data = schema.load(attendance_data)
            
            with self.get_session() as session:
                # Check if record already exists for this session
                existing = session.query(AttendanceRecord).filter(
                    AttendanceRecord.student_id == validated_data['student_id'],
                    AttendanceRecord.attendance_date == validated_data['attendance_date'],
                    AttendanceRecord.class_session == validated_data.get('class_session')
                ).first()
                
                if existing:
                    # Update existing record
                    existing.status = validated_data['status']
                    existing.detection_method = validated_data.get('detection_method', 'manual')
                    existing.confidence_score = validated_data.get('confidence_score')
                    existing.updated_at = datetime.now(timezone.utc)
                    
                    if self._current_admin_id:
                        existing.recorded_by = self._current_admin_id
                    
                    record_id = str(existing.id)
                    logger.info(f"Updated attendance record: {record_id}")
                else:
                    # Create new record
                    record_data = validated_data.copy()
                    if self._current_admin_id:
                        record_data['recorded_by'] = self._current_admin_id
                    
                    record = AttendanceRecord(**record_data)
                    session.add(record)
                    session.flush()
                    
                    record_id = str(record.id)
                    logger.info(f"Created attendance record: {record_id}")
                
                return record_id
                
        except ValidationError as e:
            logger.warning(f"Invalid attendance data: {e.messages}")
            raise ValueError(f"Invalid data: {e.messages}")
        except Exception as e:
            logger.error(f"Failed to record attendance: {e}")
            raise
    
    # Security and Audit Methods
    def _log_security_event(self, session: Session, event_type: str, description: str, 
                          admin_id: Optional[str] = None, risk_level: str = 'low',
                          metadata: Optional[Dict] = None):
        """Log security event to audit table"""
        try:
            event = SecurityEvent(
                admin_id=admin_id or self._current_admin_id,
                event_type=event_type,
                event_description=description,
                ip_address=self._current_ip or '127.0.0.1',
                risk_level=risk_level,
                metadata=json.dumps(metadata) if metadata else None
            )
            session.add(event)
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def _log_database_operation(self, table_name: str, operation: str, record: Any):
        """Log database operation for audit trail"""
        try:
            # Don't log audit table operations to avoid recursion
            if table_name in ('SecurityEvent', 'DatabaseAudit'):
                return
            
            with self.get_session() as session:
                audit = DatabaseAudit(
                    table_name=table_name,
                    operation=operation,
                    record_id=str(getattr(record, 'id', None)) if record else None,
                    admin_id=self._current_admin_id,
                    ip_address=self._current_ip or '127.0.0.1'
                )
                session.add(audit)
                
        except Exception as e:
            logger.error(f"Failed to log database operation: {e}")
    
    # Raw SQL execution (when ORM is not sufficient)
    def execute_raw_query(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """
        Execute raw SQL query with parameterization (use sparingly)
        
        Args:
            query: SQL query with named parameters (e.g., :param_name)
            params: Dictionary of parameters
            
        Returns:
            Query results as list of dictionaries
        """
        if not query:
            raise ValueError("Query cannot be empty")
        
        # Log the query for audit purposes
        logger.info(f"Executing raw query: {query[:100]}...")
        
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text(query), params or {})
                
                # Convert to list of dictionaries
                columns = result.keys()
                return [dict(zip(columns, row)) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Raw query execution failed: {e}")
            raise
    
    def close(self):
        """Close database connections"""
        if self.engine:
            self.engine.dispose()
            logger.info("Database connections closed")