"""
Database Security Module
Implements secure SQLite operations with parameterized queries and optional encryption
"""
import sqlite3
import os
from typing import Optional, List, Tuple, Any
from datetime import datetime
from contextlib import contextmanager


class DatabaseManager:
    """Manages secure database operations"""
    
    def __init__(self, db_path: str = 'data/attendance.db', encryption_key: Optional[str] = None):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
            encryption_key: Optional encryption key for database encryption (requires pysqlcipher3)
        """
        self.db_path = db_path
        self.encryption_key = encryption_key
        self._ensure_database_directory()
        self._initialize_database()
    
    def _ensure_database_directory(self):
        """Create database directory if it doesn't exist"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections
        Ensures proper connection handling and cleanup
        """
        if self.encryption_key:
            # Use encrypted database if key is provided
            # Note: Requires pysqlcipher3 to be installed
            try:
                from pysqlcipher3 import dbapi2 as sqlcipher
                conn = sqlcipher.connect(self.db_path)
                conn.execute(f"PRAGMA key = '{self.encryption_key}'")
            except ImportError:
                print("Warning: pysqlcipher3 not installed, using standard SQLite")
                conn = sqlite3.connect(self.db_path)
        else:
            conn = sqlite3.connect(self.db_path)
        
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Use Row factory for dict-like access
        conn.row_factory = sqlite3.Row
        
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _initialize_database(self):
        """Create database tables if they don't exist"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table with secure password storage
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TEXT
                )
            """)
            
            # Create index on email for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
            """)
            
            # Audit log table for security events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Sessions table (optional - for session-based auth)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            conn.commit()
    
    # User Management Methods
    
    def create_user(self, email: str, password_hash: str, full_name: str, role: str = 'user') -> int:
        """
        Create a new user with hashed password
        
        Args:
            email: User email (unique)
            password_hash: Already hashed password
            full_name: User's full name
            role: User role (default: 'user')
            
        Returns:
            User ID of newly created user
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT INTO users (email, password_hash, full_name, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email.lower(), password_hash, full_name, role, now, now))
            
            return cursor.lastrowid
    
    def get_user_by_email(self, email: str) -> Optional[dict]:
        """
        Get user by email address
        
        Args:
            email: User email
            
        Returns:
            User dictionary or None if not found
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, email, password_hash, full_name, role, is_active, 
                       created_at, updated_at, last_login, failed_login_attempts, locked_until
                FROM users
                WHERE email = ?
            """, (email.lower(),))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        """
        Get user by ID
        
        Args:
            user_id: User ID
            
        Returns:
            User dictionary or None if not found
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, email, password_hash, full_name, role, is_active, 
                       created_at, updated_at, last_login
                FROM users
                WHERE id = ?
            """, (user_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_password(self, user_id: int, new_password_hash: str) -> bool:
        """
        Update user password (for rehashing)
        
        Args:
            user_id: User ID
            new_password_hash: New hashed password
            
        Returns:
            True if successful
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                UPDATE users
                SET password_hash = ?, updated_at = ?
                WHERE id = ?
            """, (new_password_hash, now, user_id))
            
            return cursor.rowcount > 0
    
    def update_last_login(self, user_id: int) -> bool:
        """
        Update last login timestamp
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                UPDATE users
                SET last_login = ?, failed_login_attempts = 0
                WHERE id = ?
            """, (now, user_id))
            
            return cursor.rowcount > 0
    
    def user_exists(self, email: str) -> bool:
        """
        Check if user exists
        
        Args:
            email: User email
            
        Returns:
            True if user exists
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email.lower(),))
            return cursor.fetchone()[0] > 0
    
    # Audit Logging
    
    def log_audit_event(self, user_id: Optional[int], event_type: str, 
                       ip_address: Optional[str], user_agent: Optional[str],
                       details: Optional[str] = None) -> None:
        """
        Log an audit event
        
        Args:
            user_id: User ID (can be None for failed login attempts)
            event_type: Type of event
            ip_address: IP address
            user_agent: User agent string
            details: Additional details (JSON string)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT INTO audit_log (user_id, event_type, ip_address, user_agent, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, event_type, ip_address, user_agent, details, now))
    
    # Backup and Maintenance
    
    def backup_database(self, backup_path: str) -> bool:
        """
        Create a backup of the database
        
        Args:
            backup_path: Path for backup file
            
        Returns:
            True if successful
        """
        try:
            import shutil
            
            # Ensure backup directory exists
            backup_dir = os.path.dirname(backup_path)
            if backup_dir and not os.path.exists(backup_dir):
                os.makedirs(backup_dir, exist_ok=True)
            
            # Create backup
            shutil.copy2(self.db_path, backup_path)
            return True
        except Exception as e:
            print(f"Backup failed: {e}")
            return False
    
    def vacuum_database(self) -> bool:
        """
        Vacuum database to reclaim space and optimize
        
        Returns:
            True if successful
        """
        try:
            with self.get_connection() as conn:
                conn.execute("VACUUM")
            return True
        except Exception as e:
            print(f"Vacuum failed: {e}")
            return False
