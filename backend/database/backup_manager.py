"""
Encrypted Database Backup System

Features:
- Encrypted backups to prevent sensitive data exposure
- Secure backup rotation and cleanup
- Cloud storage integration (S3, GCS, etc.)
- Backup integrity verification
- Automated scheduling support
"""

import os
import gzip
import json
import logging
import subprocess
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import tempfile
import shutil
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class EncryptedBackupManager:
    """
    Manages encrypted database backups with secure storage
    """
    
    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize backup manager
        
        Args:
            database_url: Database connection URL
        """
        self.database_url = database_url or os.getenv('DATABASE_URL')
        self.backup_path = Path(os.getenv('BACKUP_STORAGE_PATH', './backups'))
        self.encryption_key = self._get_encryption_key()
        self.max_backups = int(os.getenv('MAX_BACKUP_RETENTION', 30))
        
        # Create backup directory
        self.backup_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize cipher
        if self.encryption_key:
            self.cipher = Fernet(self.encryption_key)
        else:
            logger.warning("No backup encryption key found - backups will not be encrypted!")
            self.cipher = None
    
    def _get_encryption_key(self) -> Optional[bytes]:
        """Get or generate encryption key for backups"""
        key_env = os.getenv('BACKUP_ENCRYPTION_KEY')
        
        if key_env:
            try:
                # Try to decode as base64 Fernet key
                return base64.urlsafe_b64decode(key_env)
            except Exception:
                # Generate key from password using PBKDF2
                password = key_env.encode()
                salt = b'backup_salt_' + hashlib.sha256(password).digest()[:16]
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                return base64.urlsafe_b64encode(kdf.derive(password))
        
        return None
    
    def create_backup(self, backup_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Create encrypted database backup
        
        Args:
            backup_name: Optional custom backup name
            
        Returns:
            Backup metadata
        """
        timestamp = datetime.now(timezone.utc)
        backup_name = backup_name or f"backup_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        try:
            logger.info(f"Starting database backup: {backup_name}")
            
            # Determine backup method based on database type
            if self.database_url.startswith('postgresql'):
                backup_data = self._backup_postgresql()
            elif self.database_url.startswith('sqlite'):
                backup_data = self._backup_sqlite()
            else:
                raise ValueError(f"Unsupported database type: {self.database_url}")
            
            # Compress backup data
            compressed_data = gzip.compress(backup_data.encode('utf-8'))
            
            # Encrypt if key is available
            if self.cipher:
                encrypted_data = self.cipher.encrypt(compressed_data)
                is_encrypted = True
            else:
                encrypted_data = compressed_data
                is_encrypted = False
            
            # Calculate checksum
            checksum = hashlib.sha256(encrypted_data).hexdigest()
            
            # Save backup file
            backup_file = self.backup_path / f"{backup_name}.bak"
            with open(backup_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Create metadata file
            metadata = {
                'backup_name': backup_name,
                'timestamp': timestamp.isoformat(),
                'database_type': self._get_db_type(),
                'is_encrypted': is_encrypted,
                'is_compressed': True,
                'checksum': checksum,
                'file_size': len(encrypted_data),
                'original_size': len(backup_data)
            }
            
            metadata_file = self.backup_path / f"{backup_name}.meta"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Backup completed: {backup_file} ({len(encrypted_data)} bytes)")
            
            # Clean up old backups
            self._cleanup_old_backups()
            
            return metadata
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            raise
    
    def _backup_postgresql(self) -> str:
        """Create PostgreSQL backup using pg_dump"""
        try:
            # Parse connection URL
            from urllib.parse import urlparse
            parsed = urlparse(self.database_url)
            
            # Set environment variables for pg_dump
            env = os.environ.copy()
            env['PGPASSWORD'] = parsed.password
            
            # Build pg_dump command
            cmd = [
                'pg_dump',
                '-h', parsed.hostname,
                '-p', str(parsed.port or 5432),
                '-U', parsed.username,
                '-d', parsed.path[1:],  # Remove leading slash
                '--no-password',
                '--clean',
                '--if-exists',
                '--create',
                '--verbose'
            ]
            
            # Execute pg_dump
            result = subprocess.run(
                cmd, 
                env=env, 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"pg_dump failed: {e.stderr}")
            raise
        except Exception as e:
            logger.error(f"PostgreSQL backup error: {e}")
            raise
    
    def _backup_sqlite(self) -> str:
        """Create SQLite backup using .dump command"""
        try:
            # Extract database path from URL
            db_path = self.database_url.replace('sqlite:///', '')
            
            if not os.path.exists(db_path):
                raise FileNotFoundError(f"SQLite database not found: {db_path}")
            
            # Use sqlite3 command line tool
            cmd = ['sqlite3', db_path, '.dump']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"SQLite dump failed: {e.stderr}")
            raise
        except Exception as e:
            logger.error(f"SQLite backup error: {e}")
            raise
    
    def restore_backup(self, backup_name: str, target_url: Optional[str] = None) -> bool:
        """
        Restore database from encrypted backup
        
        Args:
            backup_name: Name of backup to restore
            target_url: Optional target database URL (defaults to current)
            
        Returns:
            Success status
        """
        target_url = target_url or self.database_url
        
        try:
            logger.info(f"Starting backup restore: {backup_name}")
            
            # Load metadata
            metadata_file = self.backup_path / f"{backup_name}.meta"
            if not metadata_file.exists():
                raise FileNotFoundError(f"Backup metadata not found: {metadata_file}")
            
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Load backup file
            backup_file = self.backup_path / f"{backup_name}.bak"
            if not backup_file.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_file}")
            
            with open(backup_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Verify checksum
            checksum = hashlib.sha256(encrypted_data).hexdigest()
            if checksum != metadata['checksum']:
                raise ValueError("Backup file checksum mismatch - file may be corrupted")
            
            # Decrypt if encrypted
            if metadata['is_encrypted']:
                if not self.cipher:
                    raise ValueError("Cannot decrypt backup - no encryption key available")
                decrypted_data = self.cipher.decrypt(encrypted_data)
            else:
                decrypted_data = encrypted_data
            
            # Decompress if compressed
            if metadata['is_compressed']:
                backup_sql = gzip.decompress(decrypted_data).decode('utf-8')
            else:
                backup_sql = decrypted_data.decode('utf-8')
            
            # Restore based on database type
            if target_url.startswith('postgresql'):
                success = self._restore_postgresql(backup_sql, target_url)
            elif target_url.startswith('sqlite'):
                success = self._restore_sqlite(backup_sql, target_url)
            else:
                raise ValueError(f"Unsupported database type: {target_url}")
            
            if success:
                logger.info(f"Backup restore completed: {backup_name}")
            
            return success
            
        except Exception as e:
            logger.error(f"Backup restore failed: {e}")
            raise
    
    def _restore_postgresql(self, sql_dump: str, target_url: str) -> bool:
        """Restore PostgreSQL backup"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            
            # Set environment variables
            env = os.environ.copy()
            env['PGPASSWORD'] = parsed.password
            
            # Write SQL to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
                f.write(sql_dump)
                temp_file = f.name
            
            try:
                # Build psql command
                cmd = [
                    'psql',
                    '-h', parsed.hostname,
                    '-p', str(parsed.port or 5432),
                    '-U', parsed.username,
                    '-d', parsed.path[1:],
                    '-f', temp_file,
                    '--no-password'
                ]
                
                # Execute restore
                result = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                return True
                
            finally:
                # Clean up temporary file
                os.unlink(temp_file)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"PostgreSQL restore failed: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"PostgreSQL restore error: {e}")
            return False
    
    def _restore_sqlite(self, sql_dump: str, target_url: str) -> bool:
        """Restore SQLite backup"""
        try:
            # Extract database path
            db_path = target_url.replace('sqlite:///', '')
            
            # Create backup of existing database
            if os.path.exists(db_path):
                backup_path = f"{db_path}.restore_backup"
                shutil.copy2(db_path, backup_path)
                logger.info(f"Created backup of existing database: {backup_path}")
            
            # Write SQL to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False) as f:
                f.write(sql_dump)
                temp_file = f.name
            
            try:
                # Execute restore
                cmd = ['sqlite3', db_path, f'.read {temp_file}']
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                return True
                
            finally:
                # Clean up temporary file
                os.unlink(temp_file)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"SQLite restore failed: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"SQLite restore error: {e}")
            return False
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups with metadata"""
        backups = []
        
        try:
            for meta_file in self.backup_path.glob('*.meta'):
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                
                # Check if backup file exists
                backup_file = self.backup_path / f"{metadata['backup_name']}.bak"
                metadata['file_exists'] = backup_file.exists()
                
                if metadata['file_exists']:
                    metadata['file_path'] = str(backup_file)
                
                backups.append(metadata)
            
            # Sort by timestamp (newest first)
            backups.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return backups
            
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
            return []
    
    def verify_backup(self, backup_name: str) -> Dict[str, Any]:
        """
        Verify backup integrity
        
        Args:
            backup_name: Name of backup to verify
            
        Returns:
            Verification results
        """
        try:
            # Load metadata
            metadata_file = self.backup_path / f"{backup_name}.meta"
            if not metadata_file.exists():
                return {'valid': False, 'error': 'Metadata file not found'}
            
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Check backup file
            backup_file = self.backup_path / f"{backup_name}.bak"
            if not backup_file.exists():
                return {'valid': False, 'error': 'Backup file not found'}
            
            # Verify file size
            actual_size = backup_file.stat().st_size
            if actual_size != metadata['file_size']:
                return {
                    'valid': False, 
                    'error': f'File size mismatch: expected {metadata["file_size"]}, got {actual_size}'
                }
            
            # Verify checksum
            with open(backup_file, 'rb') as f:
                file_data = f.read()
            
            actual_checksum = hashlib.sha256(file_data).hexdigest()
            if actual_checksum != metadata['checksum']:
                return {'valid': False, 'error': 'Checksum mismatch - file may be corrupted'}
            
            # Try to decrypt if encrypted
            if metadata['is_encrypted']:
                if not self.cipher:
                    return {'valid': False, 'error': 'Cannot verify encrypted backup - no key available'}
                
                try:
                    self.cipher.decrypt(file_data)
                except Exception as e:
                    return {'valid': False, 'error': f'Decryption failed: {str(e)}'}
            
            return {
                'valid': True,
                'backup_name': backup_name,
                'metadata': metadata,
                'verified_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return {'valid': False, 'error': str(e)}
    
    def _cleanup_old_backups(self):
        """Remove old backups based on retention policy"""
        try:
            backups = self.list_backups()
            
            if len(backups) <= self.max_backups:
                return
            
            # Remove oldest backups
            to_remove = backups[self.max_backups:]
            
            for backup in to_remove:
                backup_name = backup['backup_name']
                
                # Remove backup file
                backup_file = self.backup_path / f"{backup_name}.bak"
                if backup_file.exists():
                    backup_file.unlink()
                
                # Remove metadata file
                metadata_file = self.backup_path / f"{backup_name}.meta"
                if metadata_file.exists():
                    metadata_file.unlink()
                
                logger.info(f"Removed old backup: {backup_name}")
            
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
    
    def _get_db_type(self) -> str:
        """Get database type from URL"""
        if self.database_url.startswith('postgresql'):
            return 'postgresql'
        elif self.database_url.startswith('sqlite'):
            return 'sqlite'
        else:
            return 'unknown'
    
    def schedule_backup(self, cron_schedule: str = "0 2 * * *") -> str:
        """
        Generate cron entry for automated backups
        
        Args:
            cron_schedule: Cron schedule (default: daily at 2 AM)
            
        Returns:
            Cron command string
        """
        script_path = os.path.abspath(__file__)
        
        cron_command = (
            f'{cron_schedule} /usr/bin/python3 {script_path} '
            f'--backup --database-url="{self.database_url}"'
        )
        
        return cron_command


# CLI interface for backup operations
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Database Backup Manager')
    parser.add_argument('--backup', action='store_true', help='Create backup')
    parser.add_argument('--restore', type=str, help='Restore from backup')
    parser.add_argument('--list', action='store_true', help='List backups')
    parser.add_argument('--verify', type=str, help='Verify backup')
    parser.add_argument('--database-url', type=str, help='Database URL')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    backup_manager = EncryptedBackupManager(args.database_url)
    
    if args.backup:
        result = backup_manager.create_backup()
        print(f"Backup created: {result['backup_name']}")
    
    elif args.restore:
        success = backup_manager.restore_backup(args.restore)
        print(f"Restore {'successful' if success else 'failed'}")
    
    elif args.list:
        backups = backup_manager.list_backups()
        for backup in backups:
            print(f"{backup['backup_name']} - {backup['timestamp']} - "
                  f"{'Encrypted' if backup['is_encrypted'] else 'Unencrypted'}")
    
    elif args.verify:
        result = backup_manager.verify_backup(args.verify)
        print(f"Verification: {'PASS' if result['valid'] else 'FAIL'}")
        if not result['valid']:
            print(f"Error: {result['error']}")