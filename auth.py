import bcrypt
import pyotp
import re
import secrets
from models import db

class AuthService:
    @staticmethod
    def validate_password_strength(password):
        """Validate password meets security requirements"""
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    @staticmethod
    def register_user(username, email, password):
        """Register a new user with secure password handling"""
        # Validate password strength
        is_valid, message = AuthService.validate_password_strength(password)
        if not is_valid:
            return False, message
        
        # Create user in database
        user_id = db.create_user(username, email, password)
        if user_id:
            return True, "User registered successfully"
        else:
            return False, "Username or email already exists"
    
    @staticmethod
    def authenticate_user(username, password, totp_code=None):
        """Authenticate user with password and optional TOTP"""
        # Check if account is locked
        if db.is_account_locked(username):
            return False, "Account is temporarily locked due to too many failed attempts"
        
        # Get user from database
        user = db.get_user_by_username(username)
        if not user:
            return False, "Invalid username or password"
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            db.increment_failed_attempts(username)
            return False, "Invalid username or password"
        
        # Check if MFA is required
        if user['totp_secret']:
            if not totp_code:
                return False, "TOTP code required"
            
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(totp_code):
                db.increment_failed_attempts(username)
                return False, "Invalid TOTP code"
        
        # Reset failed attempts on successful login
        db.reset_failed_attempts(username)
        return True, "Authentication successful"
    
    @staticmethod
    def generate_totp_secret():
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def verify_totp_code(secret, code):
        """Verify TOTP code"""
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    
    @staticmethod
    def validate_session(session_token):
        """Validate session token"""
        user = db.get_user_by_session(session_token)
        return user is not None
    
    @staticmethod
    def logout(session_token):
        """Logout user by deleting session"""
        db.delete_session(session_token)
