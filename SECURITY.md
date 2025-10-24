# Security Design Documentation

## Architecture Overview

This secure login system implements multiple layers of security to protect user accounts and prevent common attack vectors.

## Authentication Flow

1. User registration with strong password requirements
2. Password hashing using bcrypt with salt
3. User login with optional MFA
4. Secure session creation and management

## Security Controls

### Password Security
- Minimum 12-character length
- Complexity requirements (uppercase, lowercase, numbers, special characters)
- bcrypt hashing with random salt
- Secure storage in database

### Account Protection
- Account lockout after 5 failed attempts
- 30-minute lock duration
- Failed attempt tracking

### Multi-Factor Authentication
- TOTP implementation (RFC 6238)
- QR code provisioning
- Time-based one-time passwords
- 30-second window for code validation

## Database Schema

### users table
- id: Primary key
- username: Unique identifier
- email: Contact information
- password_hash: Bcrypt-hashed password
- totp_secret: Base32-encoded TOTP secret
- failed_attempts: Counter for failed logins
- locked_until: Timestamp for account lock

## Session Management
- Random session tokens (32-byte URL-safe strings)
- 24-hour session expiration
- Session validation on each request
- Proper logout functionality

## Security Considerations for Production

While this system demonstrates secure principles, additional measures would be needed for production:

- HTTPS encryption
- Input validation and sanitization
- Rate limiting
- Monitoring and logging
- Regular security audits
- Password policies and rotation
- Account recovery mechanisms
