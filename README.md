# Secure Login System with Multi-Factor Authentication

A secure authentication system demonstrating modern cybersecurity practices including password security, account lockout mechanisms, and multi-factor authentication.

![Secure Login System Screenshot](screenshots)

## Features

✅ **Password Security**
- Passwords hashed with bcrypt
- 12+ character requirement
- Complexity validation (uppercase, lowercase, numbers, special characters)
- Secure storage practices

🔒 **Account Protection**
- Account lockout after 5 failed attempts (30-minute lock)
- Failed attempt tracking
- Rate limiting protection

📱 **Multi-Factor Authentication (MFA)**
- TOTP-based authentication (RFC 6238)
- QR code provisioning for authenticator apps
- Google Authenticator/MS Authenticator compatible
- Session persistence

🛡️ **Session Security**
- Secure session tokens
- 24-hour session expiration
- Proper logout functionality
- Session validation on each request

