# Secure Login System with Multi-Factor Authentication

A secure authentication system demonstrating modern cybersecurity practices including password security, account lockout mechanisms, and multi-factor authentication.

![Secure Login System Screenshot](screenshots/login.png)

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

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-login-system.git
cd secure-login-system

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install Flask bcrypt pyotp qrcode Pillow

# Run the application
python app.py
