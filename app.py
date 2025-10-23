from flask import Flask, request, render_template, redirect, url_for, session, flash, send_file
import pyotp
import qrcode
from io import BytesIO
from auth import AuthService
from models import db

app = Flask(__name__)
app.secret_key = 'your-super-secret-key-change-this-in-production'

# Rate limiting (simplified)
login_attempts = {}

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        success, message = AuthService.register_user(username, email, password)
        if success:
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form.get('totp_code')
        
        # Check rate limiting
        ip_address = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        if ip_address in login_attempts:
            if login_attempts[ip_address]['count'] > 5:
                flash('Too many login attempts. Please try again later.', 'error')
                return render_template('login.html')
        
        success, message = AuthService.authenticate_user(username, password, totp_code)
        
        if success:
            # Reset rate limiting
            if ip_address in login_attempts:
                del login_attempts[ip_address]
            
            # Get user and create session
            user = db.get_user_by_username(username)
            session_token = db.create_session(user['id'])
            
            # Store session token in secure cookie
            session['session_token'] = session_token
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            db.log_login_attempt(username, ip_address, True)
            return redirect(url_for('dashboard'))
        else:
            # Update rate limiting
            if ip_address not in login_attempts:
                login_attempts[ip_address] = {'count': 1}
            else:
                login_attempts[ip_address]['count'] += 1
            
            db.log_login_attempt(username, ip_address, False)
            flash(message, 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session_token = session.get('session_token')
    if session_token:
        AuthService.logout(session_token)
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Validate session
    session_token = session.get('session_token')
    if not AuthService.validate_session(session_token):
        session.clear()
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    user = db.get_user_by_id(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/setup-mfa')
def setup_mfa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Generate new TOTP secret
    totp_secret = AuthService.generate_totp_secret()
    session['totp_secret'] = totp_secret
    
    # Generate QR code for authenticator app
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        session['username'],
        issuer_name="Secure Login System"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return render_template('mfa_setup.html', qr_code_data=img_io.getvalue(), totp_secret=totp_secret)

@app.route('/confirm-mfa', methods=['POST'])
def confirm_mfa():
    if 'user_id' not in session or 'totp_secret' not in session:
        return redirect(url_for('login'))
    
    totp_code = request.form['totp_code']
    
    if AuthService.verify_totp_code(session['totp_secret'], totp_code):
        # Save TOTP secret to user account
        db.update_totp_secret(session['user_id'], session['totp_secret'])
        session.pop('totp_secret', None)
        flash('Multi-factor authentication enabled successfully!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid TOTP code. Please try again.', 'error')
        return redirect(url_for('setup_mfa'))

@app.route('/qr-code')
def qr_code():
    if 'totp_secret' not in session:
        return '', 404
    
    totp_uri = pyotp.totp.TOTP(session['totp_secret']).provisioning_uri(
        session['username'],
        issuer_name="Secure Login System"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
