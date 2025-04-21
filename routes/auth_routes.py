from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, flash, current_app
from database import User, db  
from werkzeug.security import generate_password_hash, check_password_hash  
from functools import wraps


auth_bp = Blueprint('auth', __name__)


def login_required(f):
    from flask import redirect, url_for, session
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))  
        return f(*args, **kwargs)
    return decorated_function


from flask import request
import time

auth_bp = Blueprint('auth', __name__)

login_attempts = {}

@auth_bp.route('/api/login', methods=['POST'])
def login():
    global login_attempts
    ip = request.remote_addr
    now = time.time()
    window = 300  # 5 minutes
    max_attempts = 5

    login_attempts[ip] = [t for t in login_attempts.get(ip, []) if now - t < window]

    if len(login_attempts[ip]) >= max_attempts:
        retry_after = int(window - (now - login_attempts[ip][0]))
        return jsonify({'success': False, 'error': f'Too many login attempts. Please try again after {retry_after} seconds.'}), 429

    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
    else:
        username = request.form.get('username')
        password = request.form.get('password')

    # Default username to 'admin' 
    if not username:
        username = 'admin'

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        # Successful login, reset attempts
        login_attempts[ip] = []
        session.permanent = True  
        session['username'] = username
        session['user_id'] = user.id
        return jsonify({'success': True, 'redirect': url_for('dashboard.dashboard')})
    else:
        # Failed login, record attempt
        login_attempts.setdefault(ip, []).append(now)
        return jsonify({'success': False, 'error': 'Invalid username or password'}), 401

@auth_bp.route('/api/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

@auth_bp.route('/reset_password', methods=['GET'])
def reset_password_page():
    return render_template('reset_password.html')

@auth_bp.route('/reset_password.html', methods=['GET'])
def reset_password_html_redirect():
    return redirect(url_for('auth.reset_password_page'))

@auth_bp.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('newPassword')
    confirm_password = data.get('confirmPassword')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    if not new_password or not confirm_password:
        return jsonify({'error': 'Password fields are required'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    # Password strength validation
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
    if not any(c.isupper() for c in new_password):
        return jsonify({'error': 'Password must contain at least one uppercase letter'}), 400
    if not any(c.islower() for c in new_password):
        return jsonify({'error': 'Password must contain at least one lowercase letter'}), 400
    if not any(c.isdigit() for c in new_password):
        return jsonify({'error': 'Password must contain at least one digit'}), 400
    if not any(c in '!@#$%^&*(),.?":{}|<>' for c in new_password):
        return jsonify({'error': 'Password must contain at least one special character'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Password reset successfully'})
