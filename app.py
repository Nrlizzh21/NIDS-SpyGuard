from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, flash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from matplotlib import colors
from flask_migrate import Migrate
from database import db, User
import joblib
import pandas as pd
import numpy as np
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

print("Starting Flask app from app.py")


app = Flask(__name__)
app.secret_key = 'SpyGu@rD'  
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nids_spyguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set session timeout to 10 minutes as per user request
app.permanent_session_lifetime = timedelta(minutes=10)


# Initialize CSRF protection
csrf = CSRFProtect(app)


db.init_app(app)
migrate = Migrate(app, db)

# Create default admin user 
with app.app_context():
    try:
        existing_admin = User.query.filter_by(username='admin').first()
        if not existing_admin:
            admin_user = User(username='admin', password='spyguard1&')  
            db.session.add(admin_user)
            db.session.commit()
    except Exception as e:
        print(f"Warning: Could not create default admin user: {e}")

# Load saved model, scaler, and label encoders
model = joblib.load('models/rf_model.pkl')
scaler = joblib.load('models/scaler.pkl')
encoders = joblib.load('models/label_encoders.pkl')

categorical_columns = ['protocol_type', 'service', 'flag']

# Define all feature columns expected by the model 
feature_columns = [
    "duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

# Importing route blueprints
from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.about_routes import about_bp
from routes.faqs_routes import faqs_bp
from routes.history_routes import history_bp
from routes.upload_routes import upload_bp

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(about_bp)
app.register_blueprint(faqs_bp)
app.register_blueprint(history_bp)
app.register_blueprint(upload_bp)

# Exempt API routes from CSRF protection
csrf.exempt(auth_bp)
csrf.exempt(upload_bp)
csrf.exempt(history_bp)

import logging

@app.before_request
def session_management():
    if request.endpoint in ('auth.login', 'auth.logout') or request.path.startswith('/static/'):
        return

    logging.info(f"Session contents before request: {dict(session)}")
    logging.info(f"Last activity before request: {session.get('last_activity')}")

    session.permanent = True
    session.modified = True

    now = datetime.now(timezone.utc)
    last_activity = session.get('last_activity')

    if last_activity:
        if isinstance(last_activity, str):
            try:
                last_activity = datetime.fromisoformat(last_activity)
            except ValueError:
                last_activity = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S.%f")
        if (now - last_activity) > app.permanent_session_lifetime:
            session.clear()
            flash('Session timed out due to inactivity. Please log in again.')
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Session timed out. Please log in again.'}), 401
            else:
                return redirect(url_for('index'))

    session['last_activity'] = now.isoformat()

from flask_wtf.csrf import CSRFError

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({'success': False, 'error': 'CSRF token missing or invalid.'}), 400

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
