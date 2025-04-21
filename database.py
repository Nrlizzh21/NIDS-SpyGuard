from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    predictions = db.relationship('Prediction', backref='user', lazy=True)
    uploads = db.relationship('Upload', backref='user', lazy=True)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    processing_time = db.Column(db.Float, default=0.0)
    dos_count = db.Column(db.Integer, default=0)
    normal_count = db.Column(db.Integer, default=0)
    probe_count = db.Column(db.Integer, default=0)
    r2l_count = db.Column(db.Integer, default=0)
    u2r_count = db.Column(db.Integer, default=0)
    unknown_count = db.Column(db.Integer, default=0)
    total_predictions = db.Column(db.Integer, default=0)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_id = db.Column(db.Integer, db.ForeignKey('upload.id'), nullable=True)
    row_number = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.Float, nullable=True)
    protocol_type = db.Column(db.Integer, nullable=True)
    service = db.Column(db.Integer, nullable=True)
    src_bytes = db.Column(db.Integer, nullable=True)
    dst_bytes = db.Column(db.Integer, nullable=True)
    prediction = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    upload = db.relationship('Upload', backref='predictions')


