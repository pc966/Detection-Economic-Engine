from datetime import datetime
from flask_login import UserMixin
from app.extensions import db, login_manager
import bcrypt
import json

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='analyst')
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), 
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode('utf-8'), 
            self.password_hash.encode('utf-8')
        )
    
    def is_admin(self):
        return self.role == 'admin'
    
    # Relationships
    investigations = db.relationship('Investigation', backref='analyst', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    profile = db.relationship('UserProfile', backref='user', uselist=False, lazy=True)

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True)
    bio = db.Column(db.String(500))
    department = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    avatar_url = db.Column(db.String(255))

class Rule(db.Model):
    __tablename__ = 'rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    
    # Real SOC Fields
    category = db.Column(db.String(50), default='General')
    severity = db.Column(db.String(20), default='Medium')
    mitre_technique = db.Column(db.String(50), default='N/A')
    mitre_tactic = db.Column(db.String(50), default='N/A')
    description = db.Column(db.Text, default='No description provided')
    priority = db.Column(db.Integer, default=3)
    last_alert_date = db.Column(db.DateTime, nullable=True)
    alert_count = db.Column(db.Integer, default=0)
    
    # Economics Fields
    attack_frequency = db.Column(db.String(20), default='Common')
    asset_criticality = db.Column(db.String(20), default='High')
    detection_accuracy = db.Column(db.Float, default=90.0)
    false_positive_rate = db.Column(db.Float, default=5.0)
    maintenance_hours = db.Column(db.Float, default=2.0)
    
    # Calculated Fields
    score = db.Column(db.Float, default=0.0)
    recommendation = db.Column(db.String(20), default='Monitor')
    email_sent = db.Column(db.Boolean, default=False)
    flag_for_review = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigations = db.relationship('Investigation', backref='rule', lazy=True, cascade="all, delete-orphan")

class Investigation(db.Model):
    __tablename__ = 'investigations'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rules.id'))
    analyst_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    steps = db.Column(db.Text)
    resolution = db.Column(db.String(50))
    time_spent = db.Column(db.Float)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_steps(self):
        if self.steps:
            return json.loads(self.steps)
        return []

    def set_steps(self, steps_list):
        self.steps = json.dumps(steps_list)

class Playbook(db.Model):
    __tablename__ = 'playbooks'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    description = db.Column(db.Text)
    steps = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_steps(self):
        if self.steps:
            return json.loads(self.steps)
        return []

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)