from flask_login import UserMixin
from app import db, login_manager
from datetime import datetime
import bcrypt

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='analyst') # 'admin' or 'analyst'

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    # Relationships
    investigations = db.relationship('Investigation', backref='analyst', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True) 

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    
    # Real SOC Fields
    category = db.Column(db.String(50), default='General')
    severity = db.Column(db.String(20), default='Medium')
    mitre_technique = db.Column(db.String(50), default='N/A')
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

    investigations = db.relationship('Investigation', backref='rule', lazy=True, cascade="all, delete-orphan")

class Investigation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'))
    analyst_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    steps = db.Column(db.Text) 
    resolution = db.Column(db.String(50))
    time_spent = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Playbook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    steps = db.Column(db.Text) # JSON string of steps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==========================================================
# 🚀 NEW: Audit Log Model (For tracking user activity)
# ==========================================================
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ==========================================================
# 🚀 NEW: User Profile Model (For future enhancements)
# ==========================================================
class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    bio = db.Column(db.String(200))
    last_active = db.Column(db.DateTime, default=datetime.utcnow)