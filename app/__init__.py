import os
from flask import Flask, render_template
from dotenv import load_dotenv
from app.extensions import db, login_manager, jwt, mail, migrate
from app.utils.helpers import register_template_filters

load_dotenv()

def create_app(config_object=None):
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///detection_economics.db')
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Session Security
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv('PERMANENT_SESSION_LIFETIME', 86400))
    
    # Email Config
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['MAIL_SUPPRESS_SEND'] = os.getenv('MAIL_SUPPRESS_SEND', 'False') == 'True'
    
    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    
    # Register Template Filters
    register_template_filters(app)
    
    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.api import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Error Handlers
    register_error_handlers(app)
    
    # Create Tables
    with app.app_context():
        db.create_all()
        create_default_admin(app)
        create_default_playbooks()
    
    return app

def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

def create_default_admin(app):
    """Create default admin user if it doesn't exist"""
    from app.models import User, AuditLog
    
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
    
    if not User.query.filter_by(username=admin_username).first():
        admin = User(
            username=admin_username,
            role='admin',
            is_active=True
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        
        # Log admin creation
        audit = AuditLog(
            user_id=admin.id,
            action='SYSTEM_INIT',
            description=f'Default admin user "{admin_username}" created',
            ip_address='127.0.0.1',
            user_agent='System'
        )
        db.session.add(audit)
        db.session.commit()
        
        print("✅ Detection Economics Engine is ready!")
        print(f"🔑 Default Login: {admin_username} / {admin_password}")
        print("📧 Email Alerts & AI Learning Active!")

def create_default_playbooks():
    """Create default playbooks if they don't exist"""
    from app.models import Playbook
    import json
    
    if Playbook.query.count() == 0:
        default_playbooks = [
            Playbook(
                name="Ransomware Response",
                category="Malware/Ransomware",
                description="Standard response for ransomware incidents",
                steps=json.dumps([
                    "Isolate affected host from network",
                    "Identify ransomware variant",
                    "Check for encrypted files",
                    "Restore from known good backups",
                    "Notify CISO and incident response team",
                    "Document findings and lessons learned"
                ])
            ),
            Playbook(
                name="Brute Force Mitigation",
                category="Authentication",
                description="Response to brute force login attempts",
                steps=json.dumps([
                    "Identify source IP(s)",
                    "Block IP on firewall",
                    "Check for successful logins from blocked IPs",
                    "Force password reset for affected accounts",
                    "Enable MFA for affected accounts",
                    "Monitor for lateral movement"
                ])
            ),
            Playbook(
                name="Data Exfiltration Response",
                category="Data Loss Prevention",
                description="Response to potential data exfiltration",
                steps=json.dumps([
                    "Identify data being exfiltrated",
                    "Block outbound traffic to suspicious destinations",
                    "Check for compromised credentials",
                    "Review data access logs",
                    "Notify data owners and legal team",
                    "Implement additional DLP controls"
                ])
            )
        ]
        db.session.add_all(default_playbooks)
        db.session.commit()
        print("✅ Default playbooks created.")
