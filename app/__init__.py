import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from dotenv import load_dotenv
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
jwt = JWTManager()
mail = Mail()

def create_app():
    app = Flask(__name__, template_folder='templates')
    
    # Basic Config
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    
    # Email Config
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    
    # Initialize Extensions
    db.init_app(app)
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_recycle': 3600
    }
    
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    jwt.init_app(app)
    mail.init_app(app)

    # Register Blueprints
    from . import routes
    app.register_blueprint(routes.auth_bp)
    app.register_blueprint(routes.main_bp)
    app.register_blueprint(routes.api_bp, url_prefix='/api')

    # Create Tables & Default Admin User
    with app.app_context():
        from .models import User
        db.create_all()
        
        # Create default admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin')
            admin.set_password('admin123')
            admin.role = 'admin'
            db.session.add(admin)
            db.session.commit()
            print("✅ Detection Economics Engine is ready!")
            print("🔑 Default Login: admin / admin123")
            print("📧 Email Alerts & AI Learning Active!")

    return app