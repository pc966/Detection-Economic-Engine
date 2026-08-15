import pytest
from app import create_app
from app.extensions import db
from app.models import User, Rule, Investigation, AuditLog, Playbook

@pytest.fixture
def app():
    """Create and configure a test app instance"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client"""
    return app.test_client()

@pytest.fixture
def test_user(app):
    """Create a test user"""
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            role='analyst'
        )
        user.set_password('testpass123')
        db.session.add(user)
        db.session.commit()
        return user

def test_user_creation(app, test_user):
    """Test user creation and password hashing"""
    assert test_user.username == 'testuser'
    assert test_user.email == 'test@example.com'
    assert test_user.role == 'analyst'
    assert test_user.check_password('testpass123') is True
    assert test_user.check_password('wrongpass') is False

def test_user_is_admin(app, test_user):
    """Test admin role checking"""
    assert test_user.is_admin() is False
    
    # Create admin user
    with app.app_context():
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        assert admin.is_admin() is True

def test_rule_creation(app):
    """Test rule creation and scoring"""
    with app.app_context():
        rule = Rule(
            name='Test Rule',
            category='Authentication',
            severity='High',
            mitre_technique='T1110',
            attack_frequency='Common',
            asset_criticality='High',
            detection_accuracy=95.0,
            false_positive_rate=3.0,
            maintenance_hours=2.0
        )
        db.session.add(rule)
        db.session.commit()
        
        assert rule.id is not None
        assert rule.name == 'Test Rule'
        assert rule.score == 0.0  # Score calculated by service

def test_investigation_creation(app, test_user):
    """Test investigation creation"""
    with app.app_context():
        rule = Rule(
            name='Test Rule',
            category='Authentication',
            severity='High'
        )
        db.session.add(rule)
        db.session.commit()
        
        investigation = Investigation(
            rule_id=rule.id,
            analyst_id=test_user.id,
            steps='["Check logs", "Block IP"]',
            resolution='True_Positive',
            time_spent=30.0
        )
        db.session.add(investigation)
        db.session.commit()
        
        assert investigation.id is not None
        assert investigation.rule_id == rule.id
        assert investigation.analyst_id == test_user.id
        assert investigation.resolution == 'True_Positive'

def test_audit_log_creation(app, test_user):
    """Test audit log creation"""
    with app.app_context():
        audit = AuditLog(
            user_id=test_user.id,
            action='LOGIN',
            description='User logged in',
            ip_address='127.0.0.1',
            user_agent='Test Agent'
        )
        db.session.add(audit)
        db.session.commit()
        
        assert audit.id is not None
        assert audit.user_id == test_user.id
        assert audit.action == 'LOGIN'

def test_playbook_creation(app):
    """Test playbook creation"""
    with app.app_context():
        playbook = Playbook(
            name='Test Playbook',
            category='Authentication',
            description='Test description',
            steps='["Step 1", "Step 2"]'
        )
        db.session.add(playbook)
        db.session.commit()
        
        assert playbook.id is not None
        assert playbook.name == 'Test Playbook'
        assert playbook.get_steps() == ['Step 1', 'Step 2']