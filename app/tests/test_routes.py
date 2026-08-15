import pytest
from app import create_app
from app.extensions import db
from app.models import User, Rule

@pytest.fixture
def app():
    """Create and configure a test app instance"""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        # Create a test admin user
        admin = User(
            username='admin',
            email='admin@test.com',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client"""
    return app.test_client()

@pytest.fixture
def auth_client(client):
    """Create a logged-in test client"""
    client.post('/auth/login', data={
        'username': 'admin',
        'password': 'admin123'
    })
    return client

def test_login_page(client):
    """Test login page loads"""
    response = client.get('/auth/login')
    assert response.status_code == 200
    assert b'Login' in response.data

def test_login_success(client):
    """Test successful login"""
    response = client.post('/auth/login', data={
        'username': 'admin',
        'password': 'admin123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Dashboard' in response.data

def test_login_failure(client):
    """Test login failure"""
    response = client.post('/auth/login', data={
        'username': 'admin',
        'password': 'wrongpassword'
    })
    assert response.status_code == 200
    assert b'Invalid' in response.data

def test_dashboard_access_unauthorized(client):
    """Test dashboard requires login"""
    response = client.get('/')
    assert response.status_code == 302  # Redirect to login

def test_dashboard_access_authorized(auth_client):
    """Test dashboard loads for logged-in user"""
    response = auth_client.get('/')
    assert response.status_code == 200
    assert b'Dashboard' in response.data

def test_add_rule_page(auth_client):
    """Test add rule page loads for admin"""
    response = auth_client.get('/add_rule')
    assert response.status_code == 200
    assert b'Add' in response.data

def test_add_rule_submit(auth_client):
    """Test submitting a new rule"""
    data = {
        'name': 'Test Rule',
        'category': 'Authentication',
        'severity': 'High',
        'mitre_technique': 'T1110',
        'description': 'Test description',
        'priority': 2,
        'attack_frequency': 'Common',
        'asset_criticality': 'High',
        'detection_accuracy': 95.0,
        'false_positive_rate': 3.0,
        'maintenance_hours': 2.0
    }
    response = auth_client.post('/add_rule', data=data, follow_redirects=True)
    assert response.status_code == 200
    assert b'added' in response.data

def test_rule_listing(auth_client):
    """Test rules are listed on dashboard"""
    # First, add a rule
    data = {
        'name': 'Test Rule',
        'category': 'Authentication',
        'severity': 'High',
        'attack_frequency': 'Common',
        'asset_criticality': 'High',
        'detection_accuracy': 95.0,
        'false_positive_rate': 3.0,
        'maintenance_hours': 2.0
    }
    auth_client.post('/add_rule', data=data)
    
    # Check dashboard for rule
    response = auth_client.get('/')
    assert response.status_code == 200
    assert b'Test Rule' in response.data

def test_investigate_page(auth_client):
    """Test investigation page loads"""
    # Create a rule first
    rule = Rule(
        name='Test Rule',
        category='Authentication',
        severity='High',
        attack_frequency='Common',
        asset_criticality='High'
    )
    with auth_client.application.app_context():
        db.session.add(rule)
        db.session.commit()
        rule_id = rule.id
    
    response = auth_client.get(f'/investigate/{rule_id}')
    assert response.status_code == 200
    assert b'Investigating' in response.data

def test_reports_page(auth_client):
    """Test reports page loads"""
    response = auth_client.get('/reports')
    assert response.status_code == 200
    assert b'Reports' in response.data

def test_audit_logs_page(auth_client):
    """Test audit logs page loads for admin"""
    response = auth_client.get('/audit_logs')
    assert response.status_code == 200
    assert b'Audit' in response.data

def test_my_investigations(auth_client):
    """Test my investigations page loads"""
    response = auth_client.get('/my_investigations')
    assert response.status_code == 200
    assert b'Activity' in response.data

def test_logout(auth_client):
    """Test logout functionality"""
    response = auth_client.get('/auth/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data

def test_api_health(client):
    """Test API health endpoint"""
    response = client.get('/api/health')
    assert response.status_code == 200
    assert b'healthy' in response.data

def test_api_stats_unauthorized(client):
    """Test API stats requires authentication"""
    response = client.get('/api/stats')
    assert response.status_code == 401  # Unauthorized