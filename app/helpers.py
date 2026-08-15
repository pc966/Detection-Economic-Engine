import json
from flask import request, current_app
from datetime import datetime
from app.extensions import db
from app.models import AuditLog

def register_template_filters(app):
    """Register custom Jinja2 filters"""
    
    @app.template_filter('from_json')
    def from_json_filter(value):
        if value:
            try:
                return json.loads(value)
            except:
                return []
        return []
    
    @app.template_filter('format_datetime')
    def format_datetime_filter(value):
        if value:
            return value.strftime('%Y-%m-%d %H:%M:%S')
        return ''
    
    @app.template_filter('truncate_text')
    def truncate_text_filter(value, length=50):
        if value and len(value) > length:
            return value[:length] + '...'
        return value
    
    @app.template_filter('json')
    def json_filter(value):
        return json.dumps(value)

def log_audit(user_id, action, description):
    """Helper to create audit logs"""
    try:
        audit = AuditLog(
            user_id=user_id,
            action=action,
            description=description,
            ip_address=request.remote_addr if request else '127.0.0.1',
            user_agent=request.headers.get('User-Agent', 'Unknown') if request else 'System'
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log audit: {e}")

def format_datetime(dt):
    """Format datetime for display"""
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return ''

def truncate_text(text, length=100):
    """Truncate text to specified length"""
    if text and len(text) > length:
        return text[:length] + '...'
    return text