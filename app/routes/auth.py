from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User
from app.extensions import db
from app.utils.helpers import log_audit
from datetime import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.is_active and user.check_password(password):
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log login
            log_audit(user.id, 'LOGIN', 'User logged in')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    log_audit(current_user.id, 'LOGOUT', 'User logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# ==========================================================
# 🚀 NEW: User Registration for Analysts
# ==========================================================

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Allow new analysts to register"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip()
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html')
        
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        # Create analyst user
        user = User(
            username=username,
            email=email,
            role='analyst',
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        log_audit(user.id, 'REGISTER', f'New analyst registered: {username}')
        
        flash(f'✅ Account created successfully! Please login.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

# ==========================================================
# 🚀 NEW: Admin - Create User (Only for Admin)
# ==========================================================

@auth_bp.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    """Admin can create new users"""
    if not current_user.is_admin():
        flash('Access Denied! Only admins can create users.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'analyst')
        email = request.form.get('email', '').strip()
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters.', 'danger')
            return render_template('create_user.html', users=User.query.all())
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('create_user.html', users=User.query.all())
        
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('create_user.html', users=User.query.all())
        
        # Create user
        user = User(
            username=username,
            email=email,
            role=role,
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Log creation
        log_audit(current_user.id, 'CREATE_USER', f'Created user: {username} with role: {role}')
        
        flash(f'✅ User "{username}" created successfully with role: {role}', 'success')
        return redirect(url_for('auth.create_user'))
    
    # Get all users to display
    all_users = User.query.all()
    return render_template('create_user.html', users=all_users)

@auth_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Admin can delete users"""
    if not current_user.is_admin():
        flash('Access Denied!', 'danger')
        return redirect(url_for('main.dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting self
    if user.id == current_user.id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('auth.create_user'))
    
    # Prevent deleting last admin
    if user.role == 'admin':
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            flash('Cannot delete the last admin user!', 'danger')
            return redirect(url_for('auth.create_user'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    log_audit(current_user.id, 'DELETE_USER', f'Deleted user: {username}')
    flash(f'User "{username}" deleted successfully!', 'success')
    return redirect(url_for('auth.create_user'))