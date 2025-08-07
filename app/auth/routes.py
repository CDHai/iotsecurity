"""
Authentication routes for web interface
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from urllib.parse import urlparse, urljoin

from app import db
from app.models.user import User
from app.utils.validators import validate_user_data
from app.utils.decorators import handle_exceptions, rate_limit

auth_bp = Blueprint('auth', __name__)

def is_safe_url(target):
    """Check if redirect URL is safe."""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
@handle_exceptions()
def login():
    """User login page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = bool(request.form.get('remember_me'))
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('auth/login.html')
        
        # Authenticate user
        user = User.authenticate(username, password)
        
        if user:
            if not user.is_active:
                flash('Your account has been disabled. Please contact administrator.', 'error')
                return render_template('auth/login.html')
            
            # Log user in
            login_user(user, remember=remember_me)
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if not next_page or not is_safe_url(next_page):
                next_page = url_for('dashboard.index')
            
            flash(f'Welcome back, {user.full_name or user.username}!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout."""
    username = current_user.username
    logout_user()
    flash(f'You have been logged out successfully, {username}.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@handle_exceptions()
def register():
    """User registration page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        try:
            # Get form data
            form_data = {
                'username': request.form.get('username', '').strip(),
                'email': request.form.get('email', '').strip(),
                'password': request.form.get('password', ''),
                'full_name': request.form.get('full_name', '').strip(),
                'organization': request.form.get('organization', '').strip()
            }
            
            # Validate password confirmation
            password_confirm = request.form.get('password_confirm', '')
            if form_data['password'] != password_confirm:
                flash('Passwords do not match.', 'error')
                return render_template('auth/register.html', form_data=form_data)
            
            # Validate form data
            validated_data = validate_user_data(form_data)
            
            # Create user
            user = User.create_user(**validated_data)
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('auth/register.html', form_data=form_data)
        except Exception as e:
            flash('Registration failed. Please try again.', 'error')
            return render_template('auth/register.html', form_data=form_data)
    
    return render_template('auth/register.html')

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@handle_exceptions()
def profile():
    """User profile page."""
    if request.method == 'POST':
        try:
            # Update profile data
            current_user.full_name = request.form.get('full_name', '').strip()
            current_user.email = request.form.get('email', '').strip()
            current_user.organization = request.form.get('organization', '').strip()
            
            # Update password if provided
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if new_password:
                if not current_password:
                    flash('Current password is required to change password.', 'error')
                    return render_template('auth/profile.html')
                
                if not current_user.check_password(current_password):
                    flash('Current password is incorrect.', 'error')
                    return render_template('auth/profile.html')
                
                if new_password != confirm_password:
                    flash('New passwords do not match.', 'error')
                    return render_template('auth/profile.html')
                
                if len(new_password) < 8:
                    flash('New password must be at least 8 characters long.', 'error')
                    return render_template('auth/profile.html')
                
                current_user.set_password(new_password)
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash('Failed to update profile. Please try again.', 'error')
    
    return render_template('auth/profile.html')

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@handle_exceptions()
def change_password():
    """Change password page."""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            return render_template('auth/change_password.html')
        
        # Validate new password
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
            return render_template('auth/change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('auth/change_password.html')
        
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('auth.profile'))
    
    return render_template('auth/change_password.html')

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@rate_limit(max_requests=3, window_seconds=300)
@handle_exceptions()
def forgot_password():
    """Forgot password page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Email address is required.', 'error')
            return render_template('auth/forgot_password.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.is_active:
            # In a real application, send password reset email
            # For demo purposes, we'll just show a message
            flash('If an account with that email exists, password reset instructions have been sent.', 'info')
        else:
            # Don't reveal whether user exists or not
            flash('If an account with that email exists, password reset instructions have been sent.', 'info')
        
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')

@auth_bp.route('/users')
@login_required
@handle_exceptions()
def list_users():
    """List all users (admin only)."""
    if not current_user.has_role('admin'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('dashboard.index'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('auth/users.html', users=users)

@auth_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@handle_exceptions()
def toggle_user_status(user_id):
    """Toggle user active status (admin only)."""
    if not current_user.has_role('admin'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('dashboard.index'))
    
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot disable your own account.', 'error')
        return redirect(url_for('auth.list_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}.', 'success')
    
    return redirect(url_for('auth.list_users'))

@auth_bp.route('/users/<int:user_id>/change-role', methods=['POST'])
@login_required
@handle_exceptions()
def change_user_role(user_id):
    """Change user role (admin only)."""
    if not current_user.has_role('admin'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('dashboard.index'))
    
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if new_role not in ['admin', 'tester', 'viewer']:
        flash('Invalid role specified.', 'error')
        return redirect(url_for('auth.list_users'))
    
    if user.id == current_user.id and new_role != 'admin':
        flash('You cannot change your own admin role.', 'error')
        return redirect(url_for('auth.list_users'))
    
    old_role = user.role
    user.role = new_role
    db.session.commit()
    
    flash(f'User {user.username} role changed from {old_role} to {new_role}.', 'success')
    return redirect(url_for('auth.list_users'))

# Error handlers for auth blueprint
@auth_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('errors/404.html'), 404

@auth_bp.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    return render_template('errors/403.html'), 403

@auth_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    db.session.rollback()
    return render_template('errors/500.html'), 500
