"""
Authentication API endpoints
"""

from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt
)
from werkzeug.security import check_password_hash

from app import db, jwt
from app.models.user import User
from app.utils.validators import validate_user_data
from app.utils.decorators import (
    handle_exceptions, rate_limit, validate_json, 
    require_content_type, log_activity
)

auth_api_bp = Blueprint('auth_api', __name__)

# JWT token blacklist (use Redis in production)
blacklisted_tokens = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Check if JWT token is blacklisted."""
    jti = jwt_payload['jti']
    return jti in blacklisted_tokens

@auth_api_bp.route('/register', methods=['POST'])
@require_content_type('application/json')
@validate_json()
@rate_limit(max_requests=5, window_seconds=300)
@handle_exceptions()
@log_activity('register', 'user')
def register():
    """Register a new user."""
    data = request.get_json()
    
    try:
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate password confirmation
        if data.get('password') != data.get('password_confirm'):
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Validate user data
        validated_data = validate_user_data(data)
        
        # Create user (default role is 'viewer')
        user = User.create_user(**validated_data)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@auth_api_bp.route('/login', methods=['POST'])
@require_content_type('application/json')
@validate_json()
@rate_limit(max_requests=5, window_seconds=300)
@handle_exceptions()
@log_activity('login', 'user')
def login():
    """Authenticate user and return JWT tokens."""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Authenticate user
    user = User.authenticate(username, password)
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 401
    
    # Create JWT tokens
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'role': user.role}
    )
    refresh_token = create_refresh_token(identity=user.id)
    
    # Update last login
    user.update_last_login()
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict(),
        'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
    }), 200

@auth_api_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@handle_exceptions()
def refresh():
    """Refresh access token using refresh token."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_active:
        return jsonify({'error': 'Invalid user'}), 401
    
    # Create new access token
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'role': user.role}
    )
    
    return jsonify({
        'access_token': access_token,
        'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
    }), 200

@auth_api_bp.route('/logout', methods=['POST'])
@jwt_required()
@handle_exceptions()
@log_activity('logout', 'user')
def logout():
    """Logout user by blacklisting current token."""
    jti = get_jwt()['jti']
    blacklisted_tokens.add(jti)
    
    return jsonify({'message': 'Successfully logged out'}), 200

@auth_api_bp.route('/profile', methods=['GET'])
@jwt_required()
@handle_exceptions()
def get_profile():
    """Get current user profile."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'user': user.to_dict()}), 200

@auth_api_bp.route('/profile', methods=['PUT'])
@jwt_required()
@require_content_type('application/json')
@validate_json()
@handle_exceptions()
@log_activity('update_profile', 'user')
def update_profile():
    """Update current user profile."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    try:
        # Update allowed fields
        allowed_fields = ['full_name', 'email', 'organization']
        for field in allowed_fields:
            if field in data:
                setattr(user, field, data[field])
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Profile update error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500

@auth_api_bp.route('/change-password', methods=['POST'])
@jwt_required()
@require_content_type('application/json')
@validate_json()
@rate_limit(max_requests=3, window_seconds=300)
@handle_exceptions()
@log_activity('change_password', 'user')
def change_password():
    """Change user password."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new passwords are required'}), 400
    
    # Verify current password
    if not user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    # Validate new password
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters long'}), 400
    
    try:
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Password change error: {str(e)}")
        return jsonify({'error': 'Failed to change password'}), 500

@auth_api_bp.route('/verify-token', methods=['GET'])
@jwt_required()
@handle_exceptions()
def verify_token():
    """Verify JWT token validity."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_active:
        return jsonify({'error': 'Invalid token'}), 401
    
    claims = get_jwt()
    
    return jsonify({
        'valid': True,
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'expires_at': claims['exp']
    }), 200

@auth_api_bp.route('/users', methods=['GET'])
@jwt_required()
@handle_exceptions()
def list_users():
    """List all users (admin only)."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.has_role('admin'):
        return jsonify({'error': 'Administrator privileges required'}), 403
    
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    role_filter = request.args.get('role')
    active_only = request.args.get('active_only', 'false').lower() == 'true'
    search = request.args.get('search', '').strip()
    
    # Build query
    query = User.query
    
    if role_filter:
        query = query.filter(User.role == role_filter)
    
    if active_only:
        query = query.filter(User.is_active == True)
    
    if search:
        search_pattern = f'%{search}%'
        query = query.filter(
            db.or_(
                User.username.like(search_pattern),
                User.email.like(search_pattern),
                User.full_name.like(search_pattern)
            )
        )
    
    # Paginate results
    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    users = [user.to_dict() for user in pagination.items]
    
    return jsonify({
        'users': users,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
    }), 200

@auth_api_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
@handle_exceptions()
def get_user(user_id):
    """Get user details (admin only or own profile)."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Users can view their own profile, admins can view any profile
    if user_id != current_user_id and not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'user': user.to_dict(include_sensitive=current_user.has_role('admin'))}), 200

@auth_api_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@jwt_required()
@require_content_type('application/json')
@validate_json()
@handle_exceptions()
@log_activity('change_user_role', 'user')
def change_user_role(user_id):
    """Change user role (admin only)."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.has_role('admin'):
        return jsonify({'error': 'Administrator privileges required'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    new_role = data.get('role')
    
    if new_role not in ['admin', 'tester', 'viewer']:
        return jsonify({'error': 'Invalid role. Must be admin, tester, or viewer'}), 400
    
    # Prevent changing own admin role
    if user_id == current_user_id and new_role != 'admin':
        return jsonify({'error': 'Cannot change your own admin role'}), 400
    
    try:
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        current_app.logger.info(f"Admin {current_user.username} changed user {user.username} role from {old_role} to {new_role}")
        
        return jsonify({
            'message': f'User role changed from {old_role} to {new_role}',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Role change error: {str(e)}")
        return jsonify({'error': 'Failed to change user role'}), 500

@auth_api_bp.route('/users/<int:user_id>/status', methods=['PUT'])
@jwt_required()
@require_content_type('application/json')
@validate_json()
@handle_exceptions()
@log_activity('toggle_user_status', 'user')
def toggle_user_status(user_id):
    """Toggle user active status (admin only)."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.has_role('admin'):
        return jsonify({'error': 'Administrator privileges required'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Prevent disabling own account
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot disable your own account'}), 400
    
    data = request.get_json()
    is_active = data.get('is_active')
    
    if is_active is None:
        return jsonify({'error': 'is_active field is required'}), 400
    
    try:
        user.is_active = bool(is_active)
        db.session.commit()
        
        status = 'activated' if user.is_active else 'deactivated'
        current_app.logger.info(f"Admin {current_user.username} {status} user {user.username}")
        
        return jsonify({
            'message': f'User {status} successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Status toggle error: {str(e)}")
        return jsonify({'error': 'Failed to change user status'}), 500

# Error handlers for auth API
@auth_api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Resource not found'}), 404

@auth_api_bp.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    return jsonify({'error': 'Access forbidden'}), 403

@auth_api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500
