from flask import jsonify, request, current_app
from flask_login import login_required, current_user
from app.api import api_bp
from app.models import User
from app.models.user import UserRole
from app import db

@api_bp.route('/auth/register', methods=['POST'])
def register():
    """Register new user"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'viewer')
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password are required'
            }), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({
                'success': False,
                'error': 'Username already exists'
            }), 400
        
        # Validate role
        try:
            user_role = UserRole(role)
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Invalid role'
            }), 400
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password=password,
            role=user_role
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'data': user.to_dict()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error registering user: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to register user'
        }), 500

@api_bp.route('/auth/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    try:
        return jsonify({
            'success': True,
            'data': current_user.to_dict()
        })
    except Exception as e:
        current_app.logger.error(f"Error getting profile: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get profile'
        }), 500

@api_bp.route('/auth/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update current user profile"""
    try:
        data = request.get_json()
        
        # Update allowed fields
        if 'email' in data:
            current_user.email = data['email']
        
        if 'password' in data:
            current_user.set_password(data['password'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'data': current_user.to_dict()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error updating profile: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to update profile'
        }), 500

@api_bp.route('/auth/users', methods=['GET'])
@login_required
def get_users():
    """Get list of users (admin only)"""
    try:
        if not current_user.is_admin():
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        users = User.query.all()
        
        return jsonify({
            'success': True,
            'data': [user.to_dict() for user in users]
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting users: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get users'
        }), 500

@api_bp.route('/auth/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update user (admin only)"""
    try:
        if not current_user.is_admin():
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        # Update allowed fields
        if 'email' in data:
            user.email = data['email']
        
        if 'role' in data:
            try:
                user.role = UserRole(data['role'])
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid role'
                }), 400
        
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'data': user.to_dict()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error updating user {user_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to update user'
        }), 500

@api_bp.route('/auth/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        if not current_user.is_admin():
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        if current_user.id == user_id:
            return jsonify({
                'success': False,
                'error': 'Cannot delete yourself'
            }), 400
        
        user = User.query.get_or_404(user_id)
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete user'
        }), 500
