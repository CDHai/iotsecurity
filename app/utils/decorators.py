"""
Decorators for authentication, authorization, and other common functionality
"""

import functools
import time
from datetime import datetime, timedelta
from flask import request, jsonify, current_app, g
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from werkzeug.exceptions import Forbidden, Unauthorized
from typing import List, Optional, Callable, Any

from app.models.user import User

def require_auth(f):
    """Decorator to require authentication for web routes."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        from flask_login import current_user
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_api_auth(f):
    """Decorator to require JWT authentication for API routes."""
    @functools.wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'Invalid or inactive user'}), 401
        
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function

def require_role(required_role: str):
    """Decorator to require specific role for access."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            
            if not user:
                from flask_login import current_user
                user = current_user if current_user.is_authenticated else None
            
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not user.has_role(required_role):
                return jsonify({'error': f'Role {required_role} required'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_roles(required_roles: List[str]):
    """Decorator to require one of multiple roles for access."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            
            if not user:
                from flask_login import current_user
                user = current_user if current_user.is_authenticated else None
            
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not any(user.has_role(role) for role in required_roles):
                return jsonify({'error': f'One of these roles required: {required_roles}'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_permission(permission: str):
    """Decorator to require specific permission for access."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', None)
            
            if not user:
                from flask_login import current_user
                user = current_user if current_user.is_authenticated else None
            
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not user.can_access(permission):
                return jsonify({'error': f'Permission {permission} required'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Decorator to require admin role."""
    return require_role('admin')(f)

def tester_required(f):
    """Decorator to require tester or admin role."""
    return require_roles(['admin', 'tester'])(f)

def rate_limit(max_requests: int, window_seconds: int = 60, per_method: bool = False):
    """Rate limiting decorator."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory rate limiting (use Redis in production)
            if not hasattr(current_app, '_rate_limit_storage'):
                current_app._rate_limit_storage = {}
            
            # Create unique key for rate limiting
            if hasattr(g, 'current_user') and g.current_user:
                client_id = f"user_{g.current_user.id}"
            else:
                client_id = request.remote_addr
            
            method = request.method if per_method else 'ALL'
            key = f"{client_id}:{f.__name__}:{method}"
            
            now = time.time()
            window_start = now - window_seconds
            
            # Clean old entries and count requests in current window
            if key not in current_app._rate_limit_storage:
                current_app._rate_limit_storage[key] = []
            
            # Remove old timestamps
            current_app._rate_limit_storage[key] = [
                timestamp for timestamp in current_app._rate_limit_storage[key]
                if timestamp > window_start
            ]
            
            # Check if limit exceeded
            if len(current_app._rate_limit_storage[key]) >= max_requests:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'max_requests': max_requests,
                    'window_seconds': window_seconds
                }), 429
            
            # Add current request timestamp
            current_app._rate_limit_storage[key].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_json(schema_class=None):
    """Decorator to validate JSON input against schema."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            try:
                data = request.get_json()
                if data is None:
                    return jsonify({'error': 'Invalid JSON'}), 400
                
                if schema_class:
                    schema = schema_class()
                    validated_data = schema.load(data)
                    g.validated_data = validated_data
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': f'JSON validation failed: {str(e)}'}), 400
        return decorated_function
    return decorator

def log_activity(action: str, resource_type: str = None):
    """Decorator to log user activity."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = datetime.utcnow()
            
            try:
                result = f(*args, **kwargs)
                
                # Log successful activity
                user = getattr(g, 'current_user', None)
                if user:
                    current_app.logger.info(
                        f"User {user.username} performed {action} on {resource_type or 'resource'}"
                    )
                
                return result
            except Exception as e:
                # Log failed activity
                user = getattr(g, 'current_user', None)
                if user:
                    current_app.logger.error(
                        f"User {user.username} failed to perform {action} on {resource_type or 'resource'}: {str(e)}"
                    )
                raise
        return decorated_function
    return decorator

def cache_result(timeout_seconds: int = 300):
    """Simple caching decorator (use Redis in production)."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{f.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            
            if not hasattr(current_app, '_cache_storage'):
                current_app._cache_storage = {}
            
            now = time.time()
            
            # Check if cached result exists and is still valid
            if cache_key in current_app._cache_storage:
                cached_data, timestamp = current_app._cache_storage[cache_key]
                if now - timestamp < timeout_seconds:
                    return cached_data
            
            # Execute function and cache result
            result = f(*args, **kwargs)
            current_app._cache_storage[cache_key] = (result, now)
            
            return result
        return decorated_function
    return decorator

def measure_execution_time(f):
    """Decorator to measure and log execution time."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = f(*args, **kwargs)
            execution_time = time.time() - start_time
            
            current_app.logger.info(
                f"Function {f.__name__} executed in {execution_time:.3f} seconds"
            )
            
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            current_app.logger.error(
                f"Function {f.__name__} failed after {execution_time:.3f} seconds: {str(e)}"
            )
            raise
    return decorated_function

def handle_exceptions(default_response=None, status_code: int = 500):
    """Decorator to handle exceptions and return consistent error responses."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except ValueError as e:
                return jsonify({'error': f'Invalid input: {str(e)}'}), 400
            except KeyError as e:
                return jsonify({'error': f'Missing required field: {str(e)}'}), 400
            except Forbidden as e:
                return jsonify({'error': 'Access forbidden'}), 403
            except Unauthorized as e:
                return jsonify({'error': 'Authentication required'}), 401
            except Exception as e:
                current_app.logger.error(f"Unhandled exception in {f.__name__}: {str(e)}")
                
                if default_response:
                    return default_response, status_code
                
                return jsonify({'error': 'Internal server error'}), status_code
        return decorated_function
    return decorator

def require_content_type(content_type: str = 'application/json'):
    """Decorator to require specific content type."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if request.content_type != content_type:
                return jsonify({
                    'error': f'Content-Type must be {content_type}'
                }), 415
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def cors_headers(origin: str = '*', methods: List[str] = None, headers: List[str] = None):
    """Decorator to add CORS headers."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            
            # Handle both Response objects and tuples
            if isinstance(response, tuple):
                data, status_code = response
                response = jsonify(data), status_code
            
            if hasattr(response, 'headers'):
                response.headers['Access-Control-Allow-Origin'] = origin
                
                if methods:
                    response.headers['Access-Control-Allow-Methods'] = ', '.join(methods)
                
                if headers:
                    response.headers['Access-Control-Allow-Headers'] = ', '.join(headers)
            
            return response
        return decorated_function
    return decorator
