"""
User model for authentication and authorization
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from app import db

class User(UserMixin, db.Model):
    """User model for authentication and role-based access control."""
    
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User credentials
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # User profile
    full_name = db.Column(db.String(100), nullable=True)
    organization = db.Column(db.String(100), nullable=True)
    
    # Role and permissions
    role = db.Column(db.Enum('admin', 'tester', 'viewer', name='user_roles'), 
                     default='viewer', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    assessments = db.relationship('Assessment', backref='user', lazy='dynamic', 
                                 cascade='all, delete-orphan')
    test_suites = db.relationship('TestSuite', backref='creator', lazy='dynamic',
                                 foreign_keys='TestSuite.created_by')
    
    def __init__(self, username, email=None, password=None, **kwargs):
        """Initialize user with required fields."""
        self.username = username
        self.email = email
        if password:
            self.set_password(password)
        
        # Set additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def set_password(self, password):
        """Hash and set user password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash."""
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        """Check if user has specific role."""
        return self.role == role
    
    def can_access(self, resource):
        """Check if user can access specific resource based on role."""
        role_permissions = {
            'admin': ['read', 'write', 'delete', 'manage_users', 'system_config'],
            'tester': ['read', 'write', 'run_assessments', 'view_reports'],
            'viewer': ['read', 'view_reports']
        }
        
        permissions = role_permissions.get(self.role, [])
        return resource in permissions
    
    def update_last_login(self):
        """Update last login timestamp."""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary representation."""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'organization': self.organization,
            'role': self.role,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
        
        if include_sensitive:
            data['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        
        return data
    
    @classmethod
    def create_user(cls, username, email, password, role='viewer', **kwargs):
        """Create new user with validation."""
        # Check if username exists
        if cls.query.filter_by(username=username).first():
            raise ValueError(f"Username '{username}' already exists")
        
        # Check if email exists
        if email and cls.query.filter_by(email=email).first():
            raise ValueError(f"Email '{email}' already exists")
        
        # Create user
        user = cls(username=username, email=email, password=password, role=role, **kwargs)
        db.session.add(user)
        db.session.commit()
        
        return user
    
    @classmethod
    def authenticate(cls, username, password):
        """Authenticate user with username/password."""
        user = cls.query.filter_by(username=username, is_active=True).first()
        if user and user.check_password(password):
            user.update_last_login()
            return user
        return None
    
    def __repr__(self):
        return f'<User {self.username}>'
