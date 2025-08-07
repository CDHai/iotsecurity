"""
Test Suite model for organizing security tests
"""

import json
from datetime import datetime
from app import db

class TestSuite(db.Model):
    """Model representing a collection of security tests."""
    
    __tablename__ = 'test_suites'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Suite metadata
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    version = db.Column(db.String(20), default='1.0', nullable=False)
    
    # Suite configuration
    device_types = db.Column(db.Text, nullable=True)  # JSON array of applicable device types
    protocols = db.Column(db.Text, nullable=True)     # JSON array of protocols
    category = db.Column(db.Enum('basic', 'standard', 'comprehensive', 'specialized',
                               name='suite_categories'), default='standard')
    
    # Suite status and metadata
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    execution_order = db.Column(db.Integer, default=0)  # Order of test execution
    
    # Authorship and timestamps
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Suite statistics
    total_tests = db.Column(db.Integer, default=0)
    estimated_duration = db.Column(db.Integer, default=0)  # in seconds
    
    # Configuration and settings
    timeout_settings = db.Column(db.Text, nullable=True)  # JSON object
    retry_settings = db.Column(db.Text, nullable=True)    # JSON object
    
    # Relationships
    security_tests = db.relationship('SecurityTest', backref='test_suite', lazy='dynamic',
                                   cascade='all, delete-orphan')
    assessments = db.relationship('Assessment', backref='test_suite', lazy='dynamic')
    
    def __init__(self, name, **kwargs):
        """Initialize test suite."""
        self.name = name
        
        # Set additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @property
    def device_types_list(self):
        """Get device types as Python list."""
        if self.device_types:
            try:
                return json.loads(self.device_types)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @device_types_list.setter
    def device_types_list(self, types):
        """Set device types from Python list."""
        if isinstance(types, list):
            self.device_types = json.dumps(types)
        else:
            self.device_types = None
    
    @property
    def protocols_list(self):
        """Get protocols as Python list."""
        if self.protocols:
            try:
                return json.loads(self.protocols)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @protocols_list.setter
    def protocols_list(self, protocols):
        """Set protocols from Python list."""
        if isinstance(protocols, list):
            self.protocols = json.dumps(protocols)
        else:
            self.protocols = None
    
    @property
    def timeout_settings_dict(self):
        """Get timeout settings as Python dictionary."""
        if self.timeout_settings:
            try:
                return json.loads(self.timeout_settings)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    @timeout_settings_dict.setter
    def timeout_settings_dict(self, settings):
        """Set timeout settings from Python dictionary."""
        if isinstance(settings, dict):
            self.timeout_settings = json.dumps(settings)
        else:
            self.timeout_settings = None
    
    @property
    def retry_settings_dict(self):
        """Get retry settings as Python dictionary."""
        if self.retry_settings:
            try:
                return json.loads(self.retry_settings)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    @retry_settings_dict.setter
    def retry_settings_dict(self, settings):
        """Set retry settings from Python dictionary."""
        if isinstance(settings, dict):
            self.retry_settings = json.dumps(settings)
        else:
            self.retry_settings = None
    
    def is_applicable_to_device(self, device):
        """Check if this test suite is applicable to a device."""
        if not self.device_types_list:
            return True  # No restrictions
        
        return device.device_type in self.device_types_list
    
    def supports_protocol(self, protocol):
        """Check if this test suite supports a specific protocol."""
        if not self.protocols_list:
            return True  # No restrictions
        
        return protocol in self.protocols_list
    
    def get_tests_by_type(self, test_type):
        """Get tests filtered by type."""
        return self.security_tests.filter_by(test_type=test_type).all()
    
    def get_tests_by_severity(self, severity):
        """Get tests filtered by severity."""
        return self.security_tests.filter_by(severity=severity).all()
    
    def get_active_tests(self):
        """Get all active tests in this suite."""
        return self.security_tests.filter_by(is_active=True).order_by('execution_order').all()
    
    def update_statistics(self):
        """Update suite statistics based on tests."""
        active_tests = self.get_active_tests()
        self.total_tests = len(active_tests)
        self.estimated_duration = sum(test.estimated_duration or 30 for test in active_tests)
        db.session.commit()
    
    def add_test(self, security_test):
        """Add a security test to this suite."""
        security_test.test_suite_id = self.id
        db.session.add(security_test)
        self.update_statistics()
    
    def remove_test(self, test_id):
        """Remove a security test from this suite."""
        test = self.security_tests.filter_by(id=test_id).first()
        if test:
            db.session.delete(test)
            self.update_statistics()
    
    def clone_suite(self, new_name, user_id):
        """Create a copy of this test suite."""
        new_suite = TestSuite(
            name=new_name,
            description=f"Cloned from {self.name}: {self.description}",
            version="1.0",
            device_types=self.device_types,
            protocols=self.protocols,
            category=self.category,
            created_by=user_id,
            timeout_settings=self.timeout_settings,
            retry_settings=self.retry_settings
        )
        
        db.session.add(new_suite)
        db.session.flush()  # Get the ID
        
        # Clone all tests
        for test in self.security_tests:
            new_test = SecurityTest(
                name=test.name,
                description=test.description,
                test_type=test.test_type,
                severity=test.severity,
                payload=test.payload,
                expected_result=test.expected_result,
                test_suite_id=new_suite.id,
                execution_order=test.execution_order
            )
            db.session.add(new_test)
        
        new_suite.update_statistics()
        db.session.commit()
        
        return new_suite
    
    def to_dict(self, include_tests=False):
        """Convert test suite to dictionary representation."""
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'device_types': self.device_types_list,
            'protocols': self.protocols_list,
            'category': self.category,
            'is_active': self.is_active,
            'is_default': self.is_default,
            'execution_order': self.execution_order,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'total_tests': self.total_tests,
            'estimated_duration': self.estimated_duration,
            'timeout_settings': self.timeout_settings_dict,
            'retry_settings': self.retry_settings_dict
        }
        
        if include_tests:
            data['tests'] = [test.to_dict() for test in self.get_active_tests()]
        
        return data
    
    @classmethod
    def get_default_suites(cls):
        """Get default test suites."""
        return cls.query.filter_by(is_default=True, is_active=True).all()
    
    @classmethod
    def get_suites_for_device_type(cls, device_type):
        """Get test suites applicable to a device type."""
        suites = cls.query.filter_by(is_active=True).all()
        applicable_suites = []
        
        for suite in suites:
            if not suite.device_types_list or device_type in suite.device_types_list:
                applicable_suites.append(suite)
        
        return applicable_suites
    
    @classmethod
    def get_suites_by_category(cls, category):
        """Get test suites by category."""
        return cls.query.filter_by(category=category, is_active=True).all()
    
    @classmethod
    def create_default_suites(cls):
        """Create default test suites."""
        default_suites = [
            {
                'name': 'Basic IoT Security',
                'description': 'Basic security tests for IoT devices',
                'category': 'basic',
                'is_default': True,
                'device_types_list': ['camera', 'sensor', 'switch', 'lock'],
                'protocols_list': ['http', 'https']
            },
            {
                'name': 'Comprehensive IoT Assessment',
                'description': 'Comprehensive security assessment for IoT devices',
                'category': 'comprehensive',
                'is_default': True,
                'device_types_list': [],  # Applies to all
                'protocols_list': ['http', 'https', 'mqtt', 'coap']
            },
            {
                'name': 'Smart Camera Security',
                'description': 'Specialized tests for IP cameras and surveillance devices',
                'category': 'specialized',
                'device_types_list': ['camera', 'nvr', 'dvr'],
                'protocols_list': ['http', 'https', 'rtsp']
            }
        ]
        
        for suite_data in default_suites:
            if not cls.query.filter_by(name=suite_data['name']).first():
                suite = cls(**suite_data)
                db.session.add(suite)
        
        db.session.commit()
    
    def __repr__(self):
        return f'<TestSuite {self.name}>'
