"""
Assessment model for security assessment management
"""

import json
from datetime import datetime
from app import db

class Assessment(db.Model):
    """Model representing a security assessment of an IoT device."""
    
    __tablename__ = 'assessments'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign keys
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    test_suite_id = db.Column(db.Integer, db.ForeignKey('test_suites.id'), nullable=True)
    
    # Assessment metadata
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Assessment status and progress
    status = db.Column(db.Enum('pending', 'running', 'completed', 'failed', 'cancelled',
                              name='assessment_status'), default='pending', nullable=False)
    progress_percentage = db.Column(db.Integer, default=0)
    
    # Assessment configuration
    scan_type = db.Column(db.Enum('quick', 'standard', 'comprehensive', 'custom',
                                 name='scan_types'), default='standard')
    target_protocols = db.Column(db.Text, nullable=True)  # JSON array
    custom_tests = db.Column(db.Text, nullable=True)      # JSON array of test IDs
    
    # Results and scoring
    total_tests = db.Column(db.Integer, default=0)
    passed_tests = db.Column(db.Integer, default=0)
    failed_tests = db.Column(db.Integer, default=0)
    error_tests = db.Column(db.Integer, default=0)
    skipped_tests = db.Column(db.Integer, default=0)
    
    risk_score = db.Column(db.Float, default=0.0)
    security_grade = db.Column(db.Enum('A', 'B', 'C', 'D', 'F', name='security_grades'),
                              nullable=True)
    
    # Vulnerability summary
    critical_vulns = db.Column(db.Integer, default=0)
    high_vulns = db.Column(db.Integer, default=0)
    medium_vulns = db.Column(db.Integer, default=0)
    low_vulns = db.Column(db.Integer, default=0)
    info_vulns = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Additional data
    scan_options = db.Column(db.Text, nullable=True)  # JSON object
    error_message = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    test_results = db.relationship('TestResult', backref='assessment', lazy='dynamic',
                                  cascade='all, delete-orphan')
    
    def __init__(self, device_id, user_id, name, **kwargs):
        """Initialize assessment."""
        self.device_id = device_id
        self.user_id = user_id
        self.name = name
        
        # Set additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @property
    def target_protocols_list(self):
        """Get target protocols as Python list."""
        if self.target_protocols:
            try:
                return json.loads(self.target_protocols)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @target_protocols_list.setter
    def target_protocols_list(self, protocols):
        """Set target protocols from Python list."""
        if isinstance(protocols, list):
            self.target_protocols = json.dumps(protocols)
        else:
            self.target_protocols = None
    
    @property
    def custom_tests_list(self):
        """Get custom tests as Python list."""
        if self.custom_tests:
            try:
                return json.loads(self.custom_tests)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @custom_tests_list.setter
    def custom_tests_list(self, tests):
        """Set custom tests from Python list."""
        if isinstance(tests, list):
            self.custom_tests = json.dumps(tests)
        else:
            self.custom_tests = None
    
    @property
    def scan_options_dict(self):
        """Get scan options as Python dictionary."""
        if self.scan_options:
            try:
                return json.loads(self.scan_options)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    @scan_options_dict.setter
    def scan_options_dict(self, options):
        """Set scan options from Python dictionary."""
        if isinstance(options, dict):
            self.scan_options = json.dumps(options)
        else:
            self.scan_options = None
    
    @property
    def duration(self):
        """Calculate assessment duration."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        elif self.started_at:
            return datetime.utcnow() - self.started_at
        return None
    
    @property
    def total_vulnerabilities(self):
        """Get total number of vulnerabilities found."""
        return (self.critical_vulns + self.high_vulns + self.medium_vulns + 
                self.low_vulns + self.info_vulns)
    
    def start_assessment(self):
        """Mark assessment as started."""
        self.status = 'running'
        self.started_at = datetime.utcnow()
        self.progress_percentage = 0
        db.session.commit()
    
    def complete_assessment(self, success=True):
        """Mark assessment as completed."""
        if success:
            self.status = 'completed'
        else:
            self.status = 'failed'
        
        self.completed_at = datetime.utcnow()
        self.progress_percentage = 100
        
        # Update device's last assessment
        if self.device:
            self.device.last_assessment = self.completed_at
            self.device.vulnerability_count = self.total_vulnerabilities
            self.device.update_risk_level()
        
        db.session.commit()
    
    def update_progress(self, percentage):
        """Update assessment progress."""
        self.progress_percentage = min(100, max(0, percentage))
        db.session.commit()
    
    def calculate_risk_score(self):
        """Calculate risk score based on vulnerabilities found."""
        # Weighted scoring system
        weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        total_score = (
            self.critical_vulns * weights['critical'] +
            self.high_vulns * weights['high'] +
            self.medium_vulns * weights['medium'] +
            self.low_vulns * weights['low'] +
            self.info_vulns * weights['info']
        )
        
        # Normalize to 0-100 scale (assuming max 20 critical vulns as 100)
        max_possible_score = 20 * weights['critical']
        self.risk_score = min(100.0, (total_score / max_possible_score) * 100)
        
        # Assign security grade
        if self.risk_score >= 80:
            self.security_grade = 'F'
        elif self.risk_score >= 60:
            self.security_grade = 'D'
        elif self.risk_score >= 40:
            self.security_grade = 'C'
        elif self.risk_score >= 20:
            self.security_grade = 'B'
        else:
            self.security_grade = 'A'
        
        db.session.commit()
    
    def add_test_result(self, test_result):
        """Add a test result and update counters."""
        if test_result.status == 'pass':
            self.passed_tests += 1
        elif test_result.status == 'fail':
            self.failed_tests += 1
            # Update vulnerability counters if vulnerability found
            if test_result.vulnerability:
                severity = test_result.vulnerability.severity
                if severity == 'critical':
                    self.critical_vulns += 1
                elif severity == 'high':
                    self.high_vulns += 1
                elif severity == 'medium':
                    self.medium_vulns += 1
                elif severity == 'low':
                    self.low_vulns += 1
                elif severity == 'info':
                    self.info_vulns += 1
        elif test_result.status == 'error':
            self.error_tests += 1
        elif test_result.status == 'skip':
            self.skipped_tests += 1
        
        self.total_tests += 1
        self.calculate_risk_score()
    
    def to_dict(self, include_results=False):
        """Convert assessment to dictionary representation."""
        data = {
            'id': self.id,
            'device_id': self.device_id,
            'user_id': self.user_id,
            'test_suite_id': self.test_suite_id,
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'progress_percentage': self.progress_percentage,
            'scan_type': self.scan_type,
            'target_protocols': self.target_protocols_list,
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'error_tests': self.error_tests,
            'skipped_tests': self.skipped_tests,
            'risk_score': self.risk_score,
            'security_grade': self.security_grade,
            'critical_vulns': self.critical_vulns,
            'high_vulns': self.high_vulns,
            'medium_vulns': self.medium_vulns,
            'low_vulns': self.low_vulns,
            'info_vulns': self.info_vulns,
            'total_vulnerabilities': self.total_vulnerabilities,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': str(self.duration) if self.duration else None,
            'error_message': self.error_message,
            'notes': self.notes
        }
        
        if include_results:
            data['test_results'] = [result.to_dict() for result in self.test_results]
        
        return data
    
    @classmethod
    def get_recent_assessments(cls, limit=10):
        """Get recent assessments."""
        return cls.query.order_by(cls.created_at.desc()).limit(limit).all()
    
    @classmethod
    def get_assessments_by_device(cls, device_id):
        """Get assessments for a specific device."""
        return cls.query.filter_by(device_id=device_id).order_by(cls.created_at.desc()).all()
    
    @classmethod
    def get_assessments_by_user(cls, user_id):
        """Get assessments by a specific user."""
        return cls.query.filter_by(user_id=user_id).order_by(cls.created_at.desc()).all()
    
    @classmethod
    def get_running_assessments(cls):
        """Get currently running assessments."""
        return cls.query.filter_by(status='running').all()
    
    def __repr__(self):
        return f'<Assessment {self.name} ({self.status})>'
