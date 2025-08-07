"""
Security Test model for individual test definitions
"""

import json
from datetime import datetime
from app import db

class SecurityTest(db.Model):
    """Model representing an individual security test."""
    
    __tablename__ = 'security_tests'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key
    test_suite_id = db.Column(db.Integer, db.ForeignKey('test_suites.id'), nullable=False)
    
    # Test metadata
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    test_type = db.Column(db.Enum('credential', 'protocol', 'web', 'network', 'firmware',
                                 name='test_types'), nullable=False)
    
    # Test severity and classification
    severity = db.Column(db.Enum('info', 'low', 'medium', 'high', 'critical',
                                name='test_severity'), nullable=False)
    category = db.Column(db.String(50), nullable=True)  # e.g., 'authentication', 'encryption'
    
    # Test execution details
    payload = db.Column(db.Text, nullable=True)           # Test payload/script
    expected_result = db.Column(db.Text, nullable=True)   # Expected test result
    validation_rules = db.Column(db.Text, nullable=True)  # JSON validation rules
    
    # Test configuration
    timeout = db.Column(db.Integer, default=30)           # Test timeout in seconds
    retry_count = db.Column(db.Integer, default=1)        # Number of retries
    execution_order = db.Column(db.Integer, default=0)    # Order within suite
    estimated_duration = db.Column(db.Integer, default=30) # Estimated duration in seconds
    
    # Test status and metadata
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    requires_authentication = db.Column(db.Boolean, default=False)
    is_destructive = db.Column(db.Boolean, default=False)  # May affect device operation
    
    # Dependencies and prerequisites
    prerequisites = db.Column(db.Text, nullable=True)     # JSON array of required conditions
    dependencies = db.Column(db.Text, nullable=True)      # JSON array of dependent test IDs
    
    # CVE and vulnerability mappings
    cve_mappings = db.Column(db.Text, nullable=True)      # JSON array of related CVEs
    vulnerability_references = db.Column(db.Text, nullable=True)  # JSON array of vuln IDs
    
    # Timestamps and authorship
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Test statistics
    success_rate = db.Column(db.Float, default=0.0)       # Historical success rate
    execution_count = db.Column(db.Integer, default=0)    # Number of times executed
    
    # Additional metadata
    tags = db.Column(db.Text, nullable=True)              # JSON array of tags
    notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    test_results = db.relationship('TestResult', backref='security_test', lazy='dynamic')
    
    def __init__(self, name, test_type, severity, **kwargs):
        """Initialize security test."""
        self.name = name
        self.test_type = test_type
        self.severity = severity
        
        # Set additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @property
    def validation_rules_dict(self):
        """Get validation rules as Python dictionary."""
        if self.validation_rules:
            try:
                return json.loads(self.validation_rules)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    @validation_rules_dict.setter
    def validation_rules_dict(self, rules):
        """Set validation rules from Python dictionary."""
        if isinstance(rules, dict):
            self.validation_rules = json.dumps(rules)
        else:
            self.validation_rules = None
    
    @property
    def prerequisites_list(self):
        """Get prerequisites as Python list."""
        if self.prerequisites:
            try:
                return json.loads(self.prerequisites)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @prerequisites_list.setter
    def prerequisites_list(self, prereqs):
        """Set prerequisites from Python list."""
        if isinstance(prereqs, list):
            self.prerequisites = json.dumps(prereqs)
        else:
            self.prerequisites = None
    
    @property
    def dependencies_list(self):
        """Get dependencies as Python list."""
        if self.dependencies:
            try:
                return json.loads(self.dependencies)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @dependencies_list.setter
    def dependencies_list(self, deps):
        """Set dependencies from Python list."""
        if isinstance(deps, list):
            self.dependencies = json.dumps(deps)
        else:
            self.dependencies = None
    
    @property
    def cve_mappings_list(self):
        """Get CVE mappings as Python list."""
        if self.cve_mappings:
            try:
                return json.loads(self.cve_mappings)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @cve_mappings_list.setter
    def cve_mappings_list(self, cves):
        """Set CVE mappings from Python list."""
        if isinstance(cves, list):
            self.cve_mappings = json.dumps(cves)
        else:
            self.cve_mappings = None
    
    @property
    def vulnerability_references_list(self):
        """Get vulnerability references as Python list."""
        if self.vulnerability_references:
            try:
                return json.loads(self.vulnerability_references)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @vulnerability_references_list.setter
    def vulnerability_references_list(self, refs):
        """Set vulnerability references from Python list."""
        if isinstance(refs, list):
            self.vulnerability_references = json.dumps(refs)
        else:
            self.vulnerability_references = None
    
    @property
    def tags_list(self):
        """Get tags as Python list."""
        if self.tags:
            try:
                return json.loads(self.tags)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @tags_list.setter
    def tags_list(self, tags):
        """Set tags from Python list."""
        if isinstance(tags, list):
            self.tags = json.dumps(tags)
        else:
            self.tags = None
    
    def check_prerequisites(self, device, assessment_context=None):
        """Check if test prerequisites are met."""
        if not self.prerequisites_list:
            return True, "No prerequisites"
        
        for prereq in self.prerequisites_list:
            if prereq == 'http_service':
                if 80 not in device.open_ports_list and 8080 not in device.open_ports_list:
                    return False, "HTTP service not available"
            elif prereq == 'https_service':
                if 443 not in device.open_ports_list:
                    return False, "HTTPS service not available"
            elif prereq == 'web_interface':
                services = device.services_dict
                if not any('http' in service.lower() for service in services.values()):
                    return False, "Web interface not detected"
            elif prereq == 'authentication_required':
                if not self.requires_authentication:
                    return False, "Authentication not configured for test"
        
        return True, "Prerequisites met"
    
    def validate_result(self, result_data):
        """Validate test result against validation rules."""
        if not self.validation_rules_dict:
            return True, "No validation rules"
        
        rules = self.validation_rules_dict
        
        # Check response code if specified
        if 'expected_status_code' in rules:
            expected = rules['expected_status_code']
            actual = result_data.get('status_code')
            if actual != expected:
                return False, f"Expected status {expected}, got {actual}"
        
        # Check response contains specific text
        if 'contains_text' in rules:
            expected_text = rules['contains_text']
            response_body = result_data.get('response_body', '')
            if expected_text not in response_body:
                return False, f"Response does not contain '{expected_text}'"
        
        # Check response doesn't contain specific text
        if 'not_contains_text' in rules:
            forbidden_text = rules['not_contains_text']
            response_body = result_data.get('response_body', '')
            if forbidden_text in response_body:
                return False, f"Response contains forbidden text '{forbidden_text}'"
        
        # Check response time
        if 'max_response_time' in rules:
            max_time = rules['max_response_time']
            actual_time = result_data.get('response_time', 0)
            if actual_time > max_time:
                return False, f"Response time {actual_time}s exceeds limit {max_time}s"
        
        return True, "Validation passed"
    
    def update_statistics(self, success):
        """Update test execution statistics."""
        self.execution_count += 1
        
        # Calculate new success rate
        if self.execution_count == 1:
            self.success_rate = 1.0 if success else 0.0
        else:
            current_successes = self.success_rate * (self.execution_count - 1)
            if success:
                current_successes += 1
            self.success_rate = current_successes / self.execution_count
        
        db.session.commit()
    
    def add_tag(self, tag):
        """Add a tag to the test."""
        current_tags = self.tags_list
        if tag not in current_tags:
            current_tags.append(tag)
            self.tags_list = current_tags
            db.session.commit()
    
    def remove_tag(self, tag):
        """Remove a tag from the test."""
        current_tags = self.tags_list
        if tag in current_tags:
            current_tags.remove(tag)
            self.tags_list = current_tags
            db.session.commit()
    
    def to_dict(self, include_payload=False):
        """Convert security test to dictionary representation."""
        data = {
            'id': self.id,
            'test_suite_id': self.test_suite_id,
            'name': self.name,
            'description': self.description,
            'test_type': self.test_type,
            'severity': self.severity,
            'category': self.category,
            'timeout': self.timeout,
            'retry_count': self.retry_count,
            'execution_order': self.execution_order,
            'estimated_duration': self.estimated_duration,
            'is_active': self.is_active,
            'requires_authentication': self.requires_authentication,
            'is_destructive': self.is_destructive,
            'prerequisites': self.prerequisites_list,
            'dependencies': self.dependencies_list,
            'cve_mappings': self.cve_mappings_list,
            'vulnerability_references': self.vulnerability_references_list,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'success_rate': self.success_rate,
            'execution_count': self.execution_count,
            'tags': self.tags_list,
            'notes': self.notes
        }
        
        if include_payload:
            data['payload'] = self.payload
            data['expected_result'] = self.expected_result
            data['validation_rules'] = self.validation_rules_dict
        
        return data
    
    @classmethod
    def get_tests_by_type(cls, test_type):
        """Get tests by type."""
        return cls.query.filter_by(test_type=test_type, is_active=True).all()
    
    @classmethod
    def get_tests_by_severity(cls, severity):
        """Get tests by severity."""
        return cls.query.filter_by(severity=severity, is_active=True).all()
    
    @classmethod
    def search_tests(cls, query):
        """Search tests by name or description."""
        search_pattern = f'%{query}%'
        return cls.query.filter(
            db.or_(
                cls.name.like(search_pattern),
                cls.description.like(search_pattern)
            )
        ).filter_by(is_active=True).all()
    
    @classmethod
    def create_default_tests(cls, test_suite_id):
        """Create default security tests for a test suite."""
        default_tests = [
            {
                'name': 'Default Credentials Check',
                'description': 'Check for common default username/password combinations',
                'test_type': 'credential',
                'severity': 'high',
                'category': 'authentication',
                'payload': 'admin:admin,admin:password,admin:123456,root:root',
                'requires_authentication': False,
                'tags_list': ['credentials', 'default', 'authentication']
            },
            {
                'name': 'HTTP Banner Grabbing',
                'description': 'Extract HTTP server information from headers',
                'test_type': 'web',
                'severity': 'info',
                'category': 'information_disclosure',
                'payload': 'GET / HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n',
                'prerequisites_list': ['http_service'],
                'tags_list': ['banner', 'information', 'web']
            },
            {
                'name': 'SSL/TLS Configuration Check',
                'description': 'Analyze SSL/TLS configuration and cipher suites',
                'test_type': 'protocol',
                'severity': 'medium',
                'category': 'encryption',
                'prerequisites_list': ['https_service'],
                'tags_list': ['ssl', 'tls', 'encryption']
            },
            {
                'name': 'Open Port Scan',
                'description': 'Identify open ports and running services',
                'test_type': 'network',
                'severity': 'info',
                'category': 'discovery',
                'payload': 'tcp:1-1000,udp:53,67,123,161',
                'tags_list': ['ports', 'services', 'discovery']
            },
            {
                'name': 'Web Directory Enumeration',
                'description': 'Discover hidden directories and files',
                'test_type': 'web',
                'severity': 'medium',
                'category': 'information_disclosure',
                'payload': '/admin,/config,/backup,/.git,/api',
                'prerequisites_list': ['web_interface'],
                'tags_list': ['directory', 'enumeration', 'web']
            }
        ]
        
        for test_data in default_tests:
            test_data['test_suite_id'] = test_suite_id
            test = cls(**test_data)
            db.session.add(test)
        
        db.session.commit()
    
    def __repr__(self):
        return f'<SecurityTest {self.name} ({self.severity})>'
