from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import enum

db = SQLAlchemy()

class AssessmentStatus(enum.Enum):
    """Assessment status enumeration"""
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class TestStatus(enum.Enum):
    """Test result status enumeration"""
    PASS = 'pass'
    FAIL = 'fail'
    ERROR = 'error'
    SKIP = 'skip'
    TIMEOUT = 'timeout'

class TestType(enum.Enum):
    """Test type enumeration"""
    CREDENTIAL = 'credential'
    PROTOCOL = 'protocol'
    WEB = 'web'
    NETWORK = 'network'
    FIRMWARE = 'firmware'
    CUSTOM = 'custom'

class Assessment(db.Model):
    """Security assessment model"""
    __tablename__ = 'assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    test_suite_id = db.Column(db.Integer, db.ForeignKey('test_suites.suite_id'), nullable=True)
    
    # Assessment details
    name = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.Enum(AssessmentStatus), default=AssessmentStatus.PENDING, nullable=False)
    
    # Timestamps
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Results
    risk_score = db.Column(db.Float, default=0.0)
    total_tests = db.Column(db.Integer, default=0)
    passed_tests = db.Column(db.Integer, default=0)
    failed_tests = db.Column(db.Integer, default=0)
    error_tests = db.Column(db.Integer, default=0)
    
    # Summary
    summary = db.Column(db.Text, nullable=True)
    findings = db.Column(db.Text, nullable=True)  # JSON object
    
    # Relationships
    test_results = db.relationship('TestResult', backref='assessment', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, device_id, user_id, test_suite_id=None, name=None, description=None):
        self.device_id = device_id
        self.user_id = user_id
        self.test_suite_id = test_suite_id
        self.name = name
        self.description = description
    
    def start_assessment(self):
        """Start the assessment"""
        self.status = AssessmentStatus.RUNNING
        self.started_at = datetime.utcnow()
        db.session.commit()
    
    def complete_assessment(self, risk_score=None, summary=None):
        """Complete the assessment"""
        self.status = AssessmentStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if risk_score is not None:
            self.risk_score = risk_score
        if summary:
            self.summary = summary
        db.session.commit()
    
    def fail_assessment(self, error_message=None):
        """Mark assessment as failed"""
        self.status = AssessmentStatus.FAILED
        self.completed_at = datetime.utcnow()
        if error_message:
            self.summary = f"Assessment failed: {error_message}"
        db.session.commit()
    
    def update_test_counts(self):
        """Update test result counts"""
        results = self.test_results.all()
        self.total_tests = len(results)
        self.passed_tests = len([r for r in results if r.status == TestStatus.PASS])
        self.failed_tests = len([r for r in results if r.status == TestStatus.FAIL])
        self.error_tests = len([r for r in results if r.status == TestStatus.ERROR])
        db.session.commit()
    
    def get_findings_dict(self):
        """Get findings as dictionary"""
        if self.findings:
            return json.loads(self.findings)
        return {}
    
    def set_findings_dict(self, findings):
        """Set findings from dictionary"""
        self.findings = json.dumps(findings) if findings else None
    
    def get_assessment_info(self):
        """Get comprehensive assessment information"""
        return {
            'id': self.id,
            'device_id': self.device_id,
            'user_id': self.user_id,
            'test_suite_id': self.test_suite_id,
            'name': self.name,
            'description': self.description,
            'status': self.status.value if self.status else None,
            'risk_score': self.risk_score,
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'error_tests': self.error_tests,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'summary': self.summary,
            'findings': self.get_findings_dict()
        }
    
    def __repr__(self):
        return f'<Assessment {self.id} ({self.status.value})>'

class TestSuite(db.Model):
    """Test suite model"""
    __tablename__ = 'test_suites'
    
    suite_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    device_types = db.Column(db.Text, nullable=True)  # JSON array
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationships
    tests = db.relationship('SecurityTest', backref='test_suite', lazy='dynamic')
    assessments = db.relationship('Assessment', backref='test_suite', lazy='dynamic')
    
    def __init__(self, name, description=None, device_types=None, created_by=None):
        self.name = name
        self.description = description
        self.created_by = created_by
        if device_types:
            self.device_types_list = device_types
    
    @property
    def device_types_list(self):
        """Get device types as list"""
        if self.device_types:
            return json.loads(self.device_types)
        return []
    
    @device_types_list.setter
    def device_types_list(self, device_types):
        """Set device types from list"""
        self.device_types = json.dumps(device_types) if device_types else None
    
    def is_applicable_to_device(self, device_type):
        """Check if test suite is applicable to device type"""
        return device_type in self.device_types_list
    
    def get_test_suite_info(self):
        """Get test suite information"""
        return {
            'suite_id': self.suite_id,
            'name': self.name,
            'description': self.description,
            'device_types': self.device_types_list,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active,
            'test_count': self.tests.count()
        }
    
    def __repr__(self):
        return f'<TestSuite {self.name}>'

class SecurityTest(db.Model):
    """Security test model"""
    __tablename__ = 'security_tests'
    
    test_id = db.Column(db.Integer, primary_key=True)
    suite_id = db.Column(db.Integer, db.ForeignKey('test_suites.suite_id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    test_type = db.Column(db.Enum(TestType), nullable=False)
    
    # Test configuration
    payload = db.Column(db.Text, nullable=True)
    expected_result = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='medium', nullable=False)
    remediation = db.Column(db.Text, nullable=True)
    
    # Test metadata
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    timeout = db.Column(db.Integer, default=30)  # seconds
    retry_count = db.Column(db.Integer, default=1)
    
    # Relationships
    test_results = db.relationship('TestResult', backref='security_test', lazy='dynamic')
    
    def __init__(self, suite_id, name, test_type, description=None, payload=None, severity='medium'):
        self.suite_id = suite_id
        self.name = name
        self.test_type = test_type
        self.description = description
        self.payload = payload
        self.severity = severity
    
    def get_test_info(self):
        """Get test information"""
        return {
            'test_id': self.test_id,
            'suite_id': self.suite_id,
            'name': self.name,
            'description': self.description,
            'test_type': self.test_type.value if self.test_type else None,
            'payload': self.payload,
            'expected_result': self.expected_result,
            'severity': self.severity,
            'remediation': self.remediation,
            'timeout': self.timeout,
            'retry_count': self.retry_count,
            'is_active': self.is_active
        }
    
    def __repr__(self):
        return f'<SecurityTest {self.name} ({self.test_type.value})>'

class TestResult(db.Model):
    """Test result model"""
    __tablename__ = 'test_results'
    
    result_id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('security_tests.test_id'), nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.vuln_id'), nullable=True)
    
    # Test execution
    status = db.Column(db.Enum(TestStatus), nullable=False)
    severity = db.Column(db.String(20), nullable=True)
    evidence = db.Column(db.Text, nullable=True)  # JSON object
    remediation = db.Column(db.Text, nullable=True)
    
    # Execution metadata
    executed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    execution_time = db.Column(db.Integer, nullable=True)  # milliseconds
    error_message = db.Column(db.Text, nullable=True)
    
    def __init__(self, assessment_id, test_id, status=TestStatus.PENDING):
        self.assessment_id = assessment_id
        self.test_id = test_id
        self.status = status
    
    def get_evidence_dict(self):
        """Get evidence as dictionary"""
        if self.evidence:
            return json.loads(self.evidence)
        return {}
    
    def set_evidence_dict(self, evidence):
        """Set evidence from dictionary"""
        self.evidence = json.dumps(evidence) if evidence else None
    
    def get_test_result_info(self):
        """Get test result information"""
        return {
            'result_id': self.result_id,
            'assessment_id': self.assessment_id,
            'test_id': self.test_id,
            'vulnerability_id': self.vulnerability_id,
            'status': self.status.value if self.status else None,
            'severity': self.severity,
            'evidence': self.get_evidence_dict(),
            'remediation': self.remediation,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'execution_time': self.execution_time,
            'error_message': self.error_message
        }
    
    def __repr__(self):
        return f'<TestResult {self.result_id} ({self.status.value})>'
