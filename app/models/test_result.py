"""
Test Result model for storing security test execution results
"""

import json
from datetime import datetime
from app import db

class TestResult(db.Model):
    """Model representing the result of a security test execution."""
    
    __tablename__ = 'test_results'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign keys
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('security_tests.id'), nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=True)
    
    # Test execution results
    status = db.Column(db.Enum('pass', 'fail', 'error', 'skip', name='test_status'), 
                      nullable=False)
    result_data = db.Column(db.Text, nullable=True)  # JSON object with detailed results
    
    # Test output and evidence
    output = db.Column(db.Text, nullable=True)       # Raw test output
    error_message = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)     # JSON array of evidence files/screenshots
    
    # Execution metadata
    execution_time = db.Column(db.Float, default=0.0)  # Execution time in seconds
    retry_count = db.Column(db.Integer, default=0)     # Number of retries performed
    
    # Risk assessment
    risk_score = db.Column(db.Float, default=0.0)      # Individual test risk score
    severity_override = db.Column(db.Enum('info', 'low', 'medium', 'high', 'critical',
                                         name='severity_override'), nullable=True)
    
    # Timestamps
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Additional metadata
    environment_info = db.Column(db.Text, nullable=True)  # JSON object with env details
    notes = db.Column(db.Text, nullable=True)
    is_false_positive = db.Column(db.Boolean, default=False)
    
    def __init__(self, assessment_id, test_id, status, **kwargs):
        """Initialize test result."""
        self.assessment_id = assessment_id
        self.test_id = test_id
        self.status = status
        
        # Set additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @property
    def result_data_dict(self):
        """Get result data as Python dictionary."""
        if self.result_data:
            try:
                return json.loads(self.result_data)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    @result_data_dict.setter
    def result_data_dict(self, data):
        """Set result data from Python dictionary."""
        if isinstance(data, dict):
            self.result_data = json.dumps(data)
        else:
            self.result_data = None
    
    @property
    def evidence_list(self):
        """Get evidence as Python list."""
        if self.evidence:
            try:
                return json.loads(self.evidence)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @evidence_list.setter
    def evidence_list(self, evidence):
        """Set evidence from Python list."""
        if isinstance(evidence, list):
            self.evidence = json.dumps(evidence)
        else:
            self.evidence = None
    
    @property
    def environment_info_dict(self):
        """Get environment info as Python dictionary."""
        if self.environment_info:
            try:
                return json.loads(self.environment_info)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    @environment_info_dict.setter
    def environment_info_dict(self, info):
        """Set environment info from Python dictionary."""
        if isinstance(info, dict):
            self.environment_info = json.dumps(info)
        else:
            self.environment_info = None
    
    @property
    def duration(self):
        """Calculate test execution duration."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    @property
    def effective_severity(self):
        """Get effective severity (override or from test)."""
        if self.severity_override:
            return self.severity_override
        elif self.security_test:
            return self.security_test.severity
        return 'info'
    
    def start_execution(self):
        """Mark test execution as started."""
        self.started_at = datetime.utcnow()
        db.session.commit()
    
    def complete_execution(self, status, **kwargs):
        """Mark test execution as completed."""
        self.status = status
        self.completed_at = datetime.utcnow()
        
        # Calculate execution time
        if self.started_at:
            duration = self.completed_at - self.started_at
            self.execution_time = duration.total_seconds()
        
        # Set additional result data
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        # Calculate risk score based on status and severity
        self.calculate_risk_score()
        
        # Update assessment counters
        if self.assessment:
            self.assessment.add_test_result(self)
        
        db.session.commit()
    
    def calculate_risk_score(self):
        """Calculate risk score for this test result."""
        if self.status == 'pass':
            self.risk_score = 0.0
        elif self.status in ['error', 'skip']:
            self.risk_score = 1.0  # Minimal risk for inconclusive tests
        elif self.status == 'fail':
            # Risk score based on severity
            severity_scores = {
                'info': 2.0,
                'low': 4.0,
                'medium': 6.0,
                'high': 8.0,
                'critical': 10.0
            }
            self.risk_score = severity_scores.get(self.effective_severity, 5.0)
        
        db.session.commit()
    
    def add_evidence(self, evidence_type, evidence_data, description=None):
        """Add evidence to the test result."""
        current_evidence = self.evidence_list
        
        evidence_item = {
            'type': evidence_type,
            'data': evidence_data,
            'description': description,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        current_evidence.append(evidence_item)
        self.evidence_list = current_evidence
        db.session.commit()
    
    def mark_false_positive(self, reason=None):
        """Mark result as false positive."""
        self.is_false_positive = True
        if reason:
            self.notes = f"False Positive: {reason}"
        db.session.commit()
    
    def create_vulnerability(self, title, description, **kwargs):
        """Create a vulnerability from this test result."""
        from app.models.vulnerability import Vulnerability
        
        vulnerability = Vulnerability(
            title=title,
            description=description,
            severity=self.effective_severity,
            **kwargs
        )
        
        db.session.add(vulnerability)
        db.session.flush()  # Get the ID
        
        self.vulnerability_id = vulnerability.id
        db.session.commit()
        
        return vulnerability
    
    def to_dict(self, include_details=False):
        """Convert test result to dictionary representation."""
        data = {
            'id': self.id,
            'assessment_id': self.assessment_id,
            'test_id': self.test_id,
            'vulnerability_id': self.vulnerability_id,
            'status': self.status,
            'execution_time': self.execution_time,
            'retry_count': self.retry_count,
            'risk_score': self.risk_score,
            'severity_override': self.severity_override,
            'effective_severity': self.effective_severity,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'duration': str(self.duration) if self.duration else None,
            'is_false_positive': self.is_false_positive,
            'notes': self.notes
        }
        
        if include_details:
            data.update({
                'result_data': self.result_data_dict,
                'output': self.output,
                'error_message': self.error_message,
                'evidence': self.evidence_list,
                'environment_info': self.environment_info_dict
            })
            
            # Include test and vulnerability details
            if self.security_test:
                data['test'] = self.security_test.to_dict()
            
            if self.vulnerability:
                data['vulnerability'] = self.vulnerability.to_dict()
        
        return data
    
    @classmethod
    def get_results_by_assessment(cls, assessment_id):
        """Get all results for an assessment."""
        return cls.query.filter_by(assessment_id=assessment_id).all()
    
    @classmethod
    def get_failed_results(cls, assessment_id=None):
        """Get failed test results, optionally filtered by assessment."""
        query = cls.query.filter_by(status='fail')
        if assessment_id:
            query = query.filter_by(assessment_id=assessment_id)
        return query.all()
    
    @classmethod
    def get_results_by_severity(cls, severity, assessment_id=None):
        """Get results by severity level."""
        # This requires joining with security_tests table
        query = cls.query.join(cls.security_test).filter(
            db.or_(
                cls.severity_override == severity,
                db.and_(
                    cls.severity_override.is_(None),
                    cls.security_test.has(severity=severity)
                )
            )
        )
        
        if assessment_id:
            query = query.filter_by(assessment_id=assessment_id)
        
        return query.all()
    
    @classmethod
    def get_vulnerability_results(cls, assessment_id=None):
        """Get results that found vulnerabilities."""
        query = cls.query.filter(cls.vulnerability_id.isnot(None))
        if assessment_id:
            query = query.filter_by(assessment_id=assessment_id)
        return query.all()
    
    @classmethod
    def get_statistics(cls, assessment_id=None):
        """Get test result statistics."""
        query = cls.query
        if assessment_id:
            query = query.filter_by(assessment_id=assessment_id)
        
        results = query.all()
        
        stats = {
            'total': len(results),
            'passed': len([r for r in results if r.status == 'pass']),
            'failed': len([r for r in results if r.status == 'fail']),
            'errors': len([r for r in results if r.status == 'error']),
            'skipped': len([r for r in results if r.status == 'skip']),
            'vulnerabilities': len([r for r in results if r.vulnerability_id]),
            'false_positives': len([r for r in results if r.is_false_positive]),
            'average_execution_time': sum(r.execution_time for r in results) / len(results) if results else 0
        }
        
        # Severity breakdown
        severity_counts = {}
        for result in results:
            severity = result.effective_severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        stats['severity_breakdown'] = severity_counts
        
        return stats
    
    def __repr__(self):
        return f'<TestResult {self.id} ({self.status})>'
