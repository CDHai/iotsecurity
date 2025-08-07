"""
Validation utilities for input data
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional, Union
from marshmallow import Schema, fields, validate, ValidationError

# Custom validation functions
def validate_ip_address(value: str) -> str:
    """Validate IP address."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise ValidationError("Invalid IP address format")

def validate_ip_range(value: str) -> str:
    """Validate IP range in CIDR notation."""
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        raise ValidationError("Invalid IP range format")

def validate_mac_address(value: str) -> str:
    """Validate MAC address."""
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    if not mac_pattern.match(value):
        raise ValidationError("Invalid MAC address format")
    return value

def validate_port_number(value: int) -> int:
    """Validate port number."""
    if not 1 <= value <= 65535:
        raise ValidationError("Port number must be between 1 and 65535")
    return value

def validate_port_range(value: str) -> str:
    """Validate port range string."""
    try:
        for part in value.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    raise ValueError()
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError()
        return value
    except (ValueError, IndexError):
        raise ValidationError("Invalid port range format")

def validate_hostname(value: str) -> str:
    """Validate hostname format."""
    hostname_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$'
    )
    if not hostname_pattern.match(value):
        raise ValidationError("Invalid hostname format")
    return value

def validate_cve_id(value: str) -> str:
    """Validate CVE ID format."""
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    if not cve_pattern.match(value):
        raise ValidationError("Invalid CVE ID format")
    return value

def validate_cvss_score(value: float) -> float:
    """Validate CVSS score."""
    if not 0.0 <= value <= 10.0:
        raise ValidationError("CVSS score must be between 0.0 and 10.0")
    return value

def validate_severity_level(value: str) -> str:
    """Validate severity level."""
    valid_levels = ['info', 'low', 'medium', 'high', 'critical']
    if value not in valid_levels:
        raise ValidationError(f"Severity must be one of: {valid_levels}")
    return value

# Marshmallow schemas for complex validation

class DeviceSchema(Schema):
    """Schema for device validation."""
    
    ip_address = fields.Str(required=True, validate=validate_ip_address)
    mac_address = fields.Str(allow_none=True, validate=validate_mac_address)
    hostname = fields.Str(allow_none=True, validate=validate_hostname)
    manufacturer = fields.Str(allow_none=True, validate=validate.Length(max=100))
    device_type = fields.Str(allow_none=True, validate=validate.Length(max=50))
    model = fields.Str(allow_none=True, validate=validate.Length(max=100))
    firmware_version = fields.Str(allow_none=True, validate=validate.Length(max=50))
    open_ports = fields.List(fields.Int(validate=validate_port_number), missing=[])
    protocols = fields.List(fields.Str(validate=validate.Length(max=20)), missing=[])
    confidence_score = fields.Float(validate=validate.Range(min=0.0, max=1.0), missing=0.0)
    notes = fields.Str(allow_none=True, validate=validate.Length(max=1000))
    tags = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])

class AssessmentSchema(Schema):
    """Schema for assessment validation."""
    
    device_id = fields.Int(required=True, validate=validate.Range(min=1))
    name = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    description = fields.Str(allow_none=True, validate=validate.Length(max=1000))
    scan_type = fields.Str(
        required=True, 
        validate=validate.OneOf(['quick', 'standard', 'comprehensive', 'custom'])
    )
    target_protocols = fields.List(
        fields.Str(validate=validate.OneOf(['http', 'https', 'ftp', 'ssh', 'telnet', 
                                           'smtp', 'pop3', 'imap', 'mqtt', 'coap'])),
        missing=[]
    )
    custom_tests = fields.List(fields.Int(validate=validate.Range(min=1)), missing=[])
    notes = fields.Str(allow_none=True, validate=validate.Length(max=1000))

class TestSuiteSchema(Schema):
    """Schema for test suite validation."""
    
    name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    description = fields.Str(allow_none=True, validate=validate.Length(max=1000))
    version = fields.Str(missing='1.0', validate=validate.Length(max=20))
    device_types = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])
    protocols = fields.List(fields.Str(validate=validate.Length(max=20)), missing=[])
    category = fields.Str(
        missing='standard',
        validate=validate.OneOf(['basic', 'standard', 'comprehensive', 'specialized'])
    )
    is_active = fields.Bool(missing=True)
    is_default = fields.Bool(missing=False)

class SecurityTestSchema(Schema):
    """Schema for security test validation."""
    
    name = fields.Str(required=True, validate=validate.Length(min=1, max=150))
    description = fields.Str(allow_none=True, validate=validate.Length(max=1000))
    test_type = fields.Str(
        required=True,
        validate=validate.OneOf(['credential', 'protocol', 'web', 'network', 'firmware'])
    )
    severity = fields.Str(required=True, validate=validate_severity_level)
    category = fields.Str(allow_none=True, validate=validate.Length(max=50))
    payload = fields.Str(allow_none=True, validate=validate.Length(max=10000))
    expected_result = fields.Str(allow_none=True, validate=validate.Length(max=1000))
    timeout = fields.Int(missing=30, validate=validate.Range(min=1, max=300))
    retry_count = fields.Int(missing=1, validate=validate.Range(min=1, max=5))
    execution_order = fields.Int(missing=0, validate=validate.Range(min=0))
    estimated_duration = fields.Int(missing=30, validate=validate.Range(min=1, max=3600))
    is_active = fields.Bool(missing=True)
    requires_authentication = fields.Bool(missing=False)
    is_destructive = fields.Bool(missing=False)
    prerequisites = fields.List(fields.Str(validate=validate.Length(max=100)), missing=[])
    dependencies = fields.List(fields.Int(validate=validate.Range(min=1)), missing=[])
    cve_mappings = fields.List(fields.Str(validate=validate_cve_id), missing=[])
    tags = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])
    notes = fields.Str(allow_none=True, validate=validate.Length(max=1000))

class VulnerabilitySchema(Schema):
    """Schema for vulnerability validation."""
    
    cve_id = fields.Str(allow_none=True, validate=validate_cve_id)
    cwe_id = fields.Str(allow_none=True, validate=validate.Regexp(r'^CWE-\d+$'))
    external_id = fields.Str(allow_none=True, validate=validate.Length(max=50))
    title = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    description = fields.Str(required=True, validate=validate.Length(min=1, max=5000))
    severity = fields.Str(required=True, validate=validate_severity_level)
    cvss_score = fields.Float(allow_none=True, validate=validate_cvss_score)
    cvss_vector = fields.Str(allow_none=True, validate=validate.Length(max=200))
    cvss_version = fields.Str(missing='3.1', validate=validate.Length(max=10))
    category = fields.Str(allow_none=True, validate=validate.Length(max=50))
    attack_vector = fields.Str(
        allow_none=True,
        validate=validate.OneOf(['network', 'adjacent', 'local', 'physical'])
    )
    attack_complexity = fields.Str(
        allow_none=True,
        validate=validate.OneOf(['low', 'high'])
    )
    confidentiality_impact = fields.Str(
        allow_none=True,
        validate=validate.OneOf(['none', 'low', 'high'])
    )
    integrity_impact = fields.Str(
        allow_none=True,
        validate=validate.OneOf(['none', 'low', 'high'])
    )
    availability_impact = fields.Str(
        allow_none=True,
        validate=validate.OneOf(['none', 'low', 'high'])
    )
    affected_products = fields.List(fields.Str(validate=validate.Length(max=100)), missing=[])
    affected_versions = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])
    fixed_versions = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])
    references = fields.List(fields.Url(), missing=[])
    proof_of_concept = fields.Str(allow_none=True, validate=validate.Length(max=10000))
    remediation = fields.Str(allow_none=True, validate=validate.Length(max=5000))
    workaround = fields.Str(allow_none=True, validate=validate.Length(max=2000))
    status = fields.Str(
        missing='draft',
        validate=validate.OneOf(['draft', 'published', 'modified', 'rejected', 'withdrawn'])
    )
    is_exploitable = fields.Bool(missing=False)
    exploit_available = fields.Bool(missing=False)
    tags = fields.List(fields.Str(validate=validate.Length(max=50)), missing=[])
    notes = fields.Str(allow_none=True, validate=validate.Length(max=2000))

class UserSchema(Schema):
    """Schema for user validation."""
    
    username = fields.Str(
        required=True, 
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(r'^[a-zA-Z0-9_-]+$', error="Username can only contain letters, numbers, underscores, and hyphens")
        ]
    )
    email = fields.Email(allow_none=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8, max=128),
        load_only=True  # Don't include in serialization
    )
    full_name = fields.Str(allow_none=True, validate=validate.Length(max=100))
    organization = fields.Str(allow_none=True, validate=validate.Length(max=100))
    role = fields.Str(
        missing='viewer',
        validate=validate.OneOf(['admin', 'tester', 'viewer'])
    )
    is_active = fields.Bool(missing=True)

class NetworkScanSchema(Schema):
    """Schema for network scan configuration."""
    
    target_network = fields.Str(required=True, validate=validate_ip_range)
    scan_type = fields.Str(
        missing='standard',
        validate=validate.OneOf(['ping', 'tcp_connect', 'tcp_syn', 'udp'])
    )
    port_range = fields.Str(missing='1-1000', validate=validate_port_range)
    timeout = fields.Int(missing=30, validate=validate.Range(min=1, max=300))
    max_concurrent = fields.Int(missing=50, validate=validate.Range(min=1, max=500))
    include_services = fields.Bool(missing=True)
    aggressive_scan = fields.Bool(missing=False)

# Validation helper functions

def validate_data(data: Dict[str, Any], schema_class: Schema) -> Dict[str, Any]:
    """Validate data against schema and return validated data."""
    schema = schema_class()
    try:
        return schema.load(data)
    except ValidationError as err:
        raise ValidationError(f"Validation failed: {err.messages}")

def validate_device_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate device data."""
    return validate_data(data, DeviceSchema)

def validate_assessment_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate assessment data."""
    return validate_data(data, AssessmentSchema)

def validate_test_suite_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate test suite data."""
    return validate_data(data, TestSuiteSchema)

def validate_security_test_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate security test data."""
    return validate_data(data, SecurityTestSchema)

def validate_vulnerability_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate vulnerability data."""
    return validate_data(data, VulnerabilitySchema)

def validate_user_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate user data."""
    return validate_data(data, UserSchema)

def validate_network_scan_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate network scan data."""
    return validate_data(data, NetworkScanSchema)
