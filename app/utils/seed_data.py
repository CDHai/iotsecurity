"""
Seed data for initializing the database with default values
"""

from datetime import datetime, date
from app import db
from app.models.user import User
from app.models.test_suite import TestSuite
from app.models.security_test import SecurityTest
from app.models.vulnerability import Vulnerability

def seed_initial_data():
    """Seed the database with initial data."""
    print("Seeding initial data...")
    
    # Create default admin user
    create_default_users()
    
    # Create default test suites
    create_default_test_suites()
    
    # Create default vulnerabilities
    create_default_vulnerabilities()
    
    print("Initial data seeding completed!")

def create_default_users():
    """Create default users."""
    print("Creating default users...")
    
    # Check if admin user already exists
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User.create_user(
            username='admin',
            email='admin@iotsecurity.local',
            password='admin123',
            role='admin',
            full_name='System Administrator',
            organization='IoT Security Framework',
            is_active=True,
            is_verified=True
        )
        print(f"Created admin user: {admin_user.username}")
    
    # Create demo tester user
    tester_user = User.query.filter_by(username='tester').first()
    if not tester_user:
        tester_user = User.create_user(
            username='tester',
            email='tester@iotsecurity.local',
            password='tester123',
            role='tester',
            full_name='Security Tester',
            organization='IoT Security Framework',
            is_active=True,
            is_verified=True
        )
        print(f"Created tester user: {tester_user.username}")
    
    # Create demo viewer user
    viewer_user = User.query.filter_by(username='viewer').first()
    if not viewer_user:
        viewer_user = User.create_user(
            username='viewer',
            email='viewer@iotsecurity.local',
            password='viewer123',
            role='viewer',
            full_name='Security Viewer',
            organization='IoT Security Framework',
            is_active=True,
            is_verified=True
        )
        print(f"Created viewer user: {viewer_user.username}")

def create_default_test_suites():
    """Create default test suites and tests."""
    print("Creating default test suites...")
    
    admin_user = User.query.filter_by(username='admin').first()
    
    # Basic IoT Security Test Suite
    basic_suite = TestSuite.query.filter_by(name='Basic IoT Security').first()
    if not basic_suite:
        basic_suite = TestSuite(
            name='Basic IoT Security',
            description='Basic security tests for IoT devices including common vulnerabilities',
            version='1.0',
            category='basic',
            is_default=True,
            is_active=True,
            created_by=admin_user.id if admin_user else None
        )
        basic_suite.device_types_list = ['camera', 'sensor', 'switch', 'lock', 'router']
        basic_suite.protocols_list = ['http', 'https', 'telnet', 'ssh']
        
        db.session.add(basic_suite)
        db.session.flush()
        
        # Add basic tests
        basic_tests = [
            {
                'name': 'Default Credentials Check',
                'description': 'Test for common default username/password combinations',
                'test_type': 'credential',
                'severity': 'high',
                'category': 'authentication',
                'payload': 'admin:admin,admin:password,admin:123456,root:root,user:user',
                'execution_order': 1,
                'tags_list': ['credentials', 'default', 'authentication']
            },
            {
                'name': 'Weak Password Policy',
                'description': 'Check if device accepts weak passwords',
                'test_type': 'credential',
                'severity': 'medium',
                'category': 'authentication',
                'payload': '123,password,admin,test',
                'execution_order': 2,
                'tags_list': ['password', 'weak', 'authentication']
            },
            {
                'name': 'HTTP Banner Grabbing',
                'description': 'Extract HTTP server information from headers',
                'test_type': 'web',
                'severity': 'info',
                'category': 'information_disclosure',
                'payload': 'GET / HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n',
                'execution_order': 3,
                'prerequisites_list': ['http_service'],
                'tags_list': ['banner', 'information', 'web']
            },
            {
                'name': 'Telnet Access Check',
                'description': 'Check if telnet service is accessible',
                'test_type': 'network',
                'severity': 'high',
                'category': 'remote_access',
                'payload': 'telnet {target} 23',
                'execution_order': 4,
                'tags_list': ['telnet', 'remote_access', 'insecure']
            }
        ]
        
        for test_data in basic_tests:
            test_data['test_suite_id'] = basic_suite.id
            test = SecurityTest(**test_data)
            db.session.add(test)
        
        basic_suite.update_statistics()
        print(f"Created test suite: {basic_suite.name}")
    
    # Comprehensive IoT Assessment Suite
    comprehensive_suite = TestSuite.query.filter_by(name='Comprehensive IoT Assessment').first()
    if not comprehensive_suite:
        comprehensive_suite = TestSuite(
            name='Comprehensive IoT Assessment',
            description='Comprehensive security assessment for IoT devices covering all major attack vectors',
            version='1.0',
            category='comprehensive',
            is_default=True,
            is_active=True,
            created_by=admin_user.id if admin_user else None
        )
        comprehensive_suite.device_types_list = []  # Applies to all device types
        comprehensive_suite.protocols_list = ['http', 'https', 'mqtt', 'coap', 'ssh', 'telnet', 'ftp']
        
        db.session.add(comprehensive_suite)
        db.session.flush()
        
        # Add comprehensive tests
        comprehensive_tests = [
            {
                'name': 'SSL/TLS Configuration Analysis',
                'description': 'Analyze SSL/TLS configuration and cipher suites',
                'test_type': 'protocol',
                'severity': 'medium',
                'category': 'encryption',
                'payload': 'sslscan {target}:443',
                'execution_order': 1,
                'prerequisites_list': ['https_service'],
                'tags_list': ['ssl', 'tls', 'encryption']
            },
            {
                'name': 'Web Directory Enumeration',
                'description': 'Discover hidden directories and files',
                'test_type': 'web',
                'severity': 'medium',
                'category': 'information_disclosure',
                'payload': '/admin,/config,/backup,/.git,/api,/cgi-bin,/setup',
                'execution_order': 2,
                'prerequisites_list': ['web_interface'],
                'tags_list': ['directory', 'enumeration', 'web']
            },
            {
                'name': 'MQTT Security Check',
                'description': 'Test MQTT broker security configuration',
                'test_type': 'protocol',
                'severity': 'high',
                'category': 'iot_protocols',
                'payload': 'mosquitto_sub -h {target} -t "#" -C 10',
                'execution_order': 3,
                'prerequisites_list': ['mqtt_service'],
                'tags_list': ['mqtt', 'broker', 'authentication']
            },
            {
                'name': 'Firmware Analysis',
                'description': 'Analyze device firmware for vulnerabilities',
                'test_type': 'firmware',
                'severity': 'high',
                'category': 'firmware',
                'payload': 'binwalk -E {firmware_file}',
                'execution_order': 4,
                'estimated_duration': 300,
                'tags_list': ['firmware', 'analysis', 'binwalk']
            }
        ]
        
        for test_data in comprehensive_tests:
            test_data['test_suite_id'] = comprehensive_suite.id
            test = SecurityTest(**test_data)
            db.session.add(test)
        
        comprehensive_suite.update_statistics()
        print(f"Created test suite: {comprehensive_suite.name}")
    
    # Smart Camera Security Suite
    camera_suite = TestSuite.query.filter_by(name='Smart Camera Security').first()
    if not camera_suite:
        camera_suite = TestSuite(
            name='Smart Camera Security',
            description='Specialized security tests for IP cameras and surveillance devices',
            version='1.0',
            category='specialized',
            is_default=False,
            is_active=True,
            created_by=admin_user.id if admin_user else None
        )
        camera_suite.device_types_list = ['camera', 'nvr', 'dvr']
        camera_suite.protocols_list = ['http', 'https', 'rtsp', 'onvif']
        
        db.session.add(camera_suite)
        db.session.flush()
        
        # Add camera-specific tests
        camera_tests = [
            {
                'name': 'RTSP Stream Access',
                'description': 'Check if RTSP video streams are accessible without authentication',
                'test_type': 'protocol',
                'severity': 'critical',
                'category': 'unauthorized_access',
                'payload': 'ffprobe rtsp://{target}:554/stream',
                'execution_order': 1,
                'tags_list': ['rtsp', 'video', 'unauthorized']
            },
            {
                'name': 'ONVIF Service Discovery',
                'description': 'Discover and test ONVIF camera services',
                'test_type': 'protocol',
                'severity': 'medium',
                'category': 'service_discovery',
                'payload': 'onvif-discover --timeout 5',
                'execution_order': 2,
                'tags_list': ['onvif', 'discovery', 'camera']
            },
            {
                'name': 'Camera Web Interface CVE Check',
                'description': 'Check for known CVEs in camera web interfaces',
                'test_type': 'web',
                'severity': 'high',
                'category': 'known_vulnerabilities',
                'payload': 'CVE-2017-7921,CVE-2018-9995,CVE-2019-11219',
                'execution_order': 3,
                'cve_mappings_list': ['CVE-2017-7921', 'CVE-2018-9995', 'CVE-2019-11219'],
                'tags_list': ['cve', 'camera', 'web']
            }
        ]
        
        for test_data in camera_tests:
            test_data['test_suite_id'] = camera_suite.id
            test = SecurityTest(**test_data)
            db.session.add(test)
        
        camera_suite.update_statistics()
        print(f"Created test suite: {camera_suite.name}")
    
    db.session.commit()

def create_default_vulnerabilities():
    """Create default vulnerability entries."""
    print("Creating default vulnerabilities...")
    
    vulnerabilities = [
        {
            'cve_id': 'CVE-2017-7921',
            'title': 'Hikvision IP Camera Authentication Bypass',
            'description': 'A vulnerability in Hikvision IP cameras allows remote attackers to bypass authentication and access the device.',
            'severity': 'critical',
            'cvss_score': 9.8,
            'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'category': 'authentication_bypass',
            'attack_vector': 'network',
            'attack_complexity': 'low',
            'confidentiality_impact': 'high',
            'integrity_impact': 'high',
            'availability_impact': 'high',
            'affected_products_list': ['Hikvision IP Camera'],
            'affected_versions_list': ['< 5.4.5'],
            'fixed_versions_list': ['5.4.5', '5.4.41'],
            'references_list': [
                {'url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7921'},
                {'url': 'https://www.hikvision.com/en/support/cybersecurity/security-advisory/'}
            ],
            'remediation': 'Update firmware to version 5.4.5 or later. Change default credentials immediately.',
            'status': 'published',
            'is_exploitable': True,
            'exploit_available': True,
            'published_date': date(2017, 9, 23),
            'tags_list': ['hikvision', 'camera', 'authentication', 'bypass']
        },
        {
            'cve_id': 'CVE-2018-9995',
            'title': 'DVR Authentication Bypass via Cookie Manipulation',
            'description': 'Multiple DVR devices are vulnerable to authentication bypass through cookie manipulation.',
            'severity': 'high',
            'cvss_score': 8.8,
            'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
            'category': 'authentication_bypass',
            'attack_vector': 'network',
            'attack_complexity': 'low',
            'confidentiality_impact': 'high',
            'integrity_impact': 'high',
            'availability_impact': 'high',
            'affected_products_list': ['Generic DVR', 'NVR Systems'],
            'references_list': [
                {'url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9995'}
            ],
            'remediation': 'Update firmware and implement proper session management.',
            'status': 'published',
            'is_exploitable': True,
            'published_date': date(2018, 4, 17),
            'tags_list': ['dvr', 'nvr', 'authentication', 'cookie']
        },
        {
            'title': 'Default MQTT Broker Configuration',
            'description': 'MQTT brokers running with default configuration allow anonymous access and message interception.',
            'severity': 'high',
            'cvss_score': 7.5,
            'category': 'misconfiguration',
            'attack_vector': 'network',
            'attack_complexity': 'low',
            'confidentiality_impact': 'high',
            'integrity_impact': 'none',
            'availability_impact': 'none',
            'affected_products_list': ['Mosquitto MQTT Broker', 'Eclipse Mosquitto'],
            'remediation': 'Configure authentication and authorization for MQTT broker. Disable anonymous access.',
            'workaround': 'Use firewall rules to restrict access to MQTT port (1883/8883).',
            'status': 'published',
            'tags_list': ['mqtt', 'broker', 'configuration', 'anonymous']
        },
        {
            'title': 'Weak Telnet Implementation',
            'description': 'IoT devices with enabled telnet service using weak or default credentials.',
            'severity': 'high',
            'cvss_score': 8.8,
            'category': 'weak_credentials',
            'attack_vector': 'network',
            'attack_complexity': 'low',
            'confidentiality_impact': 'high',
            'integrity_impact': 'high',
            'availability_impact': 'high',
            'affected_products_list': ['Generic IoT Device'],
            'remediation': 'Disable telnet service. Use SSH with strong authentication instead.',
            'workaround': 'Change default credentials and restrict network access.',
            'status': 'published',
            'is_exploitable': True,
            'tags_list': ['telnet', 'credentials', 'remote_access']
        },
        {
            'title': 'Insecure Web Interface',
            'description': 'IoT device web interfaces lacking proper authentication and authorization controls.',
            'severity': 'medium',
            'cvss_score': 6.5,
            'category': 'access_control',
            'attack_vector': 'network',
            'attack_complexity': 'low',
            'confidentiality_impact': 'high',
            'integrity_impact': 'none',
            'availability_impact': 'none',
            'affected_products_list': ['Generic IoT Device'],
            'remediation': 'Implement proper authentication and session management for web interface.',
            'status': 'published',
            'tags_list': ['web', 'authentication', 'access_control']
        }
    ]
    
    for vuln_data in vulnerabilities:
        # Check if vulnerability already exists
        existing_vuln = None
        if vuln_data.get('cve_id'):
            existing_vuln = Vulnerability.query.filter_by(cve_id=vuln_data['cve_id']).first()
        else:
            existing_vuln = Vulnerability.query.filter_by(title=vuln_data['title']).first()
        
        if not existing_vuln:
            vulnerability = Vulnerability(**vuln_data)
            db.session.add(vulnerability)
            print(f"Created vulnerability: {vulnerability.title}")
    
    db.session.commit()

if __name__ == '__main__':
    # Run seeding if called directly
    from app import create_app
    
    app = create_app()
    with app.app_context():
        seed_initial_data()
