#!/usr/bin/env python3
"""
IoT Security Framework - Main Application
"""

import os
import sys
from flask import Flask
from app import create_app, db
from app.models import User, Device, Assessment, TestSuite, SecurityTest, TestResult, Vulnerability
from app.models.user import UserRole

def create_sample_data():
    """Create sample data for development"""
    try:
        # Create admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@iotsecurity.local',
                password='admin123',
                role=UserRole.ADMIN
            )
            db.session.add(admin_user)
            print("Created admin user: admin/admin123")
        
        # Create test user
        test_user = User.query.filter_by(username='tester').first()
        if not test_user:
            test_user = User(
                username='tester',
                email='tester@iotsecurity.local',
                password='test123',
                role=UserRole.TESTER
            )
            db.session.add(test_user)
            print("Created test user: tester/test123")
        
        # Create basic test suite
        basic_suite = TestSuite.query.filter_by(name='Basic IoT Security').first()
        if not basic_suite:
            basic_suite = TestSuite(
                name='Basic IoT Security',
                description='Basic security tests for IoT devices',
                device_types=['camera', 'router', 'sensor'],
                created_by=admin_user.id
            )
            db.session.add(basic_suite)
            db.session.flush()  # Get the ID
            
            # Add some basic tests
            tests = [
                {
                    'name': 'Default Credentials Check',
                    'description': 'Check for default username/password combinations',
                    'test_type': 'credential',
                    'severity': 'high',
                    'payload': 'admin:admin,admin:password,root:root',
                    'remediation': 'Change default credentials immediately'
                },
                {
                    'name': 'HTTP Security Headers',
                    'description': 'Check for security headers in HTTP responses',
                    'test_type': 'web',
                    'severity': 'medium',
                    'payload': 'GET / HTTP/1.1\r\nHost: {target}\r\n\r\n',
                    'remediation': 'Implement proper security headers'
                },
                {
                    'name': 'Open Port Enumeration',
                    'description': 'Check for unnecessary open ports',
                    'test_type': 'network',
                    'severity': 'medium',
                    'payload': 'nmap -sS -p- {target}',
                    'remediation': 'Close unnecessary ports'
                }
            ]
            
            for test_data in tests:
                test = SecurityTest(
                    suite_id=basic_suite.suite_id,
                    name=test_data['name'],
                    description=test_data['description'],
                    test_type=test_data['test_type'],
                    severity=test_data['severity'],
                    payload=test_data['payload'],
                    remediation=test_data['remediation']
                )
                db.session.add(test)
        
        # Create sample vulnerabilities
        sample_vulns = [
            {
                'cve_id': 'CVE-2023-1234',
                'title': 'Default Credentials in IoT Camera',
                'description': 'Camera uses default admin:admin credentials',
                'severity': 'critical',
                'cvss_score': 9.8,
                'affected_devices': ['camera'],
                'affected_manufacturers': ['Hikvision', 'Dahua'],
                'remediation': 'Change default credentials immediately'
            },
            {
                'cve_id': 'CVE-2023-5678',
                'title': 'Weak Encryption in MQTT Communication',
                'description': 'MQTT broker uses weak encryption',
                'severity': 'high',
                'cvss_score': 7.5,
                'affected_devices': ['sensor'],
                'affected_manufacturers': ['Xiaomi'],
                'remediation': 'Enable TLS encryption for MQTT'
            }
        ]
        
        for vuln_data in sample_vulns:
            existing_vuln = Vulnerability.query.filter_by(cve_id=vuln_data['cve_id']).first()
            if not existing_vuln:
                vuln = Vulnerability(
                    title=vuln_data['title'],
                    description=vuln_data['description'],
                    severity=vuln_data['severity'],
                    cve_id=vuln_data['cve_id'],
                    cvss_score=vuln_data['cvss_score'],
                    affected_devices_list=vuln_data['affected_devices'],
                    affected_manufacturers_list=vuln_data['affected_manufacturers'],
                    remediation=vuln_data['remediation']
                )
                db.session.add(vuln)
        
        db.session.commit()
        print("Sample data created successfully!")
        
    except Exception as e:
        print(f"Error creating sample data: {e}")
        db.session.rollback()

def main():
    """Main application entry point"""
    app = create_app()
    
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Create sample data in development
        if app.config['DEBUG']:
            create_sample_data()
    
    # Run the application
    app.run(
        host=os.environ.get('HOST', '0.0.0.0'),
        port=int(os.environ.get('PORT', 5000)),
        debug=app.config['DEBUG']
    )

if __name__ == '__main__':
    main()
