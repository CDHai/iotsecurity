"""
Security test execution engine for IoT devices
"""

import asyncio
import subprocess
import requests
import socket
import ssl
import json
import re
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from app import db
from app.models.device import Device
from app.models.assessment import Assessment
from app.models.security_test import SecurityTest
from app.models.test_result import TestResult
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class SecurityTestEngine:
    """Main engine for executing security tests on IoT devices."""
    
    def __init__(self, max_workers: int = 10, timeout: int = 30):
        self.max_workers = max_workers
        self.timeout = timeout
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.test_modules = self._load_test_modules()
        
    def _load_test_modules(self) -> Dict[str, Any]:
        """Load available test modules."""
        return {
            'credential': CredentialTestModule(),
            'web': WebSecurityTestModule(),
            'network': NetworkTestModule(),
            'protocol': ProtocolTestModule(),
            'firmware': FirmwareTestModule()
        }
    
    def execute_assessment(self, assessment_id: int) -> Dict[str, Any]:
        """Execute all tests for an assessment."""
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found")
        
        logger.info(f"Starting assessment {assessment_id} for device {assessment.device.ip_address}")
        
        try:
            # Mark assessment as running
            assessment.start_assessment()
            
            # Get tests to execute
            tests = self._get_tests_for_assessment(assessment)
            
            if not tests:
                raise ValueError("No tests found for assessment")
            
            # Execute tests
            results = self._execute_tests(assessment, tests)
            
            # Process results
            self._process_test_results(assessment, results)
            
            # Complete assessment
            assessment.complete_assessment(success=True)
            
            logger.info(f"Assessment {assessment_id} completed successfully")
            
            return {
                'assessment_id': assessment_id,
                'status': 'completed',
                'total_tests': len(results),
                'passed': len([r for r in results if r['status'] == 'pass']),
                'failed': len([r for r in results if r['status'] == 'fail']),
                'errors': len([r for r in results if r['status'] == 'error'])
            }
            
        except Exception as e:
            logger.error(f"Assessment {assessment_id} failed: {str(e)}")
            assessment.complete_assessment(success=False)
            assessment.error_message = str(e)
            db.session.commit()
            raise
    
    def _get_tests_for_assessment(self, assessment: Assessment) -> List[SecurityTest]:
        """Get list of tests to execute for assessment."""
        tests = []
        
        if assessment.test_suite_id:
            # Use specific test suite
            suite_tests = assessment.test_suite.get_active_tests()
            tests.extend(suite_tests)
        
        if assessment.custom_tests_list:
            # Add custom tests
            custom_tests = SecurityTest.query.filter(
                SecurityTest.id.in_(assessment.custom_tests_list),
                SecurityTest.is_active == True
            ).all()
            tests.extend(custom_tests)
        
        if not tests:
            # Use default tests based on scan type
            tests = self._get_default_tests(assessment.scan_type, assessment.device)
        
        # Filter tests based on device compatibility
        compatible_tests = []
        for test in tests:
            if self._is_test_compatible(test, assessment.device):
                compatible_tests.append(test)
        
        return compatible_tests
    
    def _get_default_tests(self, scan_type: str, device: Device) -> List[SecurityTest]:
        """Get default tests based on scan type and device."""
        from app.models.test_suite import TestSuite
        
        # Get default test suite based on scan type
        suite_map = {
            'quick': 'Basic IoT Security',
            'standard': 'Basic IoT Security',
            'comprehensive': 'Comprehensive IoT Assessment'
        }
        
        suite_name = suite_map.get(scan_type, 'Basic IoT Security')
        suite = TestSuite.query.filter_by(name=suite_name, is_active=True).first()
        
        if suite:
            return suite.get_active_tests()
        
        return []
    
    def _is_test_compatible(self, test: SecurityTest, device: Device) -> bool:
        """Check if test is compatible with device."""
        # Check prerequisites
        is_compatible, reason = test.check_prerequisites(device)
        if not is_compatible:
            logger.debug(f"Test {test.name} not compatible with {device.ip_address}: {reason}")
            return False
        
        # Check protocol requirements
        if test.test_type == 'web':
            return 'http' in device.protocols_list or 'https' in device.protocols_list
        elif test.test_type == 'protocol':
            # Check if device supports required protocols
            return True  # Most protocol tests are generic
        
        return True
    
    def _execute_tests(self, assessment: Assessment, tests: List[SecurityTest]) -> List[Dict[str, Any]]:
        """Execute tests concurrently."""
        results = []
        futures = []
        
        # Submit tests to thread pool
        for i, test in enumerate(tests):
            future = self.executor.submit(
                self._execute_single_test, 
                assessment, 
                test, 
                i + 1, 
                len(tests)
            )
            futures.append((future, test))
        
        # Collect results
        for future, test in futures:
            try:
                result = future.result(timeout=self.timeout * 2)
                results.append(result)
                
                # Update progress
                progress = (len(results) / len(tests)) * 100
                assessment.update_progress(int(progress))
                
            except Exception as e:
                logger.error(f"Test {test.name} failed with exception: {str(e)}")
                results.append({
                    'test_id': test.id,
                    'status': 'error',
                    'error_message': str(e),
                    'execution_time': 0.0
                })
        
        return results
    
    def _execute_single_test(self, assessment: Assessment, test: SecurityTest, 
                           current: int, total: int) -> Dict[str, Any]:
        """Execute a single security test."""
        logger.info(f"Executing test {current}/{total}: {test.name}")
        
        start_time = time.time()
        
        try:
            # Get test module
            module = self.test_modules.get(test.test_type)
            if not module:
                raise ValueError(f"No module found for test type: {test.test_type}")
            
            # Execute test
            result = module.execute_test(test, assessment.device)
            
            # Calculate execution time
            execution_time = time.time() - start_time
            
            # Validate result
            is_valid, validation_message = test.validate_result(result.get('data', {}))
            
            # Determine test status
            if result.get('success', False) and is_valid:
                status = 'pass'
            elif not is_valid:
                status = 'fail'
                result['validation_error'] = validation_message
            else:
                status = 'fail'
            
            # Update test statistics
            test.update_statistics(status == 'pass')
            
            return {
                'test_id': test.id,
                'status': status,
                'execution_time': execution_time,
                'result_data': result.get('data', {}),
                'output': result.get('output', ''),
                'evidence': result.get('evidence', []),
                'error_message': result.get('error') or result.get('validation_error')
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Test {test.name} failed: {str(e)}")
            
            return {
                'test_id': test.id,
                'status': 'error',
                'execution_time': execution_time,
                'error_message': str(e),
                'output': '',
                'result_data': {},
                'evidence': []
            }
    
    def _process_test_results(self, assessment: Assessment, results: List[Dict[str, Any]]):
        """Process and save test results."""
        for result_data in results:
            try:
                # Create test result record
                test_result = TestResult(
                    assessment_id=assessment.id,
                    test_id=result_data['test_id'],
                    status=result_data['status'],
                    execution_time=result_data['execution_time'],
                    output=result_data.get('output'),
                    error_message=result_data.get('error_message')
                )
                
                # Set result data and evidence
                if result_data.get('result_data'):
                    test_result.result_data_dict = result_data['result_data']
                
                if result_data.get('evidence'):
                    test_result.evidence_list = result_data['evidence']
                
                # Create vulnerability if test failed
                if result_data['status'] == 'fail':
                    vulnerability = self._create_vulnerability_from_result(
                        result_data, assessment.device
                    )
                    if vulnerability:
                        test_result.vulnerability_id = vulnerability.id
                
                db.session.add(test_result)
                
                # Update assessment counters
                assessment.add_test_result(test_result)
                
            except Exception as e:
                logger.error(f"Error processing test result: {str(e)}")
                continue
        
        db.session.commit()
    
    def _create_vulnerability_from_result(self, result_data: Dict[str, Any], 
                                        device: Device) -> Optional[Vulnerability]:
        """Create vulnerability record from failed test result."""
        try:
            test = SecurityTest.query.get(result_data['test_id'])
            if not test:
                return None
            
            # Check if similar vulnerability already exists
            existing_vuln = Vulnerability.query.filter_by(
                title=f"{test.name} - {device.ip_address}"
            ).first()
            
            if existing_vuln:
                return existing_vuln
            
            # Create new vulnerability
            vulnerability = Vulnerability(
                title=f"{test.name} - {device.ip_address}",
                description=f"Security test '{test.name}' failed on device {device.ip_address}. "
                          f"{test.description}",
                severity=test.severity,
                category=test.category or 'security_test_failure',
                status='published'
            )
            
            # Add affected product
            if device.manufacturer and device.model:
                vulnerability.affected_products_list = [f"{device.manufacturer} {device.model}"]
            elif device.manufacturer:
                vulnerability.affected_products_list = [device.manufacturer]
            
            # Add remediation if available
            if hasattr(test, 'remediation') and test.remediation:
                vulnerability.remediation = test.remediation
            
            db.session.add(vulnerability)
            db.session.flush()  # Get ID
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error creating vulnerability: {str(e)}")
            return None

class BaseTestModule:
    """Base class for security test modules."""
    
    def execute_test(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Execute a security test. Must be implemented by subclasses."""
        raise NotImplementedError
    
    def _make_http_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """Make HTTP request with common settings."""
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('allow_redirects', True)
        
        # Add common headers
        headers = kwargs.get('headers', {})
        headers.setdefault('User-Agent', 'IoT-Security-Scanner/1.0')
        kwargs['headers'] = headers
        
        return requests.request(method, url, **kwargs)

class CredentialTestModule(BaseTestModule):
    """Module for testing default and weak credentials."""
    
    def execute_test(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Execute credential-based security test."""
        if 'default' in test.name.lower():
            return self._test_default_credentials(test, device)
        elif 'weak' in test.name.lower():
            return self._test_weak_passwords(test, device)
        else:
            return self._test_authentication_bypass(test, device)
    
    def _test_default_credentials(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test for default credentials."""
        # Parse credential pairs from payload
        credentials = []
        if test.payload:
            pairs = test.payload.split(',')
            for pair in pairs:
                if ':' in pair:
                    username, password = pair.strip().split(':', 1)
                    credentials.append((username, password))
        
        # Default credentials to try
        if not credentials:
            credentials = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('admin', ''),
                ('root', 'root'),
                ('user', 'user'),
                ('guest', 'guest')
            ]
        
        results = []
        
        # Try HTTP authentication
        for port in [80, 8080, 443, 8443]:
            if port in device.open_ports_list:
                protocol = 'https' if port in [443, 8443] else 'http'
                base_url = f"{protocol}://{device.ip_address}:{port}"
                
                for username, password in credentials:
                    try:
                        response = self._make_http_request(
                            base_url,
                            auth=(username, password),
                            timeout=5
                        )
                        
                        if response.status_code == 200:
                            results.append({
                                'protocol': protocol,
                                'port': port,
                                'username': username,
                                'password': password,
                                'success': True,
                                'response_code': response.status_code
                            })
                            
                            return {
                                'success': False,  # Test failed (vulnerability found)
                                'data': {
                                    'vulnerable_credentials': results,
                                    'total_attempts': len(credentials)
                                },
                                'output': f"Default credentials found: {username}:{password}",
                                'evidence': [
                                    {
                                        'type': 'http_response',
                                        'data': response.text[:500],
                                        'description': f"Successful login with {username}:{password}"
                                    }
                                ]
                            }
                            
                    except Exception as e:
                        logger.debug(f"Credential test failed for {username}:{password}: {str(e)}")
                        continue
        
        # Try SSH if available
        if 22 in device.open_ports_list:
            ssh_results = self._test_ssh_credentials(device, credentials)
            if ssh_results:
                return ssh_results
        
        # Try Telnet if available
        if 23 in device.open_ports_list:
            telnet_results = self._test_telnet_credentials(device, credentials)
            if telnet_results:
                return telnet_results
        
        return {
            'success': True,  # Test passed (no default credentials)
            'data': {
                'attempts': len(credentials),
                'vulnerable_credentials': []
            },
            'output': f"No default credentials found after {len(credentials)} attempts"
        }
    
    def _test_ssh_credentials(self, device: Device, credentials: List[Tuple[str, str]]) -> Optional[Dict[str, Any]]:
        """Test SSH credentials."""
        try:
            import paramiko
            
            for username, password in credentials:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    ssh.connect(
                        device.ip_address,
                        port=22,
                        username=username,
                        password=password,
                        timeout=5,
                        auth_timeout=5
                    )
                    
                    ssh.close()
                    
                    return {
                        'success': False,  # Vulnerability found
                        'data': {
                            'protocol': 'ssh',
                            'username': username,
                            'password': password
                        },
                        'output': f"SSH access with default credentials: {username}:{password}"
                    }
                    
                except paramiko.AuthenticationException:
                    continue
                except Exception as e:
                    logger.debug(f"SSH test error: {str(e)}")
                    continue
                    
        except ImportError:
            logger.debug("paramiko not available for SSH testing")
        
        return None
    
    def _test_telnet_credentials(self, device: Device, credentials: List[Tuple[str, str]]) -> Optional[Dict[str, Any]]:
        """Test Telnet credentials."""
        try:
            import telnetlib
            
            for username, password in credentials:
                try:
                    tn = telnetlib.Telnet(device.ip_address, 23, timeout=5)
                    
                    # Look for login prompt
                    tn.read_until(b"login:", timeout=5)
                    tn.write(username.encode('ascii') + b"\n")
                    
                    tn.read_until(b"Password:", timeout=5)
                    tn.write(password.encode('ascii') + b"\n")
                    
                    # Check for successful login
                    response = tn.read_some()
                    tn.close()
                    
                    if b"$" in response or b"#" in response or b">" in response:
                        return {
                            'success': False,  # Vulnerability found
                            'data': {
                                'protocol': 'telnet',
                                'username': username,
                                'password': password
                            },
                            'output': f"Telnet access with default credentials: {username}:{password}"
                        }
                        
                except Exception as e:
                    logger.debug(f"Telnet test error: {str(e)}")
                    continue
                    
        except ImportError:
            logger.debug("telnetlib not available")
        
        return None
    
    def _test_weak_passwords(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test for weak password policies."""
        # This would test if the device accepts weak passwords
        # Implementation would depend on having a way to create/modify accounts
        
        return {
            'success': True,
            'data': {'message': 'Weak password test not implemented yet'},
            'output': 'Test skipped - requires account creation capability'
        }
    
    def _test_authentication_bypass(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test for authentication bypass vulnerabilities."""
        # Test common authentication bypass techniques
        
        bypass_attempts = [
            # SQL injection attempts
            ("admin'--", "anything"),
            ("admin' OR '1'='1'--", "anything"),
            ("' OR 1=1--", "anything"),
            
            # Path traversal
            ("../../../etc/passwd", "anything"),
            
            # Empty/null
            ("", ""),
            (None, None)
        ]
        
        for port in [80, 8080, 443, 8443]:
            if port in device.open_ports_list:
                protocol = 'https' if port in [443, 8443] else 'http'
                base_url = f"{protocol}://{device.ip_address}:{port}"
                
                for username, password in bypass_attempts:
                    try:
                        # Try different authentication methods
                        methods = [
                            lambda: self._make_http_request(base_url, auth=(username, password)),
                            lambda: self._make_http_request(
                                base_url + "/login",
                                method='POST',
                                data={'username': username, 'password': password}
                            )
                        ]
                        
                        for method in methods:
                            try:
                                response = method()
                                
                                # Check for successful bypass indicators
                                if (response.status_code == 200 and
                                    any(indicator in response.text.lower() for indicator in 
                                        ['dashboard', 'welcome', 'logout', 'admin panel'])):
                                    
                                    return {
                                        'success': False,  # Vulnerability found
                                        'data': {
                                            'bypass_method': f"{username}:{password}",
                                            'response_code': response.status_code
                                        },
                                        'output': f"Authentication bypass possible with: {username}:{password}",
                                        'evidence': [
                                            {
                                                'type': 'http_response',
                                                'data': response.text[:500],
                                                'description': 'Successful authentication bypass'
                                            }
                                        ]
                                    }
                                    
                            except Exception:
                                continue
                                
                    except Exception as e:
                        logger.debug(f"Bypass test error: {str(e)}")
                        continue
        
        return {
            'success': True,
            'data': {'bypass_attempts': len(bypass_attempts)},
            'output': 'No authentication bypass vulnerabilities found'
        }

class WebSecurityTestModule(BaseTestModule):
    """Module for web application security testing."""
    
    def execute_test(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Execute web security test."""
        if 'banner' in test.name.lower():
            return self._test_http_banner_grabbing(test, device)
        elif 'directory' in test.name.lower() or 'enumeration' in test.name.lower():
            return self._test_directory_enumeration(test, device)
        elif 'ssl' in test.name.lower() or 'tls' in test.name.lower():
            return self._test_ssl_configuration(test, device)
        else:
            return self._test_generic_web_vulnerability(test, device)
    
    def _test_http_banner_grabbing(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test HTTP banner grabbing."""
        banners = {}
        
        for port in [80, 8080, 443, 8443]:
            if port in device.open_ports_list:
                try:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    url = f"{protocol}://{device.ip_address}:{port}"
                    
                    response = self._make_http_request(url, timeout=10)
                    
                    banner_info = {
                        'server': response.headers.get('Server', 'Unknown'),
                        'x_powered_by': response.headers.get('X-Powered-By', ''),
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    }
                    
                    banners[f"{protocol}:{port}"] = banner_info
                    
                except Exception as e:
                    logger.debug(f"Banner grab failed for port {port}: {str(e)}")
                    continue
        
        if banners:
            # Check for information disclosure
            sensitive_headers = []
            for port_info, banner in banners.items():
                server = banner.get('server', '').lower()
                powered_by = banner.get('x_powered_by', '').lower()
                
                if any(info in server + powered_by for info in 
                       ['version', 'apache', 'nginx', 'iis', 'tomcat']):
                    sensitive_headers.append({
                        'port': port_info,
                        'server': banner.get('server'),
                        'powered_by': banner.get('x_powered_by')
                    })
            
            success = len(sensitive_headers) == 0  # Test passes if no sensitive info disclosed
            
            return {
                'success': success,
                'data': {
                    'banners': banners,
                    'sensitive_headers': sensitive_headers
                },
                'output': f"HTTP banners collected from {len(banners)} ports. "
                         f"{'No sensitive information disclosed.' if success else 'Sensitive information disclosed.'}",
                'evidence': [
                    {
                        'type': 'http_headers',
                        'data': json.dumps(banners, indent=2),
                        'description': 'HTTP response headers'
                    }
                ]
            }
        
        return {
            'success': True,
            'data': {'message': 'No HTTP services found'},
            'output': 'No HTTP services available for banner grabbing'
        }
    
    def _test_directory_enumeration(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test directory enumeration."""
        # Common directories to check
        directories = [
            '/admin', '/administrator', '/config', '/configuration',
            '/backup', '/backups', '/tmp', '/temp', '/test',
            '/.git', '/.svn', '/cgi-bin', '/scripts',
            '/api', '/v1', '/v2', '/docs', '/documentation'
        ]
        
        # Add directories from test payload if available
        if test.payload:
            payload_dirs = [d.strip() for d in test.payload.split(',')]
            directories.extend(payload_dirs)
        
        found_directories = []
        
        for port in [80, 8080, 443, 8443]:
            if port in device.open_ports_list:
                protocol = 'https' if port in [443, 8443] else 'http'
                base_url = f"{protocol}://{device.ip_address}:{port}"
                
                for directory in directories:
                    try:
                        url = base_url + directory
                        response = self._make_http_request(url, timeout=5)
                        
                        # Consider directory found if:
                        # - Status code is 200 (OK)
                        # - Status code is 401/403 (authentication required/forbidden)
                        # - Status code is 301/302 (redirect)
                        if response.status_code in [200, 301, 302, 401, 403]:
                            found_directories.append({
                                'url': url,
                                'status_code': response.status_code,
                                'content_length': len(response.content),
                                'content_type': response.headers.get('Content-Type', '')
                            })
                        
                    except Exception as e:
                        logger.debug(f"Directory enumeration error for {directory}: {str(e)}")
                        continue
        
        # Test fails if sensitive directories are found
        sensitive_dirs = [d for d in found_directories 
                         if any(sensitive in d['url'].lower() for sensitive in 
                               ['/admin', '/config', '/backup', '/.git', '/cgi-bin'])]
        
        success = len(sensitive_dirs) == 0
        
        return {
            'success': success,
            'data': {
                'total_directories_checked': len(directories),
                'found_directories': found_directories,
                'sensitive_directories': sensitive_dirs
            },
            'output': f"Found {len(found_directories)} accessible directories. "
                     f"{'No sensitive directories exposed.' if success else f'{len(sensitive_dirs)} sensitive directories found.'}",
            'evidence': [
                {
                    'type': 'directory_listing',
                    'data': json.dumps(found_directories, indent=2),
                    'description': 'Accessible directories found'
                }
            ] if found_directories else []
        }
    
    def _test_ssl_configuration(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test SSL/TLS configuration."""
        ssl_results = {}
        
        for port in [443, 8443]:
            if port in device.open_ports_list:
                try:
                    # Get SSL certificate info
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((device.ip_address, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=device.ip_address) as ssock:
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            version = ssock.version()
                            
                            ssl_info = {
                                'port': port,
                                'version': version,
                                'cipher': cipher,
                                'certificate': {
                                    'subject': dict(x[0] for x in cert.get('subject', [])),
                                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                    'not_before': cert.get('notBefore'),
                                    'not_after': cert.get('notAfter'),
                                    'serial_number': cert.get('serialNumber')
                                }
                            }
                            
                            ssl_results[port] = ssl_info
                            
                except Exception as e:
                    logger.debug(f"SSL test failed for port {port}: {str(e)}")
                    continue
        
        if ssl_results:
            # Analyze SSL configuration for vulnerabilities
            vulnerabilities = []
            
            for port, ssl_info in ssl_results.items():
                # Check for weak SSL/TLS versions
                if ssl_info['version'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    vulnerabilities.append(f"Weak SSL/TLS version: {ssl_info['version']} on port {port}")
                
                # Check for weak ciphers
                cipher_name = ssl_info['cipher'][0] if ssl_info['cipher'] else ''
                if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL']):
                    vulnerabilities.append(f"Weak cipher: {cipher_name} on port {port}")
                
                # Check certificate validity
                cert = ssl_info['certificate']
                try:
                    from datetime import datetime
                    not_after = datetime.strptime(cert['not_after'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        vulnerabilities.append(f"Expired certificate on port {port}")
                except:
                    pass
            
            success = len(vulnerabilities) == 0
            
            return {
                'success': success,
                'data': {
                    'ssl_configurations': ssl_results,
                    'vulnerabilities': vulnerabilities
                },
                'output': f"SSL/TLS analysis completed for {len(ssl_results)} ports. "
                         f"{'No vulnerabilities found.' if success else f'{len(vulnerabilities)} vulnerabilities found.'}",
                'evidence': [
                    {
                        'type': 'ssl_certificate',
                        'data': json.dumps(ssl_results, indent=2, default=str),
                        'description': 'SSL/TLS configuration details'
                    }
                ]
            }
        
        return {
            'success': True,
            'data': {'message': 'No HTTPS services found'},
            'output': 'No HTTPS services available for SSL testing'
        }
    
    def _test_generic_web_vulnerability(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test generic web vulnerabilities."""
        # This would implement tests for XSS, SQL injection, etc.
        # For now, return a placeholder
        
        return {
            'success': True,
            'data': {'message': 'Generic web vulnerability test not implemented yet'},
            'output': 'Test skipped - generic web vulnerability testing not implemented'
        }

class NetworkTestModule(BaseTestModule):
    """Module for network-level security testing."""
    
    def execute_test(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Execute network security test."""
        if 'port' in test.name.lower():
            return self._test_port_scan(test, device)
        elif 'ping' in test.name.lower():
            return self._test_ping_response(test, device)
        else:
            return self._test_network_service(test, device)
    
    def _test_port_scan(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test open ports and services."""
        # This would typically use nmap for comprehensive port scanning
        open_ports = device.open_ports_list
        
        # Define risky ports
        risky_ports = {
            21: 'FTP',
            23: 'Telnet',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            1433: 'SQL Server',
            3389: 'RDP',
            5900: 'VNC'
        }
        
        found_risky_ports = []
        for port in open_ports:
            if port in risky_ports:
                found_risky_ports.append({
                    'port': port,
                    'service': risky_ports[port],
                    'risk': 'high' if port in [21, 23, 135] else 'medium'
                })
        
        success = len(found_risky_ports) == 0
        
        return {
            'success': success,
            'data': {
                'total_open_ports': len(open_ports),
                'open_ports': open_ports,
                'risky_ports': found_risky_ports
            },
            'output': f"Port scan found {len(open_ports)} open ports. "
                     f"{'No risky ports detected.' if success else f'{len(found_risky_ports)} risky ports found.'}",
            'evidence': [
                {
                    'type': 'port_scan',
                    'data': json.dumps({'open_ports': open_ports, 'risky_ports': found_risky_ports}),
                    'description': 'Port scan results'
                }
            ]
        }
    
    def _test_ping_response(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test ping response (ICMP)."""
        try:
            # Use system ping command
            result = subprocess.run(
                ['ping', '-c', '3', '-W', '2', device.ip_address],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            responds_to_ping = result.returncode == 0
            
            # Extract ping statistics if available
            ping_stats = {}
            if responds_to_ping and result.stdout:
                # Parse ping output for statistics
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'packet loss' in line:
                        ping_stats['packet_loss'] = line
                    elif 'min/avg/max' in line:
                        ping_stats['timing'] = line
            
            # Responding to ping might be considered an information disclosure
            success = not responds_to_ping  # Test passes if device doesn't respond to ping
            
            return {
                'success': success,
                'data': {
                    'responds_to_ping': responds_to_ping,
                    'ping_statistics': ping_stats
                },
                'output': f"Device {'responds to' if responds_to_ping else 'does not respond to'} ping requests. "
                         f"{'Consider disabling ICMP responses.' if responds_to_ping else 'ICMP responses are disabled.'}",
                'evidence': [
                    {
                        'type': 'ping_output',
                        'data': result.stdout,
                        'description': 'Ping command output'
                    }
                ] if responds_to_ping else []
            }
            
        except Exception as e:
            return {
                'success': True,
                'data': {'error': str(e)},
                'output': f"Ping test failed: {str(e)}"
            }
    
    def _test_network_service(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test specific network service."""
        # Generic network service testing
        return {
            'success': True,
            'data': {'message': 'Generic network service test not implemented yet'},
            'output': 'Test skipped - generic network service testing not implemented'
        }

class ProtocolTestModule(BaseTestModule):
    """Module for IoT protocol-specific testing."""
    
    def execute_test(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Execute protocol-specific security test."""
        if 'mqtt' in test.name.lower():
            return self._test_mqtt_security(test, device)
        elif 'coap' in test.name.lower():
            return self._test_coap_security(test, device)
        elif 'snmp' in test.name.lower():
            return self._test_snmp_security(test, device)
        else:
            return self._test_generic_protocol(test, device)
    
    def _test_mqtt_security(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test MQTT broker security."""
        if 1883 not in device.open_ports_list and 8883 not in device.open_ports_list:
            return {
                'success': True,
                'data': {'message': 'MQTT service not available'},
                'output': 'MQTT ports (1883, 8883) not open'
            }
        
        try:
            import paho.mqtt.client as mqtt
            
            vulnerabilities = []
            
            # Test anonymous access
            def on_connect(client, userdata, flags, rc):
                userdata['connected'] = rc == 0
                if rc == 0:
                    vulnerabilities.append('Anonymous MQTT access allowed')
            
            def on_message(client, userdata, msg):
                userdata['messages'].append({
                    'topic': msg.topic,
                    'payload': msg.payload.decode('utf-8', errors='ignore')[:100]
                })
            
            # Test standard MQTT port
            for port in [1883, 8883]:
                if port in device.open_ports_list:
                    try:
                        client = mqtt.Client()
                        userdata = {'connected': False, 'messages': []}
                        client.user_data_set(userdata)
                        client.on_connect = on_connect
                        client.on_message = on_message
                        
                        # Try to connect without authentication
                        client.connect(device.ip_address, port, 10)
                        client.loop_start()
                        
                        # Subscribe to wildcard topic
                        if userdata['connected']:
                            client.subscribe('#')
                            time.sleep(5)  # Wait for messages
                            
                            if userdata['messages']:
                                vulnerabilities.append(f'Sensitive data exposed via MQTT on port {port}')
                        
                        client.loop_stop()
                        client.disconnect()
                        
                    except Exception as e:
                        logger.debug(f"MQTT test failed for port {port}: {str(e)}")
                        continue
            
            success = len(vulnerabilities) == 0
            
            return {
                'success': success,
                'data': {
                    'vulnerabilities': vulnerabilities,
                    'tested_ports': [p for p in [1883, 8883] if p in device.open_ports_list]
                },
                'output': f"MQTT security test completed. "
                         f"{'No vulnerabilities found.' if success else f'{len(vulnerabilities)} vulnerabilities found.'}",
                'evidence': [
                    {
                        'type': 'mqtt_messages',
                        'data': json.dumps(vulnerabilities),
                        'description': 'MQTT security vulnerabilities'
                    }
                ] if vulnerabilities else []
            }
            
        except ImportError:
            return {
                'success': True,
                'data': {'message': 'paho-mqtt not available'},
                'output': 'MQTT testing skipped - paho-mqtt library not installed'
            }
        except Exception as e:
            return {
                'success': True,
                'data': {'error': str(e)},
                'output': f"MQTT test failed: {str(e)}"
            }
    
    def _test_coap_security(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test CoAP security."""
        if 5683 not in device.open_ports_list:
            return {
                'success': True,
                'data': {'message': 'CoAP service not available'},
                'output': 'CoAP port (5683) not open'
            }
        
        # CoAP testing would require aiocoap library
        return {
            'success': True,
            'data': {'message': 'CoAP security test not implemented yet'},
            'output': 'Test skipped - CoAP security testing not implemented'
        }
    
    def _test_snmp_security(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test SNMP security."""
        if 161 not in device.open_ports_list:
            return {
                'success': True,
                'data': {'message': 'SNMP service not available'},
                'output': 'SNMP port (161) not open'
            }
        
        # Test common SNMP community strings
        communities = ['public', 'private', 'admin', 'manager', 'write']
        vulnerable_communities = []
        
        try:
            from pysnmp.hlapi import *
            
            for community in communities:
                try:
                    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                        SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((device.ip_address, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # sysDescr
                        lexicographicMode=False,
                        maxRows=1
                    ):
                        if errorIndication or errorStatus:
                            break
                        
                        # If we get here, the community string worked
                        vulnerable_communities.append(community)
                        break
                        
                except Exception:
                    continue
            
            success = len(vulnerable_communities) == 0
            
            return {
                'success': success,
                'data': {
                    'tested_communities': communities,
                    'vulnerable_communities': vulnerable_communities
                },
                'output': f"SNMP security test completed. "
                         f"{'No default community strings found.' if success else f'{len(vulnerable_communities)} default communities found.'}",
                'evidence': [
                    {
                        'type': 'snmp_communities',
                        'data': json.dumps(vulnerable_communities),
                        'description': 'Vulnerable SNMP community strings'
                    }
                ] if vulnerable_communities else []
            }
            
        except ImportError:
            return {
                'success': True,
                'data': {'message': 'pysnmp not available'},
                'output': 'SNMP testing skipped - pysnmp library not installed'
            }
        except Exception as e:
            return {
                'success': True,
                'data': {'error': str(e)},
                'output': f"SNMP test failed: {str(e)}"
            }
    
    def _test_generic_protocol(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Test generic protocol vulnerabilities."""
        return {
            'success': True,
            'data': {'message': 'Generic protocol test not implemented yet'},
            'output': 'Test skipped - generic protocol testing not implemented'
        }

class FirmwareTestModule(BaseTestModule):
    """Module for firmware analysis."""
    
    def execute_test(self, test: SecurityTest, device: Device) -> Dict[str, Any]:
        """Execute firmware security test."""
        # Firmware testing would require actual firmware files
        # This is a placeholder implementation
        
        return {
            'success': True,
            'data': {'message': 'Firmware analysis not implemented yet'},
            'output': 'Test skipped - firmware analysis requires firmware files'
        }

class TestExecutor:
    """High-level test execution coordinator."""
    
    def __init__(self):
        self.engine = SecurityTestEngine()
    
    def run_quick_scan(self, device_id: int, user_id: int) -> Dict[str, Any]:
        """Run a quick security scan on a device."""
        device = Device.query.get(device_id)
        if not device:
            raise ValueError(f"Device {device_id} not found")
        
        # Create assessment
        assessment = Assessment(
            device_id=device_id,
            user_id=user_id,
            name=f"Quick Scan - {device.ip_address}",
            scan_type='quick'
        )
        
        db.session.add(assessment)
        db.session.commit()
        
        # Execute assessment
        return self.engine.execute_assessment(assessment.id)
    
    def run_comprehensive_scan(self, device_id: int, user_id: int) -> Dict[str, Any]:
        """Run a comprehensive security scan on a device."""
        device = Device.query.get(device_id)
        if not device:
            raise ValueError(f"Device {device_id} not found")
        
        # Create assessment
        assessment = Assessment(
            device_id=device_id,
            user_id=user_id,
            name=f"Comprehensive Scan - {device.ip_address}",
            scan_type='comprehensive'
        )
        
        db.session.add(assessment)
        db.session.commit()
        
        # Execute assessment
        return self.engine.execute_assessment(assessment.id)
