"""
Report generation API endpoints
"""

from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import desc
import os
import json
from datetime import datetime

from app import db
from app.models.assessment import Assessment
from app.models.device import Device
from app.models.vulnerability import Vulnerability
from app.utils.decorators import (
    require_api_auth, require_permission, handle_exceptions, 
    validate_json, rate_limit, log_activity
)

reports_api_bp = Blueprint('reports_api', __name__)

@reports_api_bp.route('/assessments/<int:assessment_id>', methods=['GET'])
@require_api_auth
@require_permission('view_reports')
@handle_exceptions()
def get_assessment_report(assessment_id):
    """Generate assessment report."""
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found'}), 404
    
    if assessment.status != 'completed':
        return jsonify({'error': 'Report can only be generated for completed assessments'}), 400
    
    # Get report format
    format_type = request.args.get('format', 'json')
    
    try:
        report_data = generate_assessment_report_data(assessment)
        
        if format_type == 'json':
            return jsonify(report_data), 200
        elif format_type == 'pdf':
            # In a real implementation, generate PDF using reportlab or weasyprint
            return jsonify({'error': 'PDF format not yet implemented'}), 501
        else:
            return jsonify({'error': 'Unsupported format. Use json or pdf'}), 400
            
    except Exception as e:
        current_app.logger.error(f"Report generation error: {str(e)}")
        return jsonify({'error': 'Failed to generate report'}), 500

@reports_api_bp.route('/assessments/<int:assessment_id>/summary', methods=['GET'])
@require_api_auth
@require_permission('view_reports')
@handle_exceptions()
def get_assessment_summary(assessment_id):
    """Get assessment summary report."""
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found'}), 404
    
    summary = {
        'assessment': {
            'id': assessment.id,
            'name': assessment.name,
            'device_ip': assessment.device.ip_address,
            'device_type': assessment.device.device_type,
            'scan_type': assessment.scan_type,
            'status': assessment.status,
            'created_at': assessment.created_at.isoformat(),
            'completed_at': assessment.completed_at.isoformat() if assessment.completed_at else None,
            'duration': str(assessment.duration) if assessment.duration else None
        },
        'results': {
            'total_tests': assessment.total_tests,
            'passed_tests': assessment.passed_tests,
            'failed_tests': assessment.failed_tests,
            'error_tests': assessment.error_tests,
            'skipped_tests': assessment.skipped_tests,
            'risk_score': assessment.risk_score,
            'security_grade': assessment.security_grade
        },
        'vulnerabilities': {
            'total': assessment.total_vulnerabilities,
            'critical': assessment.critical_vulns,
            'high': assessment.high_vulns,
            'medium': assessment.medium_vulns,
            'low': assessment.low_vulns,
            'info': assessment.info_vulns
        }
    }
    
    return jsonify(summary), 200

@reports_api_bp.route('/devices/<int:device_id>/history', methods=['GET'])
@require_api_auth
@require_permission('view_reports')
@handle_exceptions()
def get_device_history_report(device_id):
    """Get device assessment history report."""
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    # Get all assessments for this device
    assessments = Assessment.get_assessments_by_device(device_id)
    
    # Get query parameters
    limit = min(request.args.get('limit', 10, type=int), 100)
    
    history_data = {
        'device': device.to_dict(),
        'assessment_history': [],
        'trends': {
            'risk_score_trend': [],
            'vulnerability_trend': []
        }
    }
    
    # Process assessments
    completed_assessments = [a for a in assessments if a.status == 'completed'][:limit]
    
    for assessment in completed_assessments:
        history_data['assessment_history'].append({
            'id': assessment.id,
            'name': assessment.name,
            'completed_at': assessment.completed_at.isoformat() if assessment.completed_at else None,
            'risk_score': assessment.risk_score,
            'security_grade': assessment.security_grade,
            'total_vulnerabilities': assessment.total_vulnerabilities,
            'critical_vulns': assessment.critical_vulns,
            'high_vulns': assessment.high_vulns
        })
        
        # Add to trends
        if assessment.completed_at:
            history_data['trends']['risk_score_trend'].append({
                'date': assessment.completed_at.date().isoformat(),
                'risk_score': assessment.risk_score
            })
            
            history_data['trends']['vulnerability_trend'].append({
                'date': assessment.completed_at.date().isoformat(),
                'total_vulnerabilities': assessment.total_vulnerabilities
            })
    
    return jsonify(history_data), 200

@reports_api_bp.route('/dashboard', methods=['GET'])
@require_api_auth
@require_permission('view_reports')
@handle_exceptions()
def get_dashboard_report():
    """Get dashboard overview report."""
    # Get date range
    days = request.args.get('days', 30, type=int)
    from datetime import timedelta
    
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Overall statistics
    stats = {
        'total_devices': Device.query.count(),
        'active_devices': Device.query.filter_by(is_active=True).count(),
        'total_assessments': Assessment.query.count(),
        'completed_assessments': Assessment.query.filter_by(status='completed').count(),
        'running_assessments': Assessment.query.filter_by(status='running').count(),
        'total_vulnerabilities': Vulnerability.query.count()
    }
    
    # Recent activity
    recent_assessments = Assessment.query.filter(
        Assessment.created_at >= start_date
    ).order_by(desc(Assessment.created_at)).limit(20).all()
    
    # Risk distribution
    risk_distribution = db.session.query(
        Device.risk_level,
        db.func.count(Device.id)
    ).group_by(Device.risk_level).all()
    
    # Device type distribution
    device_type_distribution = db.session.query(
        Device.device_type,
        db.func.count(Device.id)
    ).filter(Device.device_type.isnot(None)).group_by(Device.device_type).all()
    
    # Top vulnerabilities
    vulnerability_stats = db.session.query(
        Vulnerability.severity,
        db.func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity).all()
    
    report_data = {
        'generated_at': datetime.utcnow().isoformat(),
        'period': {
            'start_date': start_date.date().isoformat(),
            'end_date': end_date.date().isoformat(),
            'days': days
        },
        'statistics': stats,
        'recent_activity': [assessment.to_dict() for assessment in recent_assessments],
        'distributions': {
            'risk_levels': dict(risk_distribution),
            'device_types': dict(device_type_distribution),
            'vulnerability_severity': dict(vulnerability_stats)
        }
    }
    
    return jsonify(report_data), 200

@reports_api_bp.route('/vulnerabilities', methods=['GET'])
@require_api_auth
@require_permission('view_reports')
@handle_exceptions()
def get_vulnerability_report():
    """Get vulnerability report."""
    # Get query parameters
    severity = request.args.get('severity', '')
    limit = min(request.args.get('limit', 50, type=int), 200)
    
    query = Vulnerability.query
    
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    
    vulnerabilities = query.order_by(desc(Vulnerability.created_at)).limit(limit).all()
    
    # Group by severity
    severity_groups = {}
    for vuln in vulnerabilities:
        if vuln.severity not in severity_groups:
            severity_groups[vuln.severity] = []
        severity_groups[vuln.severity].append(vuln.to_dict())
    
    # Statistics
    stats = {
        'total_vulnerabilities': len(vulnerabilities),
        'by_severity': {},
        'exploitable_count': len([v for v in vulnerabilities if v.is_exploitable]),
        'with_exploit_count': len([v for v in vulnerabilities if v.exploit_available])
    }
    
    # Count by severity
    for vuln in vulnerabilities:
        severity_key = vuln.severity
        stats['by_severity'][severity_key] = stats['by_severity'].get(severity_key, 0) + 1
    
    report_data = {
        'generated_at': datetime.utcnow().isoformat(),
        'statistics': stats,
        'vulnerabilities_by_severity': severity_groups,
        'total_count': len(vulnerabilities)
    }
    
    return jsonify(report_data), 200

def generate_assessment_report_data(assessment):
    """Generate comprehensive assessment report data."""
    report_data = {
        'report_info': {
            'generated_at': datetime.utcnow().isoformat(),
            'report_type': 'security_assessment',
            'version': '1.0'
        },
        'assessment': assessment.to_dict(include_results=True),
        'device': assessment.device.to_dict(),
        'executive_summary': {
            'overall_risk': assessment.security_grade,
            'risk_score': assessment.risk_score,
            'total_tests': assessment.total_tests,
            'vulnerabilities_found': assessment.total_vulnerabilities,
            'critical_issues': assessment.critical_vulns,
            'recommendations': generate_recommendations(assessment)
        },
        'detailed_findings': [],
        'test_results': []
    }
    
    # Add detailed findings for failed tests
    from app.models.test_result import TestResult
    failed_results = TestResult.query.filter_by(
        assessment_id=assessment.id,
        status='fail'
    ).all()
    
    for result in failed_results:
        finding = {
            'test_name': result.security_test.name if result.security_test else 'Unknown',
            'severity': result.effective_severity,
            'status': result.status,
            'risk_score': result.risk_score,
            'description': result.security_test.description if result.security_test else '',
            'evidence': result.evidence_list,
            'remediation': result.vulnerability.remediation if result.vulnerability else None
        }
        report_data['detailed_findings'].append(finding)
    
    # Add all test results
    all_results = TestResult.query.filter_by(assessment_id=assessment.id).all()
    for result in all_results:
        test_result = {
            'test_name': result.security_test.name if result.security_test else 'Unknown',
            'status': result.status,
            'execution_time': result.execution_time,
            'severity': result.effective_severity,
            'output': result.output[:500] if result.output else None  # Truncate output
        }
        report_data['test_results'].append(test_result)
    
    return report_data

def generate_recommendations(assessment):
    """Generate security recommendations based on assessment results."""
    recommendations = []
    
    if assessment.critical_vulns > 0:
        recommendations.append({
            'priority': 'critical',
            'title': 'Address Critical Vulnerabilities',
            'description': f'Found {assessment.critical_vulns} critical vulnerabilities that require immediate attention.'
        })
    
    if assessment.high_vulns > 0:
        recommendations.append({
            'priority': 'high',
            'title': 'Fix High-Risk Issues',
            'description': f'Found {assessment.high_vulns} high-risk vulnerabilities that should be addressed soon.'
        })
    
    if assessment.device.device_type == 'camera':
        recommendations.append({
            'priority': 'medium',
            'title': 'Camera Security Best Practices',
            'description': 'Ensure camera firmware is up to date and change default credentials.'
        })
    
    # Generic recommendations
    recommendations.extend([
        {
            'priority': 'medium',
            'title': 'Regular Security Assessments',
            'description': 'Schedule regular security assessments to maintain security posture.'
        },
        {
            'priority': 'low',
            'title': 'Network Segmentation',
            'description': 'Consider placing IoT devices on a separate network segment.'
        }
    ])
    
    return recommendations

# Error handlers
@reports_api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Resource not found'}), 404

@reports_api_bp.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    return jsonify({'error': 'Access forbidden'}), 403

@reports_api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500
