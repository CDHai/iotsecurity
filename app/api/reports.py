from flask import jsonify, request, current_app, send_file
from flask_login import login_required, current_user
from app.api import api_bp
from app.models import Assessment, Device, TestResult
from app import db
import json
import os
from datetime import datetime

@api_bp.route('/reports', methods=['GET'])
@login_required
def get_reports():
    """Get list of generated reports"""
    try:
        # For now, return assessments as reports
        # In a real implementation, you'd have a separate Report model
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        query = Assessment.query.filter(Assessment.status == 'completed')
        
        # Filter by user role
        if not current_user.is_admin():
            query = query.filter(Assessment.user_id == current_user.id)
        
        query = query.order_by(Assessment.completed_at.desc())
        
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        assessments = pagination.items
        
        return jsonify({
            'success': True,
            'data': {
                'reports': [assessment.get_assessment_info() for assessment in assessments],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                }
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting reports: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load reports'
        }), 500

@api_bp.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    """Generate security report"""
    try:
        data = request.get_json()
        assessment_id = data.get('assessment_id')
        report_type = data.get('report_type', 'technical')
        format_type = data.get('format', 'json')
        
        if not assessment_id:
            return jsonify({
                'success': False,
                'error': 'Assessment ID is required'
            }), 400
        
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Check permissions
        if not current_user.is_admin() and assessment.user_id != current_user.id:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        if assessment.status != 'completed':
            return jsonify({
                'success': False,
                'error': 'Assessment must be completed to generate report'
            }), 400
        
        # Generate report data
        report_data = generate_report_data(assessment, report_type)
        
        if format_type == 'json':
            return jsonify({
                'success': True,
                'data': report_data
            })
        elif format_type == 'pdf':
            # TODO: Implement PDF generation
            return jsonify({
                'success': False,
                'error': 'PDF generation not implemented yet'
            }), 501
        else:
            return jsonify({
                'success': False,
                'error': 'Unsupported format'
            }), 400
        
    except Exception as e:
        current_app.logger.error(f"Error generating report: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to generate report'
        }), 500

@api_bp.route('/reports/export/<int:assessment_id>', methods=['GET'])
@login_required
def export_report(assessment_id):
    """Export report in various formats"""
    try:
        format_type = request.args.get('format', 'json')
        
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Check permissions
        if not current_user.is_admin() and assessment.user_id != current_user.id:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        if assessment.status != 'completed':
            return jsonify({
                'success': False,
                'error': 'Assessment must be completed to export report'
            }), 400
        
        # Generate report data
        report_data = generate_report_data(assessment, 'comprehensive')
        
        if format_type == 'json':
            return jsonify({
                'success': True,
                'data': report_data
            })
        elif format_type == 'csv':
            # TODO: Implement CSV export
            return jsonify({
                'success': False,
                'error': 'CSV export not implemented yet'
            }), 501
        else:
            return jsonify({
                'success': False,
                'error': 'Unsupported format'
            }), 400
        
    except Exception as e:
        current_app.logger.error(f"Error exporting report: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to export report'
        }), 500

def generate_report_data(assessment, report_type):
    """Generate report data based on assessment"""
    device = assessment.device
    test_results = assessment.test_results.all()
    
    # Calculate statistics
    total_tests = len(test_results)
    passed_tests = len([r for r in test_results if r.status == 'pass'])
    failed_tests = len([r for r in test_results if r.status == 'fail'])
    error_tests = len([r for r in test_results if r.status == 'error'])
    
    # Group findings by severity
    findings_by_severity = {}
    for result in test_results:
        if result.status == 'fail':
            severity = result.severity or 'medium'
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append({
                'test_name': result.security_test.name,
                'description': result.security_test.description,
                'evidence': result.get_evidence_dict(),
                'remediation': result.remediation or result.security_test.remediation
            })
    
    # Generate report based on type
    if report_type == 'executive':
        report_data = {
            'report_type': 'executive',
            'assessment_id': assessment.id,
            'device_info': {
                'ip_address': device.ip_address,
                'device_type': device.device_type.value if device.device_type else 'unknown',
                'manufacturer': device.manufacturer,
                'model': device.model
            },
            'summary': {
                'risk_score': assessment.risk_score,
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'error_tests': error_tests
            },
            'key_findings': {
                'critical': len(findings_by_severity.get('critical', [])),
                'high': len(findings_by_severity.get('high', [])),
                'medium': len(findings_by_severity.get('medium', [])),
                'low': len(findings_by_severity.get('low', []))
            },
            'recommendations': generate_recommendations(findings_by_severity)
        }
    else:  # technical report
        report_data = {
            'report_type': 'technical',
            'assessment_id': assessment.id,
            'device_info': device.get_device_info(),
            'assessment_info': assessment.get_assessment_info(),
            'test_results': [result.get_test_result_info() for result in test_results],
            'findings_by_severity': findings_by_severity,
            'statistics': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'error_tests': error_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'recommendations': generate_recommendations(findings_by_severity)
        }
    
    return report_data

def generate_recommendations(findings_by_severity):
    """Generate recommendations based on findings"""
    recommendations = []
    
    if findings_by_severity.get('critical'):
        recommendations.append({
            'priority': 'immediate',
            'title': 'Address Critical Vulnerabilities',
            'description': f'Found {len(findings_by_severity["critical"])} critical vulnerabilities that require immediate attention.',
            'actions': [
                'Disconnect device from network if possible',
                'Apply security patches immediately',
                'Change default credentials',
                'Review and update security configurations'
            ]
        })
    
    if findings_by_severity.get('high'):
        recommendations.append({
            'priority': 'high',
            'title': 'Address High-Risk Issues',
            'description': f'Found {len(findings_by_severity["high"])} high-risk vulnerabilities.',
            'actions': [
                'Update firmware to latest version',
                'Enable encryption for communications',
                'Implement proper authentication',
                'Review network security policies'
            ]
        })
    
    if findings_by_severity.get('medium'):
        recommendations.append({
            'priority': 'medium',
            'title': 'Improve Security Posture',
            'description': f'Found {len(findings_by_severity["medium"])} medium-risk issues.',
            'actions': [
                'Implement security headers',
                'Close unnecessary ports',
                'Enable logging and monitoring',
                'Regular security assessments'
            ]
        })
    
    if not recommendations:
        recommendations.append({
            'priority': 'low',
            'title': 'Maintain Security',
            'description': 'No critical or high-risk vulnerabilities found.',
            'actions': [
                'Continue regular security monitoring',
                'Keep firmware updated',
                'Regular security assessments',
                'Follow security best practices'
            ]
        })
    
    return recommendations
