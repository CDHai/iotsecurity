"""
Dashboard web interface
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func, desc
from datetime import datetime, timedelta

from app import db
from app.models.device import Device
from app.models.assessment import Assessment
from app.models.test_result import TestResult
from app.models.vulnerability import Vulnerability
from app.utils.decorators import handle_exceptions, require_permission

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
@handle_exceptions()
def index():
    """Main dashboard page."""
    # Get dashboard statistics
    stats = get_dashboard_stats()
    
    # Get recent activities
    recent_assessments = Assessment.get_recent_assessments(limit=5)
    recent_devices = Device.query.filter_by(is_active=True).order_by(desc(Device.last_seen)).limit(5).all()
    
    # Get vulnerability trends (last 30 days)
    vulnerability_trends = get_vulnerability_trends()
    
    # Get device type distribution
    device_distribution = get_device_type_distribution()
    
    return render_template('dashboard/index.html',
                         stats=stats,
                         recent_assessments=recent_assessments,
                         recent_devices=recent_devices,
                         vulnerability_trends=vulnerability_trends,
                         device_distribution=device_distribution)

@dashboard_bp.route('/api/stats')
@login_required
@handle_exceptions()
def api_stats():
    """API endpoint for dashboard statistics."""
    stats = get_dashboard_stats()
    return jsonify(stats)

@dashboard_bp.route('/api/recent-activity')
@login_required
@handle_exceptions()
def api_recent_activity():
    """API endpoint for recent activity."""
    limit = request.args.get('limit', 10, type=int)
    
    recent_assessments = Assessment.get_recent_assessments(limit=limit)
    recent_devices = Device.query.filter_by(is_active=True).order_by(desc(Device.last_seen)).limit(limit).all()
    
    return jsonify({
        'assessments': [assessment.to_dict() for assessment in recent_assessments],
        'devices': [device.to_dict() for device in recent_devices]
    })

@dashboard_bp.route('/api/vulnerability-trends')
@login_required
@handle_exceptions()
def api_vulnerability_trends():
    """API endpoint for vulnerability trends."""
    days = request.args.get('days', 30, type=int)
    trends = get_vulnerability_trends(days=days)
    return jsonify(trends)

@dashboard_bp.route('/api/device-distribution')
@login_required
@handle_exceptions()
def api_device_distribution():
    """API endpoint for device type distribution."""
    distribution = get_device_type_distribution()
    return jsonify(distribution)

@dashboard_bp.route('/api/assessment-status')
@login_required
@handle_exceptions()
def api_assessment_status():
    """API endpoint for assessment status overview."""
    if not current_user.can_access('read'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Get assessment status counts
    status_counts = db.session.query(
        Assessment.status,
        func.count(Assessment.id).label('count')
    ).group_by(Assessment.status).all()
    
    status_data = {status: count for status, count in status_counts}
    
    # Get running assessments details
    running_assessments = Assessment.get_running_assessments()
    
    return jsonify({
        'status_counts': status_data,
        'running_assessments': [assessment.to_dict() for assessment in running_assessments]
    })

@dashboard_bp.route('/api/security-overview')
@login_required
@handle_exceptions()
def api_security_overview():
    """API endpoint for security overview."""
    if not current_user.can_access('read'):
        return jsonify({'error': 'Access denied'}), 403
    
    # Get high-risk devices
    high_risk_devices = Device.get_high_risk_devices()
    
    # Get critical vulnerabilities
    critical_vulns = Vulnerability.get_critical_vulnerabilities()
    
    # Get recent failed tests
    recent_failures = TestResult.get_failed_results()[:10]
    
    return jsonify({
        'high_risk_devices': [device.to_dict() for device in high_risk_devices],
        'critical_vulnerabilities': [vuln.to_dict() for vuln in critical_vulns],
        'recent_failures': [result.to_dict() for result in recent_failures]
    })

def get_dashboard_stats():
    """Get dashboard statistics."""
    # Device statistics
    total_devices = Device.query.count()
    active_devices = Device.query.filter_by(is_active=True).count()
    high_risk_devices = Device.query.filter(Device.risk_level.in_(['high', 'critical'])).count()
    
    # Assessment statistics
    total_assessments = Assessment.query.count()
    running_assessments = Assessment.query.filter_by(status='running').count()
    completed_assessments = Assessment.query.filter_by(status='completed').count()
    
    # Get assessments from last 7 days
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_assessments = Assessment.query.filter(Assessment.created_at >= week_ago).count()
    
    # Vulnerability statistics
    total_vulnerabilities = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
    high_vulns = Vulnerability.query.filter_by(severity='high').count()
    
    # Test result statistics
    total_tests = TestResult.query.count()
    failed_tests = TestResult.query.filter_by(status='fail').count()
    
    # Calculate success rate
    success_rate = ((total_tests - failed_tests) / total_tests * 100) if total_tests > 0 else 0
    
    return {
        'devices': {
            'total': total_devices,
            'active': active_devices,
            'high_risk': high_risk_devices,
            'offline': total_devices - active_devices
        },
        'assessments': {
            'total': total_assessments,
            'running': running_assessments,
            'completed': completed_assessments,
            'recent': recent_assessments
        },
        'vulnerabilities': {
            'total': total_vulnerabilities,
            'critical': critical_vulns,
            'high': high_vulns
        },
        'tests': {
            'total': total_tests,
            'failed': failed_tests,
            'success_rate': round(success_rate, 1)
        }
    }

def get_vulnerability_trends(days=30):
    """Get vulnerability trends for the last N days."""
    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=days)
    
    # Query assessments by day
    trends = db.session.query(
        func.date(Assessment.completed_at).label('date'),
        func.sum(Assessment.critical_vulns).label('critical'),
        func.sum(Assessment.high_vulns).label('high'),
        func.sum(Assessment.medium_vulns).label('medium'),
        func.sum(Assessment.low_vulns).label('low')
    ).filter(
        Assessment.completed_at.between(start_date, end_date),
        Assessment.status == 'completed'
    ).group_by(
        func.date(Assessment.completed_at)
    ).order_by('date').all()
    
    # Format data for chart
    trend_data = []
    for trend in trends:
        trend_data.append({
            'date': trend.date.isoformat(),
            'critical': trend.critical or 0,
            'high': trend.high or 0,
            'medium': trend.medium or 0,
            'low': trend.low or 0
        })
    
    return trend_data

def get_device_type_distribution():
    """Get device type distribution."""
    distribution = db.session.query(
        Device.device_type,
        func.count(Device.id).label('count')
    ).filter(
        Device.is_active == True,
        Device.device_type.isnot(None)
    ).group_by(Device.device_type).all()
    
    # Format data for chart
    distribution_data = []
    for device_type, count in distribution:
        distribution_data.append({
            'type': device_type or 'Unknown',
            'count': count
        })
    
    return distribution_data

@dashboard_bp.route('/health')
def health_check():
    """Health check endpoint."""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Error handlers
@dashboard_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('errors/404.html'), 404

@dashboard_bp.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    return render_template('errors/403.html'), 403

@dashboard_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    db.session.rollback()
    return render_template('errors/500.html'), 500
