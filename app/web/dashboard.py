from flask import render_template, jsonify, request, current_app
from flask_login import login_required, current_user
from app.web import main_bp
from app.models import Device, Assessment, Vulnerability
from app import db
from sqlalchemy import func
from datetime import datetime, timedelta

@main_bp.route('/')
@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard/index.html')

@main_bp.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Device statistics
        total_devices = Device.query.count()
        online_devices = Device.query.filter_by(status='online').count()
        devices_with_vulns = Device.query.filter(Device.risk_score > 5.0).count()
        
        # Assessment statistics
        total_assessments = Assessment.query.count()
        completed_assessments = Assessment.query.filter_by(status='completed').count()
        running_assessments = Assessment.query.filter_by(status='running').count()
        
        # Vulnerability statistics
        critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
        high_vulns = Vulnerability.query.filter_by(severity='high').count()
        medium_vulns = Vulnerability.query.filter_by(severity='medium').count()
        
        # Recent activity (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_devices = Device.query.filter(Device.discovered_at >= week_ago).count()
        recent_assessments = Assessment.query.filter(Assessment.created_at >= week_ago).count()
        
        # Device type distribution
        device_types = db.session.query(
            Device.device_type, 
            func.count(Device.id)
        ).group_by(Device.device_type).all()
        
        device_type_distribution = {
            device_type.value if device_type else 'unknown': count 
            for device_type, count in device_types
        }
        
        # Risk distribution
        risk_distribution = {
            'critical': Device.query.filter(Device.risk_score >= 8.0).count(),
            'high': Device.query.filter(Device.risk_score >= 6.0, Device.risk_score < 8.0).count(),
            'medium': Device.query.filter(Device.risk_score >= 4.0, Device.risk_score < 6.0).count(),
            'low': Device.query.filter(Device.risk_score >= 2.0, Device.risk_score < 4.0).count(),
            'safe': Device.query.filter(Device.risk_score < 2.0).count()
        }
        
        return jsonify({
            'success': True,
            'data': {
                'devices': {
                    'total': total_devices,
                    'online': online_devices,
                    'with_vulnerabilities': devices_with_vulns,
                    'recent': recent_devices
                },
                'assessments': {
                    'total': total_assessments,
                    'completed': completed_assessments,
                    'running': running_assessments,
                    'recent': recent_assessments
                },
                'vulnerabilities': {
                    'critical': critical_vulns,
                    'high': high_vulns,
                    'medium': medium_vulns
                },
                'device_types': device_type_distribution,
                'risk_distribution': risk_distribution
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load dashboard statistics'
        }), 500

@main_bp.route('/api/dashboard/recent-activity')
@login_required
def recent_activity():
    """Get recent activity for dashboard"""
    try:
        # Recent assessments
        recent_assessments = Assessment.query.order_by(
            Assessment.created_at.desc()
        ).limit(5).all()
        
        # Recent devices
        recent_devices = Device.query.order_by(
            Device.discovered_at.desc()
        ).limit(5).all()
        
        activity_data = {
            'assessments': [
                {
                    'id': assessment.id,
                    'device_ip': assessment.device.ip_address,
                    'status': assessment.status.value,
                    'risk_score': assessment.risk_score,
                    'created_at': assessment.created_at.isoformat(),
                    'device_type': assessment.device.device_type.value if assessment.device.device_type else 'unknown'
                }
                for assessment in recent_assessments
            ],
            'devices': [
                {
                    'id': device.id,
                    'ip_address': device.ip_address,
                    'device_type': device.device_type.value if device.device_type else 'unknown',
                    'manufacturer': device.manufacturer,
                    'risk_score': device.risk_score,
                    'discovered_at': device.discovered_at.isoformat()
                }
                for device in recent_devices
            ]
        }
        
        return jsonify({
            'success': True,
            'data': activity_data
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting recent activity: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load recent activity'
        }), 500

@main_bp.route('/api/dashboard/security-trend')
@login_required
def security_trend():
    """Get security trend data for charts"""
    try:
        # Get data for last 30 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        # Daily device discoveries
        daily_discoveries = db.session.query(
            func.date(Device.discovered_at).label('date'),
            func.count(Device.id).label('count')
        ).filter(
            Device.discovered_at >= start_date
        ).group_by(
            func.date(Device.discovered_at)
        ).all()
        
        # Daily assessments
        daily_assessments = db.session.query(
            func.date(Assessment.created_at).label('date'),
            func.count(Assessment.id).label('count')
        ).filter(
            Assessment.created_at >= start_date
        ).group_by(
            func.date(Assessment.created_at)
        ).all()
        
        # Daily vulnerabilities found
        daily_vulns = db.session.query(
            func.date(TestResult.executed_at).label('date'),
            func.count(TestResult.result_id).label('count')
        ).filter(
            TestResult.executed_at >= start_date,
            TestResult.status == 'fail'
        ).group_by(
            func.date(TestResult.executed_at)
        ).all()
        
        trend_data = {
            'discoveries': [
                {
                    'date': discovery.date.isoformat(),
                    'count': discovery.count
                }
                for discovery in daily_discoveries
            ],
            'assessments': [
                {
                    'date': assessment.date.isoformat(),
                    'count': assessment.count
                }
                for assessment in daily_assessments
            ],
            'vulnerabilities': [
                {
                    'date': vuln.date.isoformat(),
                    'count': vuln.count
                }
                for vuln in daily_vulns
            ]
        }
        
        return jsonify({
            'success': True,
            'data': trend_data
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting security trend: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load security trend data'
        }), 500
