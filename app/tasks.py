"""
Background tasks for IoT Security Framework
"""

from celery import current_app
from app.core.discovery import DeviceDiscoveryService, periodic_network_scan, cleanup_stale_devices_task
from app.core.security_engine import SecurityTestEngine
import logging

logger = logging.getLogger(__name__)

@current_app.task
def discover_network_devices(network_range: str, scan_type: str = 'tcp_connect'):
    """Background task for network device discovery."""
    try:
        discovery_service = DeviceDiscoveryService()
        devices = discovery_service.discover_devices(network_range, scan_type)
        logger.info(f"Network discovery completed. Found {len(devices)} devices")
        return {
            'status': 'success',
            'devices_found': len(devices),
            'devices': [device['ip_address'] for device in devices]
        }
    except Exception as e:
        logger.error(f"Network discovery failed: {str(e)}")
        return {
            'status': 'error',
            'error': str(e)
        }

@current_app.task
def run_security_assessment(assessment_id: int):
    """Background task for running security assessment."""
    try:
        engine = SecurityTestEngine()
        result = engine.execute_assessment(assessment_id)
        logger.info(f"Security assessment {assessment_id} completed")
        return result
    except Exception as e:
        logger.error(f"Security assessment {assessment_id} failed: {str(e)}")
        return {
            'status': 'error',
            'error': str(e)
        }

@current_app.task
def periodic_network_discovery(network_range: str):
    """Periodic network discovery task."""
    return periodic_network_scan(network_range)

@current_app.task
def cleanup_stale_devices(days: int = 7):
    """Cleanup stale devices task."""
    return cleanup_stale_devices_task(days)

@current_app.task
def generate_assessment_report(assessment_id: int):
    """Generate assessment report in background."""
    try:
        from app.models.assessment import Assessment
        from app.utils.report_generator import ReportGenerator
        
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found")
        
        generator = ReportGenerator()
        report_path = generator.generate_pdf_report(assessment)
        
        logger.info(f"Report generated for assessment {assessment_id}: {report_path}")
        return {
            'status': 'success',
            'report_path': report_path
        }
    except Exception as e:
        logger.error(f"Report generation failed for assessment {assessment_id}: {str(e)}")
        return {
            'status': 'error',
            'error': str(e)
        }

@current_app.task
def send_notification_email(user_id: int, subject: str, message: str):
    """Send notification email to user."""
    try:
        from app.models.user import User
        from app.utils.email_sender import EmailSender
        
        user = User.query.get(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")
        
        email_sender = EmailSender()
        email_sender.send_email(user.email, subject, message)
        
        logger.info(f"Notification email sent to user {user_id}")
        return {
            'status': 'success',
            'recipient': user.email
        }
    except Exception as e:
        logger.error(f"Email notification failed for user {user_id}: {str(e)}")
        return {
            'status': 'error',
            'error': str(e)
        }

# Periodic tasks
@current_app.task
def health_check():
    """Simple health check task."""
    return {
        'status': 'healthy',
        'timestamp': current_app.now().isoformat()
    }
