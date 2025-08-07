from flask import jsonify, request, current_app
from flask_login import login_required, current_user
from app.api import api_bp
from app.models import Device, DeviceType, DeviceStatus
from app.core.discovery import NetworkScanner, DeviceClassifier
from app import db
from sqlalchemy import or_, and_
import asyncio

@api_bp.route('/devices', methods=['GET'])
@login_required
def get_devices():
    """Get list of devices with filtering and pagination"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        device_type = request.args.get('device_type')
        manufacturer = request.args.get('manufacturer')
        status = request.args.get('status')
        risk_level = request.args.get('risk_level')
        search = request.args.get('search')
        
        # Build query
        query = Device.query
        
        # Apply filters
        if device_type:
            query = query.filter(Device.device_type == DeviceType(device_type))
        
        if manufacturer:
            query = query.filter(Device.manufacturer.ilike(f'%{manufacturer}%'))
        
        if status:
            query = query.filter(Device.status == DeviceStatus(status))
        
        if risk_level:
            if risk_level == 'critical':
                query = query.filter(Device.risk_score >= 8.0)
            elif risk_level == 'high':
                query = query.filter(and_(Device.risk_score >= 6.0, Device.risk_score < 8.0))
            elif risk_level == 'medium':
                query = query.filter(and_(Device.risk_score >= 4.0, Device.risk_score < 6.0))
            elif risk_level == 'low':
                query = query.filter(and_(Device.risk_score >= 2.0, Device.risk_score < 4.0))
            elif risk_level == 'safe':
                query = query.filter(Device.risk_score < 2.0)
        
        if search:
            query = query.filter(
                or_(
                    Device.ip_address.ilike(f'%{search}%'),
                    Device.hostname.ilike(f'%{search}%'),
                    Device.manufacturer.ilike(f'%{search}%'),
                    Device.model.ilike(f'%{search}%')
                )
            )
        
        # Order by discovery date (newest first)
        query = query.order_by(Device.discovered_at.desc())
        
        # Paginate
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        devices = pagination.items
        
        return jsonify({
            'success': True,
            'data': {
                'devices': [device.get_device_info() for device in devices],
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
        current_app.logger.error(f"Error getting devices: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load devices'
        }), 500

@api_bp.route('/devices/<int:device_id>', methods=['GET'])
@login_required
def get_device(device_id):
    """Get specific device details"""
    try:
        device = Device.query.get_or_404(device_id)
        
        # Get recent assessments for this device
        recent_assessments = device.assessments.order_by(
            Assessment.created_at.desc()
        ).limit(5).all()
        
        device_info = device.get_device_info()
        device_info['recent_assessments'] = [
            assessment.get_assessment_info() 
            for assessment in recent_assessments
        ]
        
        return jsonify({
            'success': True,
            'data': device_info
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting device {device_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load device details'
        }), 500

@api_bp.route('/devices/scan', methods=['POST'])
@login_required
def scan_network():
    """Start network scan for IoT devices"""
    try:
        data = request.get_json()
        network_range = data.get('network_range')
        
        if not network_range:
            return jsonify({
                'success': False,
                'error': 'Network range is required'
            }), 400
        
        # Validate network range format
        if not is_valid_network_range(network_range):
            return jsonify({
                'success': False,
                'error': 'Invalid network range format'
            }), 400
        
        # Start network scan
        scanner = NetworkScanner()
        classifier = DeviceClassifier()
        
        # Run scan asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            devices = loop.run_until_complete(scanner.scan_network_async(network_range))
        finally:
            loop.close()
        
        # Classify and save devices
        discovered_devices = []
        for device in devices:
            # Classify device
            classification = classifier.classify_device(device)
            classifier.update_device_classification(device, classification)
            
            # Save to database
            db.session.add(device)
            discovered_devices.append(device)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': {
                'message': f'Scan completed. Found {len(discovered_devices)} devices.',
                'devices': [device.get_device_info() for device in discovered_devices]
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error scanning network: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to scan network'
        }), 500

@api_bp.route('/devices/<int:device_id>', methods=['PUT'])
@login_required
def update_device(device_id):
    """Update device information"""
    try:
        device = Device.query.get_or_404(device_id)
        data = request.get_json()
        
        # Update allowed fields
        if 'hostname' in data:
            device.hostname = data['hostname']
        
        if 'manufacturer' in data:
            device.manufacturer = data['manufacturer']
        
        if 'model' in data:
            device.model = data['model']
        
        if 'firmware_version' in data:
            device.firmware_version = data['firmware_version']
        
        if 'device_type' in data:
            device.device_type = DeviceType(data['device_type'])
        
        if 'notes' in data:
            device.notes = data['notes']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': device.get_device_info()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error updating device {device_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to update device'
        }), 500

@api_bp.route('/devices/<int:device_id>', methods=['DELETE'])
@login_required
def delete_device(device_id):
    """Delete device"""
    try:
        device = Device.query.get_or_404(device_id)
        
        # Delete related assessments and test results
        for assessment in device.assessments:
            for test_result in assessment.test_results:
                db.session.delete(test_result)
            db.session.delete(assessment)
        
        db.session.delete(device)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Device deleted successfully'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error deleting device {device_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete device'
        }), 500

@api_bp.route('/devices/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_devices():
    """Delete multiple devices"""
    try:
        data = request.get_json()
        device_ids = data.get('device_ids', [])
        
        if not device_ids:
            return jsonify({
                'success': False,
                'error': 'No device IDs provided'
            }), 400
        
        deleted_count = 0
        for device_id in device_ids:
            device = Device.query.get(device_id)
            if device:
                # Delete related assessments and test results
                for assessment in device.assessments:
                    for test_result in assessment.test_results:
                        db.session.delete(test_result)
                    db.session.delete(assessment)
                
                db.session.delete(device)
                deleted_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_count} devices successfully'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error bulk deleting devices: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete devices'
        }), 500

def is_valid_network_range(network_range):
    """Validate network range format"""
    try:
        # Basic validation for CIDR notation
        if '/' not in network_range:
            return False
        
        ip_part, cidr_part = network_range.split('/')
        cidr = int(cidr_part)
        
        if cidr < 0 or cidr > 32:
            return False
        
        # Validate IP address format
        parts = ip_part.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not part.isdigit() or int(part) < 0 or int(part) > 255:
                return False
        
        return True
    except:
        return False
