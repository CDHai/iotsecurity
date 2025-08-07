"""
Device management API endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import desc

from app import db
from app.models.device import Device
from app.models.user import User
from app.utils.decorators import (
    require_api_auth, require_permission, handle_exceptions, 
    validate_json, rate_limit, log_activity
)
from app.utils.validators import validate_device_data

devices_api_bp = Blueprint('devices_api', __name__)

@devices_api_bp.route('/', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def list_devices():
    """List all devices with pagination and filtering."""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    search = request.args.get('search', '').strip()
    device_type = request.args.get('type', '')
    status = request.args.get('status', '')
    risk_level = request.args.get('risk_level', '')
    manufacturer = request.args.get('manufacturer', '')
    
    # Build query
    query = Device.query
    
    if search:
        devices = Device.search_devices(search)
        query = query.filter(Device.id.in_([d.id for d in devices]))
    
    if device_type:
        query = query.filter(Device.device_type == device_type)
    
    if status == 'active':
        query = query.filter(Device.is_active == True)
    elif status == 'inactive':
        query = query.filter(Device.is_active == False)
    
    if risk_level:
        query = query.filter(Device.risk_level == risk_level)
    
    if manufacturer:
        query = query.filter(Device.manufacturer.ilike(f'%{manufacturer}%'))
    
    # Paginate results
    pagination = query.order_by(desc(Device.last_seen)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    devices = [device.to_dict() for device in pagination.items]
    
    return jsonify({
        'devices': devices,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
    }), 200

@devices_api_bp.route('/<int:device_id>', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def get_device(device_id):
    """Get device details."""
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    include_assessments = request.args.get('include_assessments', 'false').lower() == 'true'
    
    return jsonify({
        'device': device.to_dict(include_relationships=include_assessments)
    }), 200

@devices_api_bp.route('/', methods=['POST'])
@require_api_auth
@require_permission('write')
@validate_json()
@rate_limit(max_requests=10, window_seconds=60)
@handle_exceptions()
@log_activity('create_device', 'device')
def create_device():
    """Create a new device."""
    data = request.get_json()
    
    try:
        # Validate device data
        validated_data = validate_device_data(data)
        
        # Check if device with same IP already exists
        existing_device = Device.find_by_ip(validated_data['ip_address'])
        if existing_device:
            return jsonify({'error': 'Device with this IP address already exists'}), 409
        
        # Create device
        device = Device(**validated_data)
        db.session.add(device)
        db.session.commit()
        
        current_app.logger.info(f"Device {device.ip_address} created by user {get_jwt_identity()}")
        
        return jsonify({
            'message': 'Device created successfully',
            'device': device.to_dict()
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Device creation error: {str(e)}")
        return jsonify({'error': 'Failed to create device'}), 500

@devices_api_bp.route('/<int:device_id>', methods=['PUT'])
@require_api_auth
@require_permission('write')
@validate_json()
@handle_exceptions()
@log_activity('update_device', 'device')
def update_device(device_id):
    """Update device information."""
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    data = request.get_json()
    
    try:
        # Update allowed fields
        allowed_fields = [
            'hostname', 'manufacturer', 'device_type', 'model', 
            'firmware_version', 'notes', 'is_verified'
        ]
        
        for field in allowed_fields:
            if field in data:
                setattr(device, field, data[field])
        
        # Handle special fields
        if 'open_ports' in data:
            device.open_ports_list = data['open_ports']
        
        if 'protocols' in data:
            device.protocols_list = data['protocols']
        
        if 'services' in data:
            device.services_dict = data['services']
        
        if 'tags' in data:
            device.tags_list = data['tags']
        
        db.session.commit()
        
        current_app.logger.info(f"Device {device.ip_address} updated by user {get_jwt_identity()}")
        
        return jsonify({
            'message': 'Device updated successfully',
            'device': device.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Device update error: {str(e)}")
        return jsonify({'error': 'Failed to update device'}), 500

@devices_api_bp.route('/<int:device_id>', methods=['DELETE'])
@require_api_auth
@require_permission('delete')
@handle_exceptions()
@log_activity('delete_device', 'device')
def delete_device(device_id):
    """Delete a device."""
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    try:
        device_ip = device.ip_address
        db.session.delete(device)
        db.session.commit()
        
        current_app.logger.info(f"Device {device_ip} deleted by user {get_jwt_identity()}")
        
        return jsonify({'message': 'Device deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Device deletion error: {str(e)}")
        return jsonify({'error': 'Failed to delete device'}), 500

@devices_api_bp.route('/<int:device_id>/tags', methods=['POST'])
@require_api_auth
@require_permission('write')
@validate_json()
@handle_exceptions()
def add_device_tag(device_id):
    """Add a tag to device."""
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    data = request.get_json()
    tag = data.get('tag', '').strip()
    
    if not tag:
        return jsonify({'error': 'Tag is required'}), 400
    
    try:
        device.add_tag(tag)
        return jsonify({
            'message': 'Tag added successfully',
            'tags': device.tags_list
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_api_bp.route('/<int:device_id>/tags/<tag>', methods=['DELETE'])
@require_api_auth
@require_permission('write')
@handle_exceptions()
def remove_device_tag(device_id, tag):
    """Remove a tag from device."""
    device = Device.query.get(device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    try:
        device.remove_tag(tag)
        return jsonify({
            'message': 'Tag removed successfully',
            'tags': device.tags_list
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@devices_api_bp.route('/stats', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def device_stats():
    """Get device statistics."""
    stats = {
        'total_devices': Device.query.count(),
        'active_devices': Device.query.filter_by(is_active=True).count(),
        'by_type': {},
        'by_risk_level': {},
        'by_manufacturer': {}
    }
    
    # Device type distribution
    type_stats = db.session.query(
        Device.device_type,
        db.func.count(Device.id)
    ).filter(Device.device_type.isnot(None)).group_by(Device.device_type).all()
    
    for device_type, count in type_stats:
        stats['by_type'][device_type] = count
    
    # Risk level distribution
    risk_stats = db.session.query(
        Device.risk_level,
        db.func.count(Device.id)
    ).group_by(Device.risk_level).all()
    
    for risk_level, count in risk_stats:
        stats['by_risk_level'][risk_level] = count
    
    # Top manufacturers
    manufacturer_stats = db.session.query(
        Device.manufacturer,
        db.func.count(Device.id)
    ).filter(Device.manufacturer.isnot(None)).group_by(Device.manufacturer).limit(10).all()
    
    for manufacturer, count in manufacturer_stats:
        stats['by_manufacturer'][manufacturer] = count
    
    return jsonify(stats), 200

@devices_api_bp.route('/search', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def search_devices():
    """Search devices by various criteria."""
    query = request.args.get('q', '').strip()
    limit = min(request.args.get('limit', 10, type=int), 50)
    
    if not query:
        return jsonify({'error': 'Search query is required'}), 400
    
    devices = Device.search_devices(query)[:limit]
    
    return jsonify({
        'devices': [device.to_dict() for device in devices],
        'total': len(devices)
    }), 200

@devices_api_bp.route('/types', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def get_device_types():
    """Get list of available device types."""
    types = db.session.query(Device.device_type).filter(
        Device.device_type.isnot(None)
    ).distinct().all()
    
    device_types = [t[0] for t in types if t[0]]
    
    return jsonify({'device_types': sorted(device_types)}), 200

@devices_api_bp.route('/manufacturers', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def get_manufacturers():
    """Get list of available manufacturers."""
    manufacturers = db.session.query(Device.manufacturer).filter(
        Device.manufacturer.isnot(None)
    ).distinct().all()
    
    manufacturer_list = [m[0] for m in manufacturers if m[0]]
    
    return jsonify({'manufacturers': sorted(manufacturer_list)}), 200

# Error handlers
@devices_api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Resource not found'}), 404

@devices_api_bp.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    return jsonify({'error': 'Access forbidden'}), 403

@devices_api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500
