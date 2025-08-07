"""
Device management web interface
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import desc

from app import db
from app.models.device import Device
from app.models.assessment import Assessment
from app.utils.decorators import handle_exceptions, require_permission
from app.utils.validators import validate_device_data

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/')
@login_required
@require_permission('read')
@handle_exceptions()
def list_devices():
    """List all devices."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '').strip()
    device_type = request.args.get('type', '')
    status = request.args.get('status', '')
    
    query = Device.query
    
    if search:
        query = query.filter(Device.search_devices(search))
    
    if device_type:
        query = query.filter(Device.device_type == device_type)
    
    if status == 'active':
        query = query.filter(Device.is_active == True)
    elif status == 'inactive':
        query = query.filter(Device.is_active == False)
    
    devices = query.order_by(desc(Device.last_seen)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('devices/list.html', devices=devices, search=search, 
                         device_type=device_type, status=status)

@devices_bp.route('/<int:device_id>')
@login_required
@require_permission('read')
@handle_exceptions()
def view_device(device_id):
    """View device details."""
    device = Device.query.get_or_404(device_id)
    assessments = Assessment.get_assessments_by_device(device_id)
    
    return render_template('devices/view.html', device=device, assessments=assessments)

@devices_bp.route('/add', methods=['GET', 'POST'])
@login_required
@require_permission('write')
@handle_exceptions()
def add_device():
    """Add new device."""
    if request.method == 'POST':
        try:
            data = {
                'ip_address': request.form.get('ip_address', '').strip(),
                'mac_address': request.form.get('mac_address', '').strip() or None,
                'hostname': request.form.get('hostname', '').strip() or None,
                'manufacturer': request.form.get('manufacturer', '').strip() or None,
                'device_type': request.form.get('device_type', '').strip() or None,
                'model': request.form.get('model', '').strip() or None,
                'notes': request.form.get('notes', '').strip() or None
            }
            
            validated_data = validate_device_data(data)
            device = Device(**validated_data)
            
            db.session.add(device)
            db.session.commit()
            
            flash(f'Device {device.ip_address} added successfully!', 'success')
            return redirect(url_for('devices.view_device', device_id=device.id))
            
        except Exception as e:
            flash(f'Error adding device: {str(e)}', 'error')
    
    return render_template('devices/add.html')

@devices_bp.route('/<int:device_id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission('write')
@handle_exceptions()
def edit_device(device_id):
    """Edit device."""
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'POST':
        try:
            device.hostname = request.form.get('hostname', '').strip() or None
            device.manufacturer = request.form.get('manufacturer', '').strip() or None
            device.device_type = request.form.get('device_type', '').strip() or None
            device.model = request.form.get('model', '').strip() or None
            device.notes = request.form.get('notes', '').strip() or None
            
            db.session.commit()
            flash('Device updated successfully!', 'success')
            return redirect(url_for('devices.view_device', device_id=device.id))
            
        except Exception as e:
            flash(f'Error updating device: {str(e)}', 'error')
    
    return render_template('devices/edit.html', device=device)

@devices_bp.route('/<int:device_id>/delete', methods=['POST'])
@login_required
@require_permission('delete')
@handle_exceptions()
def delete_device(device_id):
    """Delete device."""
    device = Device.query.get_or_404(device_id)
    
    try:
        db.session.delete(device)
        db.session.commit()
        flash(f'Device {device.ip_address} deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting device: {str(e)}', 'error')
    
    return redirect(url_for('devices.list_devices'))
