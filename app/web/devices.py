from flask import render_template, request, current_app
from flask_login import login_required
from app.web import main_bp

@main_bp.route('/devices')
@login_required
def devices():
    """Device management page"""
    return render_template('devices/index.html')

@main_bp.route('/devices/<int:device_id>')
@login_required
def device_detail(device_id):
    """Device detail page"""
    return render_template('devices/detail.html', device_id=device_id)
