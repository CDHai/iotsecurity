"""
Assessment management web interface
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from sqlalchemy import desc

from app import db
from app.models.assessment import Assessment
from app.models.device import Device
from app.models.test_suite import TestSuite
from app.utils.decorators import handle_exceptions, require_permission

assessments_bp = Blueprint('assessments', __name__)

@assessments_bp.route('/')
@login_required
@require_permission('read')
@handle_exceptions()
def list_assessments():
    """List all assessments."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    status_filter = request.args.get('status', '')
    
    query = Assessment.query
    
    if status_filter:
        query = query.filter(Assessment.status == status_filter)
    
    assessments = query.order_by(desc(Assessment.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('assessments/list.html', assessments=assessments, 
                         status_filter=status_filter)

@assessments_bp.route('/<int:assessment_id>')
@login_required
@require_permission('read')
@handle_exceptions()
def view_assessment(assessment_id):
    """View assessment details."""
    assessment = Assessment.query.get_or_404(assessment_id)
    return render_template('assessments/view.html', assessment=assessment)

@assessments_bp.route('/new', methods=['GET', 'POST'])
@login_required
@require_permission('run_assessments')
@handle_exceptions()
def new_assessment():
    """Create new assessment."""
    if request.method == 'POST':
        try:
            device_id = request.form.get('device_id', type=int)
            test_suite_id = request.form.get('test_suite_id', type=int)
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            scan_type = request.form.get('scan_type', 'standard')
            
            if not device_id or not name:
                flash('Device and assessment name are required.', 'error')
                return render_template('assessments/new.html')
            
            assessment = Assessment(
                device_id=device_id,
                user_id=current_user.id,
                test_suite_id=test_suite_id,
                name=name,
                description=description,
                scan_type=scan_type
            )
            
            db.session.add(assessment)
            db.session.commit()
            
            flash(f'Assessment "{name}" created successfully!', 'success')
            return redirect(url_for('assessments.view_assessment', assessment_id=assessment.id))
            
        except Exception as e:
            flash(f'Error creating assessment: {str(e)}', 'error')
    
    devices = Device.get_active_devices()
    test_suites = TestSuite.get_default_suites()
    
    return render_template('assessments/new.html', devices=devices, test_suites=test_suites)

@assessments_bp.route('/<int:assessment_id>/start', methods=['POST'])
@login_required
@require_permission('run_assessments')
@handle_exceptions()
def start_assessment(assessment_id):
    """Start assessment."""
    assessment = Assessment.query.get_or_404(assessment_id)
    
    if assessment.status != 'pending':
        flash('Assessment can only be started from pending status.', 'error')
        return redirect(url_for('assessments.view_assessment', assessment_id=assessment_id))
    
    try:
        assessment.start_assessment()
        flash('Assessment started successfully!', 'success')
    except Exception as e:
        flash(f'Error starting assessment: {str(e)}', 'error')
    
    return redirect(url_for('assessments.view_assessment', assessment_id=assessment_id))
