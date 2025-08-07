"""
Report generation web interface
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user
from sqlalchemy import desc
import os

from app import db
from app.models.assessment import Assessment
from app.utils.decorators import handle_exceptions, require_permission

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/')
@login_required
@require_permission('view_reports')
@handle_exceptions()
def list_reports():
    """List available reports."""
    completed_assessments = Assessment.query.filter_by(status='completed').order_by(
        desc(Assessment.completed_at)
    ).limit(50).all()
    
    return render_template('reports/list.html', assessments=completed_assessments)

@reports_bp.route('/assessment/<int:assessment_id>')
@login_required
@require_permission('view_reports')
@handle_exceptions()
def assessment_report(assessment_id):
    """Generate assessment report."""
    assessment = Assessment.query.get_or_404(assessment_id)
    
    if assessment.status != 'completed':
        flash('Report can only be generated for completed assessments.', 'error')
        return redirect(url_for('reports.list_reports'))
    
    return render_template('reports/assessment.html', assessment=assessment)
