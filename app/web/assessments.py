from flask import render_template, request, current_app
from flask_login import login_required
from app.web import main_bp

@main_bp.route('/assessments')
@login_required
def assessments():
    """Assessment management page"""
    return render_template('assessments/index.html')

@main_bp.route('/assessments/new')
@login_required
def new_assessment():
    """New assessment page"""
    return render_template('assessments/new.html')

@main_bp.route('/assessments/<int:assessment_id>')
@login_required
def assessment_detail(assessment_id):
    """Assessment detail page"""
    return render_template('assessments/detail.html', assessment_id=assessment_id)
