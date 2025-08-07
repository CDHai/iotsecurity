from flask import render_template, request, current_app
from flask_login import login_required
from app.web import main_bp

@main_bp.route('/reports')
@login_required
def reports():
    """Reports page"""
    return render_template('reports/index.html')

@main_bp.route('/reports/generate')
@login_required
def generate_report():
    """Generate report page"""
    return render_template('reports/generate.html')
