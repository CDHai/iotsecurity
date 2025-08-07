"""
Assessment management API endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import desc

from app import db
from app.models.assessment import Assessment
from app.models.device import Device
from app.models.test_suite import TestSuite
from app.models.user import User
from app.utils.decorators import (
    require_api_auth, require_permission, handle_exceptions, 
    validate_json, rate_limit, log_activity
)
from app.utils.validators import validate_assessment_data

assessments_api_bp = Blueprint('assessments_api', __name__)

@assessments_api_bp.route('/', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def list_assessments():
    """List all assessments with pagination and filtering."""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    status = request.args.get('status', '')
    device_id = request.args.get('device_id', type=int)
    user_id = request.args.get('user_id', type=int)
    
    # Build query
    query = Assessment.query
    
    if status:
        query = query.filter(Assessment.status == status)
    
    if device_id:
        query = query.filter(Assessment.device_id == device_id)
    
    if user_id:
        query = query.filter(Assessment.user_id == user_id)
    
    # Paginate results
    pagination = query.order_by(desc(Assessment.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    assessments = [assessment.to_dict() for assessment in pagination.items]
    
    return jsonify({
        'assessments': assessments,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
    }), 200

@assessments_api_bp.route('/<int:assessment_id>', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def get_assessment(assessment_id):
    """Get assessment details."""
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found'}), 404
    
    include_results = request.args.get('include_results', 'false').lower() == 'true'
    
    return jsonify({
        'assessment': assessment.to_dict(include_results=include_results)
    }), 200

@assessments_api_bp.route('/', methods=['POST'])
@require_api_auth
@require_permission('run_assessments')
@validate_json()
@rate_limit(max_requests=5, window_seconds=60)
@handle_exceptions()
@log_activity('create_assessment', 'assessment')
def create_assessment():
    """Create a new assessment."""
    data = request.get_json()
    current_user_id = get_jwt_identity()
    
    try:
        # Validate assessment data
        validated_data = validate_assessment_data(data)
        
        # Check if device exists
        device = Device.query.get(validated_data['device_id'])
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        # Check if test suite exists (if specified)
        if validated_data.get('test_suite_id'):
            test_suite = TestSuite.query.get(validated_data['test_suite_id'])
            if not test_suite:
                return jsonify({'error': 'Test suite not found'}), 404
        
        # Create assessment
        assessment = Assessment(
            device_id=validated_data['device_id'],
            user_id=current_user_id,
            name=validated_data['name'],
            description=validated_data.get('description'),
            scan_type=validated_data['scan_type'],
            test_suite_id=validated_data.get('test_suite_id'),
            notes=validated_data.get('notes')
        )
        
        # Set target protocols and custom tests if provided
        if validated_data.get('target_protocols'):
            assessment.target_protocols_list = validated_data['target_protocols']
        
        if validated_data.get('custom_tests'):
            assessment.custom_tests_list = validated_data['custom_tests']
        
        db.session.add(assessment)
        db.session.commit()
        
        current_app.logger.info(f"Assessment '{assessment.name}' created by user {current_user_id}")
        
        return jsonify({
            'message': 'Assessment created successfully',
            'assessment': assessment.to_dict()
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Assessment creation error: {str(e)}")
        return jsonify({'error': 'Failed to create assessment'}), 500

@assessments_api_bp.route('/<int:assessment_id>/start', methods=['POST'])
@require_api_auth
@require_permission('run_assessments')
@handle_exceptions()
@log_activity('start_assessment', 'assessment')
def start_assessment(assessment_id):
    """Start an assessment."""
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found'}), 404
    
    current_user_id = get_jwt_identity()
    
    # Check if user owns the assessment or is admin
    if assessment.user_id != current_user_id:
        user = User.query.get(current_user_id)
        if not user or not user.has_role('admin'):
            return jsonify({'error': 'Access denied'}), 403
    
    if assessment.status != 'pending':
        return jsonify({'error': 'Assessment can only be started from pending status'}), 400
    
    try:
        assessment.start_assessment()
        
        current_app.logger.info(f"Assessment {assessment.id} started by user {current_user_id}")
        
        # Here you would typically trigger the actual security testing
        # For now, we'll just mark it as started
        
        return jsonify({
            'message': 'Assessment started successfully',
            'assessment': assessment.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Assessment start error: {str(e)}")
        return jsonify({'error': 'Failed to start assessment'}), 500

@assessments_api_bp.route('/<int:assessment_id>/stop', methods=['POST'])
@require_api_auth
@require_permission('run_assessments')
@handle_exceptions()
@log_activity('stop_assessment', 'assessment')
def stop_assessment(assessment_id):
    """Stop a running assessment."""
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found'}), 404
    
    current_user_id = get_jwt_identity()
    
    # Check if user owns the assessment or is admin
    if assessment.user_id != current_user_id:
        user = User.query.get(current_user_id)
        if not user or not user.has_role('admin'):
            return jsonify({'error': 'Access denied'}), 403
    
    if assessment.status != 'running':
        return jsonify({'error': 'Assessment is not currently running'}), 400
    
    try:
        assessment.status = 'cancelled'
        assessment.completed_at = db.func.now()
        db.session.commit()
        
        current_app.logger.info(f"Assessment {assessment.id} stopped by user {current_user_id}")
        
        return jsonify({
            'message': 'Assessment stopped successfully',
            'assessment': assessment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Assessment stop error: {str(e)}")
        return jsonify({'error': 'Failed to stop assessment'}), 500

@assessments_api_bp.route('/<int:assessment_id>', methods=['DELETE'])
@require_api_auth
@require_permission('delete')
@handle_exceptions()
@log_activity('delete_assessment', 'assessment')
def delete_assessment(assessment_id):
    """Delete an assessment."""
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found'}), 404
    
    current_user_id = get_jwt_identity()
    
    # Check if user owns the assessment or is admin
    if assessment.user_id != current_user_id:
        user = User.query.get(current_user_id)
        if not user or not user.has_role('admin'):
            return jsonify({'error': 'Access denied'}), 403
    
    if assessment.status == 'running':
        return jsonify({'error': 'Cannot delete running assessment'}), 400
    
    try:
        assessment_name = assessment.name
        db.session.delete(assessment)
        db.session.commit()
        
        current_app.logger.info(f"Assessment '{assessment_name}' deleted by user {current_user_id}")
        
        return jsonify({'message': 'Assessment deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Assessment deletion error: {str(e)}")
        return jsonify({'error': 'Failed to delete assessment'}), 500

@assessments_api_bp.route('/<int:assessment_id>/results', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def get_assessment_results(assessment_id):
    """Get assessment test results."""
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'error': 'Assessment not found'}), 404
    
    # Get query parameters
    status_filter = request.args.get('status', '')
    severity_filter = request.args.get('severity', '')
    
    # Build query for test results
    from app.models.test_result import TestResult
    query = TestResult.query.filter_by(assessment_id=assessment_id)
    
    if status_filter:
        query = query.filter(TestResult.status == status_filter)
    
    if severity_filter:
        query = query.join(TestResult.security_test).filter(
            TestResult.security_test.has(severity=severity_filter)
        )
    
    results = query.all()
    
    return jsonify({
        'assessment_id': assessment_id,
        'results': [result.to_dict(include_details=True) for result in results],
        'summary': {
            'total': len(results),
            'passed': len([r for r in results if r.status == 'pass']),
            'failed': len([r for r in results if r.status == 'fail']),
            'errors': len([r for r in results if r.status == 'error']),
            'skipped': len([r for r in results if r.status == 'skip'])
        }
    }), 200

@assessments_api_bp.route('/stats', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def assessment_stats():
    """Get assessment statistics."""
    stats = {
        'total_assessments': Assessment.query.count(),
        'by_status': {},
        'by_scan_type': {},
        'recent_activity': []
    }
    
    # Status distribution
    status_stats = db.session.query(
        Assessment.status,
        db.func.count(Assessment.id)
    ).group_by(Assessment.status).all()
    
    for status, count in status_stats:
        stats['by_status'][status] = count
    
    # Scan type distribution
    scan_type_stats = db.session.query(
        Assessment.scan_type,
        db.func.count(Assessment.id)
    ).group_by(Assessment.scan_type).all()
    
    for scan_type, count in scan_type_stats:
        stats['by_scan_type'][scan_type] = count
    
    # Recent activity (last 7 days)
    from datetime import datetime, timedelta
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    recent_assessments = Assessment.query.filter(
        Assessment.created_at >= week_ago
    ).order_by(desc(Assessment.created_at)).limit(10).all()
    
    stats['recent_activity'] = [assessment.to_dict() for assessment in recent_assessments]
    
    return jsonify(stats), 200

@assessments_api_bp.route('/running', methods=['GET'])
@require_api_auth
@require_permission('read')
@handle_exceptions()
def get_running_assessments():
    """Get currently running assessments."""
    running_assessments = Assessment.get_running_assessments()
    
    return jsonify({
        'running_assessments': [assessment.to_dict() for assessment in running_assessments],
        'count': len(running_assessments)
    }), 200

# Error handlers
@assessments_api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Resource not found'}), 404

@assessments_api_bp.errorhandler(403)
def forbidden(error):
    """Handle 403 errors."""
    return jsonify({'error': 'Access forbidden'}), 403

@assessments_api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500
