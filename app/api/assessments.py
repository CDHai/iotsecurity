from flask import jsonify, request, current_app
from flask_login import login_required, current_user
from app.api import api_bp
from app.models import Assessment, Device, TestSuite, TestResult
from app import db
from datetime import datetime

@api_bp.route('/assessments', methods=['GET'])
@login_required
def get_assessments():
    """Get list of assessments"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status')
        device_id = request.args.get('device_id', type=int)
        
        query = Assessment.query
        
        if status:
            query = query.filter(Assessment.status == status)
        
        if device_id:
            query = query.filter(Assessment.device_id == device_id)
        
        # Filter by user role
        if not current_user.is_admin():
            query = query.filter(Assessment.user_id == current_user.id)
        
        query = query.order_by(Assessment.created_at.desc())
        
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        assessments = pagination.items
        
        return jsonify({
            'success': True,
            'data': {
                'assessments': [assessment.get_assessment_info() for assessment in assessments],
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
        current_app.logger.error(f"Error getting assessments: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load assessments'
        }), 500

@api_bp.route('/assessments/<int:assessment_id>', methods=['GET'])
@login_required
def get_assessment(assessment_id):
    """Get specific assessment details"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Check permissions
        if not current_user.is_admin() and assessment.user_id != current_user.id:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        assessment_info = assessment.get_assessment_info()
        
        # Get test results
        test_results = assessment.test_results.all()
        assessment_info['test_results'] = [
            result.get_test_result_info() for result in test_results
        ]
        
        return jsonify({
            'success': True,
            'data': assessment_info
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting assessment {assessment_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to load assessment details'
        }), 500

@api_bp.route('/assessments', methods=['POST'])
@login_required
def create_assessment():
    """Create new assessment"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        test_suite_id = data.get('test_suite_id')
        name = data.get('name')
        description = data.get('description')
        
        if not device_id:
            return jsonify({
                'success': False,
                'error': 'Device ID is required'
            }), 400
        
        # Verify device exists
        device = Device.query.get(device_id)
        if not device:
            return jsonify({
                'success': False,
                'error': 'Device not found'
            }), 404
        
        # Create assessment
        assessment = Assessment(
            device_id=device_id,
            user_id=current_user.id,
            test_suite_id=test_suite_id,
            name=name,
            description=description
        )
        
        db.session.add(assessment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': assessment.get_assessment_info()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error creating assessment: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to create assessment'
        }), 500

@api_bp.route('/assessments/<int:assessment_id>/start', methods=['POST'])
@login_required
def start_assessment(assessment_id):
    """Start assessment execution"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Check permissions
        if not current_user.is_admin() and assessment.user_id != current_user.id:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        if assessment.status != 'pending':
            return jsonify({
                'success': False,
                'error': 'Assessment is not in pending status'
            }), 400
        
        # Start assessment
        assessment.start_assessment()
        
        # TODO: Start actual assessment execution in background
        # This would typically use Celery or similar task queue
        
        return jsonify({
            'success': True,
            'message': 'Assessment started successfully',
            'data': assessment.get_assessment_info()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error starting assessment {assessment_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to start assessment'
        }), 500

@api_bp.route('/assessments/<int:assessment_id>/cancel', methods=['POST'])
@login_required
def cancel_assessment(assessment_id):
    """Cancel assessment"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Check permissions
        if not current_user.is_admin() and assessment.user_id != current_user.id:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        if assessment.status not in ['pending', 'running']:
            return jsonify({
                'success': False,
                'error': 'Assessment cannot be cancelled'
            }), 400
        
        assessment.status = 'cancelled'
        assessment.completed_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Assessment cancelled successfully'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error cancelling assessment {assessment_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to cancel assessment'
        }), 500

@api_bp.route('/assessments/<int:assessment_id>', methods=['DELETE'])
@login_required
def delete_assessment(assessment_id):
    """Delete assessment"""
    try:
        assessment = Assessment.query.get_or_404(assessment_id)
        
        # Check permissions
        if not current_user.is_admin() and assessment.user_id != current_user.id:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        # Delete test results
        for test_result in assessment.test_results:
            db.session.delete(test_result)
        
        db.session.delete(assessment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Assessment deleted successfully'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error deleting assessment {assessment_id}: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete assessment'
        }), 500
