#!/usr/bin/env python3
"""
Celery entry point for IoT Security Framework
"""

import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set environment variables for development
os.environ.setdefault('FLASK_ENV', 'production')
os.environ.setdefault('DATABASE_URL', 'postgresql://iot_user:iot_password@db:5432/iot_security')
os.environ.setdefault('REDIS_URL', 'redis://redis:6379/0')

from celery import Celery
from app import create_app

def make_celery(app):
    """Create and configure Celery instance."""
    celery = Celery(
        app.import_name,
        backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/0'),
        broker=app.config.get('CELERY_BROKER_URL', 'redis://redis:6379/0')
    )
    
    # Update configuration
    celery.conf.update(
        broker_url=app.config.get('CELERY_BROKER_URL', 'redis://redis:6379/0'),
        result_backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/0'),
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
    )

    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context."""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

# Create Flask app
flask_app = create_app()

# Create Celery instance
celery = make_celery(flask_app)

# Make celery the main app for CLI
app = celery

# Define simple tasks
@celery.task
def health_check():
    """Simple health check task."""
    return {'status': 'healthy', 'worker': 'running'}

@celery.task
def test_task(message):
    """Simple test task."""
    return f"Received: {message}"

if __name__ == '__main__':
    celery.start()
