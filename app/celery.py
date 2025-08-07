"""
Celery configuration for IoT Security Framework
"""

import os
from celery import Celery
from app import create_app

def make_celery(app):
    """Create and configure Celery instance."""
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)

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

# Import tasks to register them (commented out to avoid circular import)
# from app.tasks import *
