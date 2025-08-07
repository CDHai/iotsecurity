#!/usr/bin/env python3
"""
Simple Celery worker for IoT Security Framework
"""

from celery import Celery
import os

# Configure Celery
broker_url = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
result_backend = os.environ.get('REDIS_URL', 'redis://redis:6379/0')

app = Celery('iot_security',
             broker=broker_url,
             backend=result_backend)

# Configure Celery
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

@app.task
def health_check():
    """Simple health check task."""
    return {'status': 'healthy', 'worker': 'running'}

@app.task
def test_task(message):
    """Simple test task."""
    return f"Worker received: {message}"

@app.task
def add_numbers(x, y):
    """Simple math task."""
    return x + y

if __name__ == '__main__':
    app.start()
