"""
Configuration settings for IoT Security Assessment Framework
"""

import os
from datetime import timedelta

class Config:
    """Base configuration class."""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///iot_security.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    
    # JWT settings
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Security settings
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'True').lower() == 'true'
    BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_LOG_ROUNDS', 12))
    
    # Application settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload
    REPORTS_DIR = os.environ.get('REPORTS_DIR', 'reports')
    UPLOAD_FOLDER = 'uploads'
    
    # Network scanning settings
    DEFAULT_SCAN_TIMEOUT = int(os.environ.get('DEFAULT_SCAN_TIMEOUT', 30))
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', 5))
    SCAN_RESULTS_TTL = int(os.environ.get('SCAN_RESULTS_TTL', 3600))
    
    # External APIs
    CVE_API_URL = os.environ.get('CVE_API_URL', 'https://cve.circl.lu/api')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    
    # Redis settings (for task queue)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Celery settings
    CELERY_BROKER_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/iot_security.log')
    
    # Mail settings (for notifications)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Report generation settings
    MAX_REPORT_SIZE_MB = int(os.environ.get('MAX_REPORT_SIZE_MB', 50))
    REPORT_TEMPLATES_DIR = 'app/templates/reports'
    
    # Security test settings
    TEST_MODULES_DIR = 'app/core/tests'
    CUSTOM_TESTS_DIR = 'custom_tests'
    
    # Device signature database
    DEVICE_SIGNATURES_FILE = 'data/device_signatures.json'
    VULNERABILITY_DB_FILE = 'data/vulnerabilities.json'
    
    @staticmethod
    def init_app(app):
        """Initialize application configuration."""
        # Create necessary directories
        os.makedirs(app.config['REPORTS_DIR'], exist_ok=True)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        os.makedirs('data', exist_ok=True)

class DevelopmentConfig(Config):
    """Development configuration."""
    
    DEBUG = True
    TESTING = False
    
    # More verbose logging in development
    LOG_LEVEL = 'DEBUG'
    
    # Development database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///iot_security_dev.db'
    
    # Disable CSRF in development for easier testing
    WTF_CSRF_ENABLED = False
    
    # Shorter token expiry for development
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)

class TestingConfig(Config):
    """Testing configuration."""
    
    TESTING = True
    DEBUG = False
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Faster password hashing for tests
    BCRYPT_LOG_ROUNDS = 4
    
    # Short token expiry for testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    
    # Disable external API calls in tests
    CVE_API_URL = 'http://localhost:5000/mock/cve'
    SHODAN_API_KEY = 'test-key'

class ProductionConfig(Config):
    """Production configuration."""
    
    DEBUG = False
    TESTING = False
    
    # Production database (PostgreSQL recommended)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://user:password@localhost/iot_security'
    
    # Enhanced security settings
    WTF_CSRF_ENABLED = True
    BCRYPT_LOG_ROUNDS = 15
    
    # Production logging
    LOG_LEVEL = 'INFO'
    
    # Longer token expiry for production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    @classmethod
    def init_app(cls, app):
        """Initialize production-specific settings."""
        Config.init_app(app)
        
        # Log to syslog in production
        import logging
        from logging.handlers import SysLogHandler
        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.INFO)
        app.logger.addHandler(syslog_handler)

class DockerConfig(ProductionConfig):
    """Docker container configuration."""
    
    # Docker-specific settings
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://iot_user:iot_password@db:5432/iot_security'
    
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
    CELERY_BROKER_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL', 'redis://redis:6379/0')

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}
