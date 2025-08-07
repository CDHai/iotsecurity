"""
IoT Security Assessment Framework
Application factory and extensions initialization
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_restx import Api
import logging
import os
from datetime import timedelta

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
jwt = JWTManager()
cors = CORS()

def create_app(config=None):
    """Application factory pattern."""
    app = Flask(__name__)
    
    # Load configuration
    load_config(app, config)
    
    # Initialize extensions
    initialize_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Setup logging
    setup_logging(app)
    
    return app

def load_config(app, config=None):
    """Load application configuration."""
    if config:
        app.config.update(config)
    else:
        # Default configuration
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///iot_security.db')
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(
            seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))
        )
        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
        
        # Security settings
        app.config['WTF_CSRF_ENABLED'] = os.getenv('WTF_CSRF_ENABLED', 'True').lower() == 'true'
        app.config['BCRYPT_LOG_ROUNDS'] = int(os.getenv('BCRYPT_LOG_ROUNDS', 12))
        
        # Celery configuration
        app.config['CELERY_BROKER_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        app.config['CELERY_RESULT_BACKEND'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        
        # Application settings
        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload
        app.config['REPORTS_DIR'] = os.getenv('REPORTS_DIR', 'reports')
        app.config['LOG_LEVEL'] = os.getenv('LOG_LEVEL', 'INFO')
        
        # Network scanning settings
        app.config['DEFAULT_SCAN_TIMEOUT'] = int(os.getenv('DEFAULT_SCAN_TIMEOUT', 30))
        app.config['MAX_CONCURRENT_SCANS'] = int(os.getenv('MAX_CONCURRENT_SCANS', 5))
        
        # External APIs
        app.config['CVE_API_URL'] = os.getenv('CVE_API_URL', 'https://cve.circl.lu/api')
        app.config['SHODAN_API_KEY'] = os.getenv('SHODAN_API_KEY', '')

def initialize_extensions(app):
    """Initialize Flask extensions."""
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Login Manager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # JWT Manager
    jwt.init_app(app)
    
    # CORS
    cors.init_app(app, resources={
        r"/api/*": {"origins": "*"}
    })
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return User.query.get(int(user_id))

def register_blueprints(app):
    """Register application blueprints."""
    # Web interface blueprints
    from app.web.dashboard import dashboard_bp
    from app.web.devices import devices_bp
    from app.web.assessments import assessments_bp
    from app.web.reports import reports_bp
    
    # API blueprints
    from app.api.auth import auth_api_bp
    from app.api.devices import devices_api_bp
    from app.api.assessments import assessments_api_bp
    from app.api.reports import reports_api_bp
    
    # Authentication blueprint
    from app.auth.routes import auth_bp
    
    # Register web blueprints
    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(devices_bp, url_prefix='/devices')
    app.register_blueprint(assessments_bp, url_prefix='/assessments')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    
    # Register API blueprints
    app.register_blueprint(auth_api_bp, url_prefix='/api/auth')
    app.register_blueprint(devices_api_bp, url_prefix='/api/devices')
    app.register_blueprint(assessments_api_bp, url_prefix='/api/assessments')
    app.register_blueprint(reports_api_bp, url_prefix='/api/reports')
    
    # Register auth blueprint
    app.register_blueprint(auth_bp, url_prefix='/auth')

def setup_logging(app):
    """Setup application logging."""
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = logging.FileHandler('logs/iot_security.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('IoT Security Framework startup')
