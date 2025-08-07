#!/usr/bin/env python3
"""
IoT Security Assessment Framework
Main application entry point
"""

import os
from flask import Flask
from flask_migrate import Migrate
from dotenv import load_dotenv

from app import create_app, db
from app.models import User, Device, Assessment, TestSuite, SecurityTest, TestResult, Vulnerability

# Load environment variables
load_dotenv()

# Create Flask application
app = create_app()
migrate = Migrate(app, db)

# CLI commands for database management
@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print("Database initialized successfully!")

@app.cli.command()
def seed_db():
    """Seed the database with initial data."""
    from app.utils.seed_data import seed_initial_data
    seed_initial_data()
    print("Database seeded successfully!")

@app.cli.command()
def create_admin():
    """Create an admin user."""
    from app.models import User
    from werkzeug.security import generate_password_hash
    
    username = input("Enter admin username: ")
    email = input("Enter admin email: ")
    password = input("Enter admin password: ")
    
    admin_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role='admin',
        is_active=True
    )
    
    db.session.add(admin_user)
    db.session.commit()
    print(f"Admin user '{username}' created successfully!")

@app.shell_context_processor
def make_shell_context():
    """Register shell context variables."""
    return {
        'db': db,
        'User': User,
        'Device': Device,
        'Assessment': Assessment,
        'TestSuite': TestSuite,
        'SecurityTest': SecurityTest,
        'TestResult': TestResult,
        'Vulnerability': Vulnerability
    }

if __name__ == '__main__':
    app.run(
        host=os.getenv('FLASK_HOST', '0.0.0.0'),
        port=int(os.getenv('FLASK_PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    )
