#!/usr/bin/env python3
"""
Management script for IoT Security Assessment Framework
"""

import click
import os
from flask.cli import FlaskGroup
from app import create_app, db
from app.models import User, Device, Assessment, TestSuite, SecurityTest, Vulnerability
from app.utils.seed_data import seed_initial_data

def create_application():
    """Create Flask application for CLI."""
    return create_app()

@click.group(cls=FlaskGroup, create_app=create_application)
def cli():
    """Management script for IoT Security Framework."""
    pass

@cli.command()
def init_db():
    """Initialize the database."""
    click.echo('Initializing database...')
    db.create_all()
    click.echo('Database initialized successfully!')

@cli.command()
def drop_db():
    """Drop all database tables."""
    if click.confirm('This will delete all data. Are you sure?'):
        click.echo('Dropping database tables...')
        db.drop_all()
        click.echo('Database tables dropped!')

@cli.command()
def reset_db():
    """Reset database (drop and recreate)."""
    if click.confirm('This will delete all data and recreate tables. Are you sure?'):
        click.echo('Resetting database...')
        db.drop_all()
        db.create_all()
        click.echo('Database reset successfully!')

@cli.command()
def seed_db():
    """Seed the database with initial data."""
    click.echo('Seeding database...')
    seed_initial_data()
    click.echo('Database seeded successfully!')

@cli.command()
def create_admin():
    """Create an admin user."""
    username = click.prompt('Username')
    email = click.prompt('Email')
    password = click.prompt('Password', hide_input=True)
    confirm_password = click.prompt('Confirm password', hide_input=True)
    
    if password != confirm_password:
        click.echo('Passwords do not match!')
        return
    
    try:
        admin_user = User.create_user(
            username=username,
            email=email,
            password=password,
            role='admin',
            is_active=True,
            is_verified=True
        )
        click.echo(f'Admin user "{username}" created successfully!')
    except ValueError as e:
        click.echo(f'Error creating user: {e}')

@cli.command()
@click.argument('username')
@click.argument('role', type=click.Choice(['admin', 'tester', 'viewer']))
def change_role(username, role):
    """Change user role."""
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(f'User "{username}" not found!')
        return
    
    old_role = user.role
    user.role = role
    db.session.commit()
    
    click.echo(f'User "{username}" role changed from {old_role} to {role}')

@cli.command()
@click.argument('username')
def toggle_user(username):
    """Toggle user active status."""
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(f'User "{username}" not found!')
        return
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    click.echo(f'User "{username}" {status}')

@cli.command()
def list_users():
    """List all users."""
    users = User.query.all()
    
    click.echo('\nUsers:')
    click.echo('-' * 60)
    click.echo(f'{"ID":<5} {"Username":<15} {"Email":<25} {"Role":<10} {"Active"}')
    click.echo('-' * 60)
    
    for user in users:
        click.echo(f'{user.id:<5} {user.username:<15} {user.email or "N/A":<25} {user.role:<10} {"Yes" if user.is_active else "No"}')

@cli.command()
def stats():
    """Display database statistics."""
    device_count = Device.query.count()
    active_devices = Device.query.filter_by(is_active=True).count()
    assessment_count = Assessment.query.count()
    completed_assessments = Assessment.query.filter_by(status='completed').count()
    user_count = User.query.count()
    vulnerability_count = Vulnerability.query.count()
    
    click.echo('\nDatabase Statistics:')
    click.echo('-' * 30)
    click.echo(f'Users: {user_count}')
    click.echo(f'Devices: {device_count} (Active: {active_devices})')
    click.echo(f'Assessments: {assessment_count} (Completed: {completed_assessments})')
    click.echo(f'Vulnerabilities: {vulnerability_count}')

@cli.command()
@click.argument('ip_address')
@click.option('--hostname', help='Device hostname')
@click.option('--device-type', help='Device type')
@click.option('--manufacturer', help='Device manufacturer')
def add_device(ip_address, hostname, device_type, manufacturer):
    """Add a device to the database."""
    try:
        device = Device(
            ip_address=ip_address,
            hostname=hostname,
            device_type=device_type,
            manufacturer=manufacturer
        )
        db.session.add(device)
        db.session.commit()
        
        click.echo(f'Device {ip_address} added successfully!')
    except Exception as e:
        click.echo(f'Error adding device: {e}')

@cli.command()
def backup_db():
    """Backup database (SQLite only)."""
    if not os.getenv('DATABASE_URL', '').startswith('sqlite'):
        click.echo('Backup is only supported for SQLite databases')
        return
    
    import shutil
    from datetime import datetime
    
    db_path = 'iot_security.db'
    if os.path.exists(db_path):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f'backup_iot_security_{timestamp}.db'
        shutil.copy2(db_path, backup_path)
        click.echo(f'Database backed up to {backup_path}')
    else:
        click.echo('Database file not found')

@cli.command()
@click.argument('backup_file')
def restore_db(backup_file):
    """Restore database from backup (SQLite only)."""
    if not os.getenv('DATABASE_URL', '').startswith('sqlite'):
        click.echo('Restore is only supported for SQLite databases')
        return
    
    if not os.path.exists(backup_file):
        click.echo(f'Backup file {backup_file} not found')
        return
    
    if click.confirm('This will replace the current database. Continue?'):
        import shutil
        shutil.copy2(backup_file, 'iot_security.db')
        click.echo('Database restored successfully')

@cli.command()
def run_tests():
    """Run the test suite."""
    import subprocess
    import sys
    
    click.echo('Running test suite...')
    result = subprocess.run([sys.executable, '-m', 'pytest', 'tests/', '-v'], 
                          capture_output=True, text=True)
    
    click.echo(result.stdout)
    if result.stderr:
        click.echo(result.stderr)
    
    if result.returncode == 0:
        click.echo('All tests passed!')
    else:
        click.echo('Some tests failed!')

@cli.command()
def check_health():
    """Check application health."""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        click.echo('✓ Database connection: OK')
        
        # Check if admin user exists
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count > 0:
            click.echo('✓ Admin user exists: OK')
        else:
            click.echo('⚠ No admin users found')
        
        # Check if test suites exist
        suite_count = TestSuite.query.count()
        if suite_count > 0:
            click.echo(f'✓ Test suites: {suite_count} found')
        else:
            click.echo('⚠ No test suites found')
        
        click.echo('\nApplication health check completed!')
        
    except Exception as e:
        click.echo(f'✗ Health check failed: {e}')

if __name__ == '__main__':
    cli()
