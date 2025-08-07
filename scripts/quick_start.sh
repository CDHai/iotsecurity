#!/bin/bash

# IoT Security Framework - Quick Start Script
# Tự động setup và khởi chạy framework

set -e

echo "🚀 IoT Security Framework - Quick Start"
echo "======================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    print_step "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        echo "Installation guide: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        echo "Installation guide: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    print_status "Docker and Docker Compose are installed ✓"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Setup environment file
setup_env() {
    print_step "Setting up environment configuration..."
    
    if [[ ! -f .env ]]; then
        if [[ -f env.example ]]; then
            cp env.example .env
            print_status "Created .env file from template"
        else
            print_error "env.example file not found!"
            exit 1
        fi
    else
        print_warning ".env file already exists"
    fi
    
    # Generate random secrets if using defaults
    if grep -q "your-secret-key-here" .env; then
        SECRET_KEY=$(openssl rand -hex 32)
        sed -i "s/your-secret-key-here-change-in-production/$SECRET_KEY/g" .env
        print_status "Generated random SECRET_KEY"
    fi
    
    if grep -q "your-jwt-secret-key-here" .env; then
        JWT_SECRET=$(openssl rand -hex 32)
        sed -i "s/your-jwt-secret-key-here/$JWT_SECRET/g" .env
        print_status "Generated random JWT_SECRET_KEY"
    fi
    
    if grep -q "iot_password" .env; then
        DB_PASSWORD=$(openssl rand -hex 16)
        sed -i "s/iot_password/$DB_PASSWORD/g" .env
        print_status "Generated random database password"
    fi
}

# Build and start containers
start_containers() {
    print_step "Building and starting Docker containers..."
    
    # Check if containers are already running
    if docker-compose ps | grep -q "Up"; then
        print_warning "Some containers are already running"
        read -p "Restart containers? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down
        else
            print_status "Using existing containers"
            return
        fi
    fi
    
    # Start containers
    docker-compose up -d
    
    print_status "Containers started successfully"
    
    # Wait for services to be ready
    print_step "Waiting for services to be ready..."
    sleep 30
    
    # Check if services are healthy
    if docker-compose ps | grep -q "unhealthy"; then
        print_error "Some services are unhealthy. Check logs with: docker-compose logs"
        exit 1
    fi
}

# Initialize database
init_database() {
    print_step "Initializing database..."
    
    # Wait a bit more for database to be fully ready
    sleep 10
    
    # Initialize database
    docker-compose exec -T web python manage.py init_db
    print_status "Database initialized"
    
    # Seed with initial data
    docker-compose exec -T web python manage.py seed_db
    print_status "Database seeded with initial data"
}

# Create admin user
create_admin() {
    print_step "Creating admin user..."
    
    echo "Please provide admin user details:"
    read -p "Username: " ADMIN_USERNAME
    read -p "Email: " ADMIN_EMAIL
    read -s -p "Password: " ADMIN_PASSWORD
    echo
    
    if [[ -z "$ADMIN_USERNAME" || -z "$ADMIN_EMAIL" || -z "$ADMIN_PASSWORD" ]]; then
        print_warning "Skipping admin user creation (empty fields)"
        return
    fi
    
    # Create admin user using Python script
    docker-compose exec -T web python -c "
from app import create_app, db
from app.models.user import User

app = create_app()
with app.app_context():
    try:
        admin_user = User.create_user(
            username='$ADMIN_USERNAME',
            email='$ADMIN_EMAIL', 
            password='$ADMIN_PASSWORD',
            role='admin',
            is_active=True,
            is_verified=True
        )
        print('Admin user created successfully!')
    except Exception as e:
        print(f'Error creating admin user: {e}')
"
}

# Display access information
show_access_info() {
    print_step "Setup completed successfully! 🎉"
    echo
    echo "Access Information:"
    echo "=================="
    echo "🌐 Web Interface: http://localhost:5000"
    echo "📚 API Documentation: http://localhost:5000/api/docs"
    echo "🗄️  Database: localhost:5432"
    echo "🔄 Redis: localhost:6379"
    echo
    echo "Default Login Credentials:"
    echo "=========================="
    echo "👤 Username: admin"
    echo "🔑 Password: admin123"
    echo "📧 Email: admin@iotsecurity.local"
    echo
    echo "Other test accounts:"
    echo "- tester/tester123 (Tester role)"
    echo "- viewer/viewer123 (Viewer role)"
    echo
    echo "Useful Commands:"
    echo "==============="
    echo "📊 View logs: docker-compose logs -f"
    echo "🔄 Restart: docker-compose restart"
    echo "🛑 Stop: docker-compose down"
    echo "🗑️  Clean up: docker-compose down -v"
    echo "💾 Backup DB: docker-compose exec web python manage.py backup_db"
    echo
    print_status "Framework is ready to use!"
}

# Health check
health_check() {
    print_step "Performing health check..."
    
    # Wait for web service to be fully ready
    sleep 5
    
    if curl -f http://localhost:5000/health > /dev/null 2>&1; then
        print_status "Health check passed ✓"
    else
        print_warning "Health check failed. Service may still be starting..."
        echo "Try accessing http://localhost:5000 in a few minutes"
    fi
}

# Cleanup function
cleanup() {
    if [[ $? -ne 0 ]]; then
        print_error "Setup failed! Cleaning up..."
        docker-compose down 2>/dev/null || true
    fi
}

# Main execution
main() {
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Run setup steps
    check_root
    check_docker
    setup_env
    start_containers
    init_database
    
    # Optional admin user creation
    read -p "Create custom admin user? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_admin
    fi
    
    health_check
    show_access_info
    
    # Remove trap
    trap - EXIT
}

# Parse command line arguments
case "${1:-}" in
    --help|-h)
        echo "IoT Security Framework Quick Start Script"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --dev          Start in development mode"
        echo "  --stop         Stop all containers"
        echo "  --clean        Stop and remove all containers and volumes"
        echo ""
        exit 0
        ;;
    --dev)
        print_status "Starting in development mode..."
        docker-compose -f docker-compose.dev.yml up -d
        exit 0
        ;;
    --stop)
        print_status "Stopping containers..."
        docker-compose down
        exit 0
        ;;
    --clean)
        print_warning "This will remove all containers and data!"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down -v
            docker system prune -f
            print_status "Cleanup completed"
        fi
        exit 0
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
