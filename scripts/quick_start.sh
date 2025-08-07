#!/bin/bash

# IoT Security Framework Quick Start Script
# This script will set up and run the IoT Security Assessment Framework

set -e

echo "🚀 Starting IoT Security Framework..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose and try again."
    exit 1
fi

echo "📦 Building and starting containers..."

# Build and start containers
docker-compose up -d --build

echo "⏳ Waiting for services to be ready..."

# Wait for database to be ready
until docker-compose exec -T db pg_isready -U iot_user -d iot_security; do
    echo "Waiting for database..."
    sleep 2
done

echo "🗄️ Initializing database..."

# Initialize database
docker-compose exec -T web python manage.py init_db

echo "🌱 Seeding initial data..."

# Seed database with initial data
docker-compose exec -T web python manage.py seed_db

echo "✅ Setup completed successfully!"
echo ""
echo "🌐 Access the application at:"
echo "   http://localhost:5000"
echo ""
echo "🔐 Default login credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "📊 Additional services:"
echo "   - Database: localhost:5432"
echo "   - Redis: localhost:6379"
echo ""
echo "🛠️ Management commands:"
echo "   - View logs: docker-compose logs -f"
echo "   - Stop services: docker-compose down"
echo "   - Restart: docker-compose restart"
echo ""
echo "🎉 Happy testing!"