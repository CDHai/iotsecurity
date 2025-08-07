-- Database initialization script for IoT Security Framework
-- This script will be executed when the PostgreSQL container starts

-- Create extensions if they don't exist
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create database user if not exists (handled by POSTGRES_USER env var)
-- The database 'iot_security' is created automatically by POSTGRES_DB env var

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE iot_security TO iot_user;

-- Set default search path
ALTER DATABASE iot_security SET search_path TO public;

-- Create any additional schemas if needed
-- CREATE SCHEMA IF NOT EXISTS analytics;
-- GRANT ALL ON SCHEMA analytics TO iot_user;

-- Log successful initialization
SELECT 'Database initialized successfully' AS status;
