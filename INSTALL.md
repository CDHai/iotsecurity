# Installation Guide

## Hướng dẫn cài đặt IoT Security Assessment Framework

### 📋 Yêu cầu hệ thống

#### Minimum Requirements
- **OS**: Linux (Ubuntu 18.04+), macOS (10.14+), Windows 10+
- **Python**: 3.9 hoặc cao hơn
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 5GB free space
- **Network**: Internet connection để download dependencies và CVE data

#### Recommended for Production
- **OS**: Ubuntu 20.04 LTS hoặc CentOS 8+
- **Python**: 3.9+
- **RAM**: 8GB+
- **CPU**: 4 cores+
- **Storage**: 20GB+ SSD
- **Database**: PostgreSQL 12+
- **Cache**: Redis 6+

## 🐳 Option 1: Docker Installation (Khuyên dùng)

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install docker.io docker-compose git

# CentOS/RHEL
sudo yum install docker docker-compose git

# macOS (với Homebrew)
brew install docker docker-compose git

# Windows: Download Docker Desktop từ docker.com
```

### Installation Steps

1. **Clone repository**
```bash
git clone https://github.com/your-username/iot-security-framework.git
cd iot-security-framework
```

2. **Cấu hình environment**
```bash
# Copy file cấu hình mẫu
cp env.example .env

# Chỉnh sửa cấu hình (quan trọng!)
nano .env
```

3. **Cấu hình .env file**
```bash
# Thay đổi các giá trị sau:
SECRET_KEY=your-very-secure-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
POSTGRES_PASSWORD=your-secure-database-password
```

4. **Build và chạy containers**
```bash
# Production deployment
docker-compose up -d

# Hoặc development mode
docker-compose -f docker-compose.dev.yml up -d
```

5. **Khởi tạo database**
```bash
# Chờ containers khởi động (30-60 seconds)
docker-compose exec web python manage.py init_db
docker-compose exec web python manage.py seed_db
```

6. **Tạo admin user**
```bash
docker-compose exec web python manage.py create_admin
```

7. **Truy cập ứng dụng**
- Web Interface: http://localhost:5000
- API Documentation: http://localhost:5000/api/docs

## 🔧 Option 2: Manual Installation

### Step 1: System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3.9 python3.9-venv python3-pip
sudo apt install postgresql postgresql-contrib redis-server
sudo apt install nmap curl netcat-openbsd git
```

#### CentOS/RHEL
```bash
sudo yum install python39 python39-pip python39-venv
sudo yum install postgresql postgresql-server redis
sudo yum install nmap curl nc git
```

#### macOS
```bash
# Install Homebrew nếu chưa có
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.9 postgresql redis nmap
```

### Step 2: Database Setup

#### PostgreSQL
```bash
# Ubuntu/Debian
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Tạo database và user
sudo -u postgres psql
CREATE DATABASE iot_security;
CREATE USER iot_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE iot_security TO iot_user;
\q

# CentOS/RHEL
sudo postgresql-setup --initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### Redis
```bash
# Ubuntu/Debian
sudo systemctl start redis-server
sudo systemctl enable redis-server

# CentOS/RHEL
sudo systemctl start redis
sudo systemctl enable redis
```

### Step 3: Application Setup

1. **Clone repository**
```bash
git clone https://github.com/your-username/iot-security-framework.git
cd iot-security-framework
```

2. **Tạo virtual environment**
```bash
python3.9 -m venv venv
source venv/bin/activate  # Linux/macOS
# hoặc
venv\Scripts\activate     # Windows
```

3. **Install Python dependencies**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

4. **Cấu hình environment**
```bash
cp env.example .env
nano .env
```

5. **Cấu hình database connection**
```bash
# Trong file .env
DATABASE_URL=postgresql://iot_user:your_password@localhost/iot_security
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your-very-secure-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
```

6. **Khởi tạo database**
```bash
python manage.py init_db
python manage.py seed_db
python manage.py create_admin
```

7. **Chạy application**
```bash
# Development mode
flask run --debug

# Production mode với Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

## ⚙️ Advanced Configuration

### Nginx Reverse Proxy (Production)

1. **Install Nginx**
```bash
sudo apt install nginx  # Ubuntu/Debian
sudo yum install nginx   # CentOS/RHEL
```

2. **Cấu hình Nginx**
```bash
sudo nano /etc/nginx/sites-available/iot-security
```

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files
    location /static {
        alias /path/to/iot-security-framework/app/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

3. **Enable site**
```bash
sudo ln -s /etc/nginx/sites-available/iot-security /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### SSL/TLS with Let's Encrypt

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Systemd Service (Production)

1. **Tạo service file**
```bash
sudo nano /etc/systemd/system/iot-security.service
```

```ini
[Unit]
Description=IoT Security Assessment Framework
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/path/to/iot-security-framework
Environment=PATH=/path/to/iot-security-framework/venv/bin
ExecStart=/path/to/iot-security-framework/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
```

2. **Enable và start service**
```bash
sudo systemctl daemon-reload
sudo systemctl enable iot-security
sudo systemctl start iot-security
```

## 🔧 Troubleshooting

### Common Issues

#### Database Connection Error
```bash
# Kiểm tra PostgreSQL service
sudo systemctl status postgresql

# Kiểm tra connection
psql -h localhost -U iot_user -d iot_security

# Reset password nếu cần
sudo -u postgres psql
ALTER USER iot_user PASSWORD 'new_password';
```

#### Permission Errors
```bash
# Fix ownership
sudo chown -R $USER:$USER /path/to/iot-security-framework

# Fix Python permissions
chmod +x manage.py
```

#### Port Already in Use
```bash
# Kiểm tra port 5000
sudo netstat -tlnp | grep :5000
sudo lsof -i :5000

# Kill process if needed
sudo kill -9 <PID>
```

#### Docker Issues
```bash
# Restart Docker
sudo systemctl restart docker

# Clean up containers
docker-compose down
docker system prune -a

# Rebuild images
docker-compose build --no-cache
```

### Performance Tuning

#### Database Optimization
```sql
-- PostgreSQL tuning
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
SELECT pg_reload_conf();
```

#### Redis Configuration
```bash
# Edit /etc/redis/redis.conf
maxmemory 512mb
maxmemory-policy allkeys-lru
```

### Monitoring Setup

#### Log Files
```bash
# Application logs
tail -f logs/iot_security.log

# Docker logs
docker-compose logs -f web

# System logs
sudo journalctl -u iot-security -f
```

#### Health Checks
```bash
# Application health
curl http://localhost:5000/health

# Database health
python manage.py check_health

# System resources
htop
df -h
```

## 🔄 Updates và Maintenance

### Updating Application
```bash
# Backup database first
python manage.py backup_db

# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt

# Run migrations if any
python manage.py init_db

# Restart application
sudo systemctl restart iot-security
```

### Backup Strategy
```bash
# Database backup
pg_dump -h localhost -U iot_user iot_security > backup_$(date +%Y%m%d).sql

# Full application backup
tar -czf iot_security_backup_$(date +%Y%m%d).tar.gz /path/to/iot-security-framework
```

## 📞 Getting Help

Nếu gặp vấn đề trong quá trình cài đặt:

1. Kiểm tra [Troubleshooting section](#-troubleshooting)
2. Xem [GitHub Issues](https://github.com/your-username/iot-security-framework/issues)
3. Tạo issue mới với thông tin chi tiết về lỗi
4. Liên hệ: your.email@example.com

---

**Chúc bạn cài đặt thành công! 🎉**
