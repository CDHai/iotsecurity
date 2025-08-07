# IoT Security Assessment Framework

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![Flask Version](https://img.shields.io/badge/flask-2.3+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](Dockerfile)

Một framework tự động hóa việc đánh giá bảo mật các thiết bị IoT trong hệ sinh thái Smart Home, được phát triển như một đề tài tốt nghiệp.

## ✨ Tính năng chính

### 🔍 Network Discovery & Device Detection
- Tự động phát hiện các thiết bị IoT trên mạng
- Phân loại và nhận dạng thiết bị dựa trên fingerprinting
- Hỗ trợ IPv4 và IPv6
- Quét port và phát hiện service

### 🛡️ Multi-Protocol Security Testing
- Hỗ trợ HTTP/HTTPS, MQTT, CoAP, SSH, Telnet
- Test suite có thể tùy chỉnh
- Kiểm tra lỗ hổng CVE database
- Phân tích cấu hình bảo mật

### 📊 Comprehensive Reporting
- Dashboard thời gian thực
- Báo cáo chi tiết với mức độ rủi ro
- Export PDF và JSON
- Theo dõi xu hướng bảo mật

### 🔐 Authentication & Authorization
- Hệ thống role-based access control
- JWT authentication cho API
- Multi-user support với các quyền khác nhau

### 🌐 RESTful API
- API đầy đủ cho tích hợp
- Swagger/OpenAPI documentation
- Rate limiting và security headers
- Real-time WebSocket updates

## 🚀 Quick Start

### Sử dụng Docker (Khuyên dùng)

```bash
# Clone repository
git clone https://github.com/your-username/iot-security-framework.git
cd iot-security-framework

# Copy environment file
cp env.example .env

# Chỉnh sửa .env với thông tin cấu hình của bạn
nano .env

# Chạy với Docker Compose
docker-compose up -d

# Khởi tạo database và seed data
docker-compose exec web python manage.py init_db
docker-compose exec web python manage.py seed_db
```

Truy cập ứng dụng tại: http://localhost:5000

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-username/iot-security-framework.git
cd iot-security-framework

# Tạo virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# hoặc
venv\Scripts\activate  # Windows

# Cài đặt dependencies
pip install -r requirements-dev.txt

# Copy environment file
cp env.example .env

# Khởi tạo database
python manage.py init_db
python manage.py seed_db

# Chạy development server
flask run --debug
```

## 📋 System Requirements

- Python 3.9+
- PostgreSQL 12+ (hoặc SQLite cho development)
- Redis 6+ (optional, cho caching và task queue)
- Docker & Docker Compose (cho containerized deployment)

### Network Tools (cho security testing)
- nmap
- curl
- netcat
- openssl

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────┬─────────────────┬─────────────────┬───────────┐
│   Web Interface │   REST API      │   CLI Interface │  Reports  │
│   - Dashboard   │   - Device API  │   - Scan Cmd    │  - HTML   │
│   - Device Mgmt │   - Scan API    │   - Config Cmd  │  - PDF    │
│   - Reports     │   - Report API  │   - Report Cmd  │  - JSON   │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Business Logic Layer                         │
│  ┌─────────────┬─────────────┬─────────────┬─────────────────┐  │
│  │   Device    │ Assessment  │    Test     │   Vulnerability │  │
│  │ Management  │   Engine    │   Suites    │    Database     │  │
│  └─────────────┴─────────────┴─────────────┴─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                      Data Layer                                 │
│  ┌─────────────┬─────────────┬─────────────┬─────────────────┐  │
│  │ PostgreSQL  │    Redis    │ File System │   External APIs │  │
│  │  Database   │   Cache     │   Storage   │   (CVE, etc.)   │  │
│  └─────────────┴─────────────┴─────────────┴─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Cấu hình

### Environment Variables

Tạo file `.env` từ `env.example` và cấu hình:

```bash
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql://user:password@localhost/iot_security

# JWT
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ACCESS_TOKEN_EXPIRES=3600

# External APIs
CVE_API_URL=https://cve.circl.lu/api
SHODAN_API_KEY=your-shodan-api-key

# Redis (optional)
REDIS_URL=redis://localhost:6379/0
```

### Database Migration

```bash
# Khởi tạo database
python manage.py init_db

# Seed với dữ liệu mẫu
python manage.py seed_db

# Tạo admin user
python manage.py create_admin
```

## 📚 API Documentation

### Authentication

```bash
# Đăng ký user mới
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "password_confirm": "password123"
  }'

# Đăng nhập
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### Device Management

```bash
# Lấy danh sách devices
curl -H "Authorization: Bearer <token>" \
  http://localhost:5000/api/devices/

# Thêm device mới
curl -X POST http://localhost:5000/api/devices/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "hostname": "smart-camera-01",
    "device_type": "camera",
    "manufacturer": "Hikvision"
  }'
```

### Assessment Management

```bash
# Tạo assessment mới
curl -X POST http://localhost:5000/api/assessments/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": 1,
    "name": "Security Assessment - Camera 01",
    "scan_type": "comprehensive",
    "target_protocols": ["http", "https", "rtsp"]
  }'

# Bắt đầu assessment
curl -X POST http://localhost:5000/api/assessments/1/start \
  -H "Authorization: Bearer <token>"
```

Xem full API documentation tại: http://localhost:5000/api/docs

## 🧪 Testing

```bash
# Chạy tất cả tests
pytest

# Chạy với coverage
pytest --cov=app tests/

# Chạy specific test file
pytest tests/test_models.py

# Chạy với verbose output
pytest -v tests/
```

## 🔒 Security Features

### Authentication & Authorization
- JWT-based authentication
- Role-based access control (Admin, Tester, Viewer)
- Session management
- Password hashing với bcrypt

### API Security
- Rate limiting
- CORS protection
- Input validation và sanitization
- SQL injection prevention
- XSS protection

### Network Security
- Non-destructive testing by default
- Configurable scan intensity
- Network isolation recommendations
- Secure credential storage

## 📊 Default Test Suites

### Basic IoT Security
- Default credential check
- Weak password policy
- HTTP banner grabbing
- Telnet access check

### Comprehensive Assessment
- SSL/TLS configuration analysis
- Web directory enumeration
- MQTT security check
- Firmware analysis

### Smart Camera Security
- RTSP stream access
- ONVIF service discovery
- Camera-specific CVE checks

## 🛠️ Management Commands

```bash
# Database management
python manage.py init_db          # Khởi tạo database
python manage.py seed_db          # Seed dữ liệu mẫu
python manage.py reset_db         # Reset database

# User management
python manage.py create_admin     # Tạo admin user
python manage.py list_users       # Liệt kê users
python manage.py change_role username admin

# System utilities
python manage.py stats            # Thống kê hệ thống
python manage.py check_health     # Kiểm tra sức khỏe hệ thống
python manage.py backup_db        # Backup database
```

## 🐳 Docker Deployment

### Production Deployment

```bash
# Build và chạy với PostgreSQL
docker-compose -f docker-compose.yml up -d

# Khởi tạo database
docker-compose exec web python manage.py init_db
docker-compose exec web python manage.py seed_db
```

### Development với Docker

```bash
# Chạy development environment
docker-compose -f docker-compose.dev.yml up -d
```

## 📁 Cấu trúc Project

```
iot-security-framework/
├── app/                          # Main application
│   ├── __init__.py              # App factory
│   ├── config.py                # Configuration
│   ├── models/                  # Database models
│   │   ├── user.py
│   │   ├── device.py
│   │   ├── assessment.py
│   │   └── ...
│   ├── api/                     # REST API endpoints
│   │   ├── auth.py
│   │   ├── devices.py
│   │   ├── assessments.py
│   │   └── reports.py
│   ├── web/                     # Web interface
│   │   ├── dashboard.py
│   │   ├── devices.py
│   │   └── ...
│   ├── auth/                    # Authentication
│   ├── core/                    # Core functionality
│   └── utils/                   # Utilities
├── tests/                       # Test suite
├── docs/                        # Documentation
├── scripts/                     # Utility scripts
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Docker configuration
├── docker-compose.yml           # Docker Compose
├── manage.py                    # Management script
└── README.md                    # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Write comprehensive tests
- Update documentation
- Use meaningful commit messages

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Your Name** - *Initial work* - [YourGitHub](https://github.com/yourusername)

## 🙏 Acknowledgments

- Flask và ecosystem
- OWASP IoT Security Guidelines
- CVE Database
- Security research community
- Các thư viện open source được sử dụng

## 📞 Support

- 📧 Email: your.email@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/iot-security-framework/issues)
- 📖 Documentation: [Wiki](https://github.com/your-username/iot-security-framework/wiki)

---

**⚠️ Lưu ý**: Framework này được phát triển cho mục đích giáo dục và nghiên cứu. Chỉ sử dụng trên các thiết bị và mạng mà bạn có quyền kiểm tra. Tác giả không chịu trách nhiệm về việc sử dụng sai mục đích.
