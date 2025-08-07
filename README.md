# IoT Security Framework

Framework đánh giá bảo mật các thiết bị IoT trong hệ sinh thái Smart Home.

## Tính năng chính

- **Network Discovery**: Tự động phát hiện thiết bị IoT trên mạng
- **Device Classification**: Phân loại thiết bị dựa trên signature và heuristic
- **Vulnerability Assessment**: Đánh giá lỗ hổng bảo mật tự động
- **Security Reporting**: Tạo báo cáo bảo mật chi tiết
- **Web Interface**: Giao diện web thân thiện
- **REST API**: API đầy đủ cho integration

## Cài đặt

### Yêu cầu hệ thống

- Python 3.9+
- SQLite (development) / PostgreSQL (production)
- Redis (optional, cho background tasks)

### Cài đặt dependencies

```bash
# Clone repository
git clone <repository-url>
cd iot-security-framework

# Tạo virtual environment
python3.9 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Cài đặt dependencies
pip install -r requirements.txt
```

### Cấu hình

1. Tạo file `.env` từ `.env.example`:
```bash
cp .env.example .env
```

2. Chỉnh sửa file `.env`:
```env
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///dev.db
REDIS_URL=redis://localhost:6379/0
```

### Khởi tạo database

```bash
# Tạo database tables
python app.py
```

## Sử dụng

### Chạy ứng dụng

```bash
python app.py
```

Ứng dụng sẽ chạy tại `http://localhost:5000`

### Tài khoản mặc định

- **Admin**: `admin` / `admin123`
- **Tester**: `tester` / `test123`

### Network Scanning

1. Đăng nhập vào web interface
2. Vào trang "Devices"
3. Click "Scan Network"
4. Nhập network range (VD: `192.168.1.0/24`)
5. Chờ scan hoàn thành

### Security Assessment

1. Chọn device từ danh sách
2. Click "New Assessment"
3. Chọn test suite
4. Click "Start Assessment"
5. Xem kết quả và báo cáo

## API Documentation

### Authentication

```bash
# Login
POST /api/auth/login
{
    "username": "admin",
    "password": "admin123"
}

# Get current user
GET /api/auth/user
```

### Devices

```bash
# Get devices
GET /api/devices?page=1&per_page=20

# Get specific device
GET /api/devices/{device_id}

# Scan network
POST /api/devices/scan
{
    "network_range": "192.168.1.0/24"
}

# Update device
PUT /api/devices/{device_id}
{
    "hostname": "new-hostname",
    "manufacturer": "New Manufacturer"
}
```

### Assessments

```bash
# Get assessments
GET /api/assessments?status=completed

# Create assessment
POST /api/assessments
{
    "device_id": 1,
    "test_suite_id": 1,
    "name": "Security Assessment",
    "description": "Comprehensive security test"
}

# Start assessment
POST /api/assessments/{assessment_id}/start

# Get assessment details
GET /api/assessments/{assessment_id}
```

### Reports

```bash
# Generate report
POST /api/reports/generate
{
    "assessment_id": 1,
    "report_type": "technical",
    "format": "json"
}

# Export report
GET /api/reports/export/{assessment_id}?format=json
```

## Cấu trúc Project

```
iot-security-framework/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── config.py            # Configuration classes
│   ├── models/              # Database models
│   │   ├── user.py
│   │   ├── device.py
│   │   ├── assessment.py
│   │   └── vulnerability.py
│   ├── core/                # Core business logic
│   │   ├── discovery.py     # Network scanning
│   │   ├── assessment.py    # Vulnerability testing
│   │   └── reporting.py     # Report generation
│   ├── web/                 # Web interface
│   │   ├── dashboard.py
│   │   ├── devices.py
│   │   ├── assessments.py
│   │   └── reports.py
│   ├── api/                 # REST API
│   │   ├── devices.py
│   │   ├── assessments.py
│   │   ├── reports.py
│   │   └── auth.py
│   └── auth/                # Authentication
│       └── routes.py
├── templates/               # HTML templates
├── static/                  # CSS, JS, images
├── tests/                   # Unit tests
├── requirements.txt         # Python dependencies
├── app.py                  # Main application
└── README.md
```

## Development

### Chạy tests

```bash
pytest tests/
```

### Code formatting

```bash
black app/
flake8 app/
```

### Database migrations

```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

## Deployment

### Docker

```bash
# Build image
docker build -t iot-security-framework .

# Run container
docker run -p 5000:5000 iot-security-framework
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

## Contributing

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Push to branch
5. Tạo Pull Request

## License

MIT License - xem file LICENSE để biết thêm chi tiết.

## Support

- Email: support@iotsecurity.local
- Documentation: [Wiki](link-to-wiki)
- Issues: [GitHub Issues](link-to-issues)
