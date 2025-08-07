# FRAMEWORK ĐÁNH GIÁ BẢO MẬT CÁC THIẾT BỊ IoT TRONG HỆ SINH THÁI SMART HOME

**Đề tài tốt nghiệp**

---

# CHƯƠNG I. ĐẶT VẤN ĐỀ

## 1. MỤC TIÊU

### 1.1 Mục tiêu tổng quát
Xây dựng một framework tự động hóa việc đánh giá bảo mật các thiết bị IoT trong hệ sinh thái Smart Home, nhằm nâng cao khả năng phát hiện và đánh giá các lỗ hổng bảo mật một cách hiệu quả và toàn diện.

### 1.2 Mục tiêu cụ thể
- **Phát triển công cụ tự động**: Tạo ra framework có khả năng tự động phát hiện, phân loại và đánh giá bảo mật các thiết bị IoT
- **Tích hợp đa giao thức**: Hỗ trợ các giao thức phổ biến trong Smart Home như MQTT, CoAP, HTTP/HTTPS
- **Báo cáo chi tiết**: Tạo ra các báo cáo bảo mật chi tiết với mức độ rủi ro và khuyến nghị khắc phục
- **Giao diện thân thiện**: Cung cấp giao diện web dễ sử dụng cho người dùng không chuyên
- **Tính mở rộng**: Thiết kế kiến trúc cho phép dễ dàng thêm các module kiểm tra mới

### 1.3 Đối tượng hướng đến
- **Security Researchers**: Nghiên cứu lỗ hổng bảo mật IoT
- **Penetration Testers**: Đánh giá bảo mật trong các dự án testing
- **IT Security Teams**: Kiểm tra bảo mật mạng doanh nghiệp
- **IoT Manufacturers**: Kiểm tra sản phẩm trước khi phát hành
- **Học viện**: Nghiên cứu và giảng dạy về IoT security

## 2. LÝ DO CHỌN ĐỀ TÀI

### 2.1 Bối cảnh thực tiễn

#### Sự bùng nổ của IoT
- Theo dự báo của Statista, số lượng thiết bị IoT toàn cầu sẽ đạt 30.9 tỷ vào năm 2025
- Thị trường Smart Home dự kiến tăng trưởng 32% mỗi năm từ 2021-2028
- Việt Nam có hơn 2.5 triệu hộ gia đình sử dụng thiết bị Smart Home

#### Thách thức bảo mật IoT
- **Thiết kế không an toàn**: 70% thiết bị IoT có lỗ hổng bảo mật nghiêm trọng
- **Mật khẩu mặc định**: 80% thiết bị sử dụng mật khẩu yếu hoặc không đổi được
- **Mã hóa kém**: 60% thiết bị không mã hóa dữ liệu truyền tải
- **Cập nhật không thường xuyên**: 90% thiết bị không nhận được bản vá bảo mật đều đặn

#### Tác động kinh tế
- Chi phí trung bình cho một vụ vi phạm dữ liệu liên quan IoT là $4.45 triệu USD
- Thiệt hại do tấn công IoT tại Việt Nam ước tính 200 triệu USD/năm
- Tuân thủ các quy định bảo mật như GDPR, Cybersecurity Law của Việt Nam

### 2.2 Khoảng trống trong giải pháp hiện tại

#### Thiếu công cụ tổng hợp
- **Tools phân mảnh**: Hiện tại phải sử dụng nhiều công cụ riêng lẻ (Nmap, Shodan, etc.)
- **Thiếu automation**: Hầu hết quy trình đánh giá đều manual, tốn thời gian
- **Không standardized**: Thiếu phương pháp luận chuẩn cho IoT security assessment

#### Hạn chế của giải pháp thương mại
- **Chi phí cao**: Các solution enterprise như Qualys, Rapid7 có giá từ $10,000+/năm
- **Phức tạp**: Khó sử dụng cho SME và individual researchers
- **Tập trung enterprise**: Ít focus vào Smart Home ecosystem

### 2.3 Cơ hội và ý nghĩa

#### Đóng góp khoa học
- Nghiên cứu các pattern tấn công mới trên IoT devices
- Phát triển methodology chuẩn cho IoT security assessment
- Tạo dataset vulnerability cho research community

#### Ứng dụng thực tiễn
- Nâng cao nhận thức về IoT security
- Hỗ trợ doanh nghiệp đánh giá rủi ro
- Góp phần xây dựng ecosystem IoT an toàn hơn

## 3. YÊU CẦU TÍNH NĂNG/CHỨC NĂNG CHÍNH CỦA SẢN PHẨM

### 3.1 Chức năng cốt lõi

#### FR-01: Network Discovery & Device Detection
```
Mô tả: Tự động phát hiện các thiết bị IoT trên mạng
Input: IP range, network configuration
Output: Danh sách devices với thông tin cơ bản
Yêu cầu:
- Scan IP range từ /24 đến /16
- Detect active hosts trong 5 phút
- Identify open ports và services
- Support IPv4 và IPv6
```

#### FR-02: Device Fingerprinting & Classification
```
Mô tả: Nhận dạng loại thiết bị và thông tin chi tiết
Input: Device IP, open ports, service responses
Output: Device type, manufacturer, model, firmware version
Yêu cầu:
- Database 500+ device signatures
- Accuracy >85% cho common devices
- Support banner grabbing
- Protocol-specific identification
```

#### FR-03: Multi-Protocol Security Testing
```
Mô tả: Kiểm tra bảo mật qua các giao thức IoT
Protocols hỗ trợ:
- HTTP/HTTPS: Web interface vulnerabilities
- MQTT: Authentication, authorization testing
- CoAP: Resource discovery, security testing
- UPnP: Service enumeration, exploitation
Yêu cầu:
- Automated test execution
- Custom payload injection
- Response analysis
```

#### FR-04: Vulnerability Assessment
```
Mô tả: Đánh giá lỗ hổng bảo mật dựa trên CVE database
Test categories:
- Default credentials
- Weak authentication
- Unencrypted communications
- Buffer overflow vulnerabilities
- Web application security (OWASP Top 10)
- Configuration weaknesses
```

#### FR-05: Comprehensive Reporting
```
Mô tả: Tạo báo cáo bảo mật chi tiết
Report types:
- Executive Summary: High-level risk overview
- Technical Report: Detailed findings
- Remediation Guide: Step-by-step fixes
- Compliance Check: Mapping to security standards
Format: HTML, PDF, JSON, XML
```

### 3.2 Chức năng hỗ trợ

#### FR-06: Web-based Management Interface
- Dashboard hiển thị tổng quan
- Device management và grouping
- Scan scheduling và automation
- User management và access control
- Real-time scan progress monitoring

#### FR-07: Plugin Architecture
- Extensible testing modules
- Custom vulnerability checks
- Third-party tool integration
- Community plugin marketplace

#### FR-08: Database Management
- Device signature database
- Vulnerability database (CVE sync)
- Historical scan results
- Configuration templates

### 3.3 Yêu cầu phi chức năng

#### NFR-01: Performance Requirements
- **Response Time**: Web interface <2s load time
- **Throughput**: Scan 254 IPs trong 5 phút
- **Scalability**: Support 1000+ devices concurrently
- **Memory Usage**: <2GB RAM for typical usage

#### NFR-02: Security Requirements
- **Authentication**: Multi-factor authentication
- **Authorization**: Role-based access control
- **Encryption**: TLS 1.3 for all communications
- **Audit**: Complete activity logging
- **Privacy**: No data collection without consent

#### NFR-03: Usability Requirements
- **Learning Curve**: <30 minutes for basic usage
- **Documentation**: Complete user manual
- **Accessibility**: WCAG 2.1 AA compliance
- **Multi-language**: English, Vietnamese support

#### NFR-04: Reliability Requirements
- **Availability**: 99.9% uptime
- **Error Handling**: Graceful degradation
- **Recovery**: Auto-restart failed scans
- **Data Integrity**: Transaction-safe database

#### NFR-05: Portability Requirements
- **OS Support**: Linux, macOS, Windows (via Docker)
- **Cloud Deployment**: AWS, GCP, Azure compatible
- **Containerization**: Docker và Kubernetes ready
- **Database**: SQLite, PostgreSQL, MySQL support

## 4. CÔNG NGHỆ SỬ DỤNG

### 4.1 Ngôn ngữ lập trình

#### Python 3.9+
**Lý do chọn:**
- Rich ecosystem cho security tools
- Excellent networking libraries
- Strong community support
- Rapid development capability

**Libraries chính:**
```python
# Network scanning & analysis
import nmap
import scapy
import requests
import asyncio
import aiohttp

# IoT protocols
import paho.mqtt.client as mqtt
import aiocoap
import upnpclient

# Web framework
import flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Data processing
import pandas
import numpy
import sqlite3
import json
```

### 4.2 Framework và thư viện

#### Backend Technologies
- **Flask 2.0+**: Web framework
  - Lightweight và flexible
  - Excellent documentation
  - Rich extension ecosystem
  - RESTful API support

- **SQLAlchemy**: ORM và database management
  - Multi-database support
  - Migration support
  - Query optimization

- **Celery**: Asynchronous task processing
  - Distributed task queue
  - Scalable background jobs
  - Redis/RabbitMQ support

#### Frontend Technologies
- **Bootstrap 5**: Responsive UI framework
- **jQuery 3.6**: DOM manipulation
- **Chart.js**: Data visualization
- **DataTables**: Advanced table features

#### Security Libraries
- **cryptography**: Encryption và hashing
- **python-nmap**: Network scanning
- **requests**: HTTP client với security features
- **paramiko**: SSH client for device access

### 4.3 Cơ sở dữ liệu

#### Primary Database: SQLite
**Advantages:**
- Zero-configuration
- Embedded database
- ACID compliance
- Cross-platform

**Schema design:**
```sql
-- Device information
devices (id, ip, mac, manufacturer, model, firmware, protocols, discovered_at)

-- Vulnerability data
vulnerabilities (id, cve_id, title, description, severity, affected_devices)

-- Assessment results
assessments (id, device_id, test_type, status, started_at, completed_at)

-- Test results
test_results (id, assessment_id, vulnerability_id, status, evidence, remediation)
```

#### Secondary Database: PostgreSQL (Production)
- Better performance for concurrent access
- Advanced querying capabilities
- Backup và replication support

### 4.4 DevOps và Deployment

#### Containerization
```dockerfile
FROM python:3.9-alpine
RUN apk add --no-cache nmap
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . /app
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
```

#### Orchestration
```yaml
# docker-compose.yml
version: '3.8'
services:
  web:
    build: .
    ports: ["5000:5000"]
    depends_on: [redis, postgres]
  
  worker:
    build: .
    command: celery worker
    depends_on: [redis]
  
  redis:
    image: redis:alpine
  
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: iot_security
```

#### CI/CD Pipeline
- **GitHub Actions**: Automated testing
- **Docker Hub**: Container registry
- **AWS ECS**: Production deployment

### 4.5 Testing Framework

#### Unit Testing
```python
import unittest
import pytest
from unittest.mock import Mock, patch

class TestDeviceDiscovery(unittest.TestCase):
    def test_network_scan(self):
        scanner = NetworkScanner()
        results = scanner.scan("192.168.1.0/24")
        self.assertIsInstance(results, list)
```

#### Integration Testing
```python
import requests
import pytest

def test_api_device_scan():
    response = requests.post('/api/scan', 
                           json={'network': '192.168.1.0/24'})
    assert response.status_code == 200
    assert 'scan_id' in response.json()
```

### 4.6 Security Implementation

#### Authentication System
```python
from flask_login import LoginManager
from werkzeug.security import generate_password_hash

class User(UserMixin, db.Model):
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
```

#### API Security
```python
from functools import wraps
import jwt

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorator
```

## 5. KẾT LUẬN

### 5.1 Tổng kết chương
Chương I đã trình bày rõ ràng về mục tiêu, lý do chọn đề tài, yêu cầu chức năng và công nghệ sử dụng cho dự án "Framework Đánh Giá Bảo Mật IoT". Đề tài được lựa chọn dựa trên nhu cầu thực tiễn cấp thiết về bảo mật IoT trong bối cảnh số hóa hiện tại.

### 5.2 Điểm mạnh của đề tài
- **Tính thực tiễn cao**: Giải quyết vấn đề cụ thể trong thực tế
- **Phạm vi phù hợp**: Tập trung vào Smart Home ecosystem
- **Công nghệ phù hợp**: Sử dụng stack công nghệ mature và reliable
- **Khả năng mở rộng**: Thiết kế cho phép phát triển trong tương lai

### 5.3 Kỳ vọng kết quả
Dự án sẽ tạo ra một framework hoàn chỉnh, có khả năng ứng dụng thực tế trong việc đánh giá bảo mật IoT, đồng thời đóng góp vào cộng đồng nghiên cứu bảo mật thông tin.

---

# CHƯƠNG II. PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG

## 1. SƠ ĐỒ KHỐI CHỨC NĂNG

### 1.1 Sơ đồ tổng quan hệ thống

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                           │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│   Web Interface │   REST API      │   CLI Interface │  Reports  │
│   - Dashboard   │   - Device API  │   - Scan Cmd    │  - HTML   │
│   - Device Mgmt │   - Scan API    │   - Config Cmd  │  - PDF    │
│   - Reports     │   - Report API  │   - Report Cmd  │  - JSON   │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                   BUSINESS LOGIC LAYER                          │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│ Discovery       │ Classification  │ Assessment      │ Reporting │
│ Engine          │ Engine          │ Engine          │ Engine    │
│                 │                 │                 │           │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────┐ │ ┌───────┐ │
│ │Network Scan │ │ │Fingerprint  │ │ │Vuln Scanner │ │ │Report │ │
│ │Port Scan    │ │ │Device Class │ │ │Protocol Test│ │ │Export │ │
│ │Service Enum │ │ │Signature DB │ │ │Exploit Test │ │ │Template│ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────┘ │ └───────┘ │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    DATA ACCESS LAYER                            │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│   Device DB     │ Vulnerability   │   Results DB    │ Config DB │
│                 │      DB         │                 │           │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────┐ │ ┌───────┐ │
│ │Devices      │ │ │CVE Database │ │ │Assessments  │ │ │Users  │ │
│ │Signatures   │ │ │Test Rules   │ │ │Test Results │ │ │Settings│ │
│ │Manufacturers│ │ │Remediation  │ │ │Evidence     │ │ │Plugins│ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────┘ │ └───────┘ │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                 INFRASTRUCTURE LAYER                            │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│  Network Tools  │ Security Tools  │   Protocols     │ File Sys  │
│                 │                 │                 │           │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────┐ │ ┌───────┐ │
│ │Nmap         │ │ │Custom Scans │ │ │HTTP Client  │ │ │Config │ │
│ │Scapy        │ │ │CVE Lookup   │ │ │MQTT Client  │ │ │Logs   │ │
│ │Requests     │ │ │Payload Gen  │ │ │CoAP Client  │ │ │Cache  │ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────┘ │ └───────┘ │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
```

### 1.2 Luồng xử lý chính

```
[Start] → [Input Network Range] → [Network Discovery]
    ↓
[Device Detection] → [Service Enumeration] → [Protocol Identification]
    ↓
[Device Classification] → [Signature Matching] → [Device Profile Creation]
    ↓
[Vulnerability Assessment] → [Test Selection] → [Automated Testing]
    ↓
[Result Analysis] → [Risk Scoring] → [Evidence Collection]
    ↓
[Report Generation] → [Template Processing] → [Export Results] → [End]
```

### 1.3 Component Interaction

```
Web UI ←→ REST API ←→ Business Logic ←→ Data Layer
   ↕         ↕            ↕               ↕
CLI ←→ Service Layer ←→ Security Tools ←→ File System
   ↕                      ↕
Reports ←→ Template Engine ←→ Database
```

## 2. ACTORS

### 2.1 Primary Actors (Tương tác trực tiếp)

#### 2.1.1 Security Researcher
- **Vai trò**: Nghiên cứu lỗ hổng bảo mật IoT
- **Mục tiêu**: Khám phá vulnerabilities mới, phân tích attack vectors
- **Quyền hạn**: Full access, custom testing, plugin development
- **Use cases**: 
  - Advanced device analysis
  - Custom exploit development
  - Research data export

#### 2.1.2 Penetration Tester
- **Vai trò**: Đánh giá bảo mật chuyên nghiệp
- **Mục tiêu**: Comprehensive security assessment cho clients
- **Quyền hạn**: Standard testing suite, reporting tools
- **Use cases**:
  - Network-wide IoT assessment
  - Compliance testing
  - Client reporting

#### 2.1.3 IT Security Administrator
- **Vai trò**: Quản lý bảo mật mạng doanh nghiệp
- **Mục tiêu**: Monitor và maintain security posture
- **Quyền hạn**: Read access, basic testing, scheduled scans
- **Use cases**:
  - Regular security monitoring
  - Incident response
  - Compliance reporting

#### 2.1.4 IoT Device Manufacturer
- **Vai trò**: Phát triển và test IoT products
- **Mục tiêu**: Ensure product security before release
- **Quyền hạn**: Device-specific testing, detailed analysis
- **Use cases**:
  - Pre-release security testing
  - Vulnerability remediation
  - Security certification

### 2.2 Secondary Actors (Tương tác gián tiếp)

#### 2.2.1 Database System
- **Vai trò**: Lưu trữ và quản lý dữ liệu
- **Tương tác**: CRUD operations, query processing
- **Services**: Device data, vulnerability DB, results storage

#### 2.2.2 External Vulnerability Database
- **Vai trò**: Cung cấp CVE và security advisories
- **Tương tác**: API calls, data synchronization
- **Services**: CVE lookup, vulnerability updates

#### 2.2.3 Network Infrastructure
- **Vai trò**: Provide network connectivity
- **Tương tác**: Network scanning, device communication
- **Services**: IP routing, protocol support

#### 2.2.4 File System
- **Vai trò**: Store configuration và reports
- **Tương tác**: File I/O operations
- **Services**: Config storage, report export, logging

## 3. BIỂU ĐỒ USECASES

### 3.1 Use Case Diagram Overview

```
                                IoT Security Framework
    ┌─────────────────────────────────────────────────────────────────┐
    │                                                                 │
    │  ┌─────────────────────────┐   ┌──────────────────────────────┐ │
    │  │    Network Discovery    │   │     Device Management        │ │
    │  │                         │   │                              │ │
    │  │  ○ Scan Network         │   │  ○ View Devices             │ │
    │  │  ○ Detect Devices       │   │  ○ Device Details           │ │
    │  │  ○ Service Enumeration  │   │  ○ Group Devices            │ │
    │  └─────────────────────────┘   │  ○ Device History           │ │
    │                                │  ○ Manual Device Add        │ │
Security  ┌─────────────────────┐    └──────────────────────────────┘ │  IT Admin
Researcher │  Vulnerability     │                                     │     │
    │   ── │  Assessment        │ ── ┌──────────────────────────────┐ │ ────┤
    │      │                    │    │        Reporting             │ │     │
    │      │ ○ Select Tests     │    │                              │ │ Penetration
    │      │ ○ Custom Testing   │    │  ○ Generate Reports         │ │    Tester
    │      │ ○ Protocol Testing │    │  ○ Export Results           │ │     │
    │      │ ○ Risk Assessment  │    │  ○ Executive Summary        │ │     │
    │      └─────────────────────┘    │  ○ Technical Details        │ │     │
    │                                 │  ○ Compliance Check         │ │     │
    │  ┌─────────────────────────┐    └──────────────────────────────┘ │     │
    │  │   System Management     │                                     │     │
    │  │                         │    ┌──────────────────────────────┐ │     │
    │  │  ○ User Management      │    │      Configuration           │ │     │
    │  │  ○ Plugin Management    │    │                              │ │     │
    │  │  ○ Database Sync        │    │  ○ Scan Settings            │ │ ────┤
    │  │  ○ System Monitoring    │    │  ○ Alert Configuration      │ │  IoT
    │  └─────────────────────────┘    │  ○ Plugin Configuration     │ │ Manufacturer
    │                                 │  ○ Database Settings        │ │
    │                                 └──────────────────────────────┘ │
    └─────────────────────────────────────────────────────────────────┘

         │                    │                    │                │
         │                    │                    │                │
    ┌─────────┐          ┌─────────┐          ┌─────────┐     ┌─────────┐
    │   CVE   │          │Network  │          │  File   │     │External │
    │Database │          │Infrastructure│     │ System  │     │  APIs   │
    └─────────┘          └─────────┘          └─────────┘     └─────────┘
   (Secondary)          (Secondary)         (Secondary)    (Secondary)
```

### 3.2 Detailed Use Cases

#### UC-01: Network Discovery
- **Primary Actor**: Security Researcher, Penetration Tester
- **Goal**: Discover IoT devices on target network
- **Preconditions**: Network access, IP range specified
- **Main Success Scenario**:
  1. User specifies network range
  2. System performs network scan
  3. System identifies active hosts
  4. System performs port scanning
  5. System enumerates services
  6. System returns device list
- **Extensions**: 
  - 2a. Network unreachable → Show error message
  - 4a. No devices found → Show empty result

#### UC-02: Device Classification
- **Primary Actor**: All user types
- **Goal**: Identify device type and characteristics
- **Preconditions**: Device discovered
- **Main Success Scenario**:
  1. System analyzes device responses
  2. System matches against signature database
  3. System determines device type
  4. System extracts firmware version
  5. System updates device profile
- **Extensions**:
  - 2a. No signature match → Mark as unknown device
  - 4a. Version detection failed → Mark as unknown version

#### UC-03: Vulnerability Assessment
- **Primary Actor**: Security Researcher, Penetration Tester
- **Goal**: Assess device security vulnerabilities
- **Preconditions**: Device classified
- **Main Success Scenario**:
  1. User selects assessment type
  2. System selects appropriate tests
  3. System executes vulnerability tests
  4. System analyzes test results
  5. System calculates risk score
  6. System stores assessment results
- **Extensions**:
  - 3a. Test execution failed → Log error, continue other tests
  - 4a. Inconclusive results → Mark as needs manual review

## 4. XÂY DỰNG CÁC KỊCH BẢN

### 4.1 Kịch bản 1: Comprehensive Smart Home Assessment

#### Background
Một penetration tester cần đánh giá bảo mật toàn bộ hệ thống Smart Home của client trước khi triển khai commercial.

#### Actors
- **Primary**: Penetration Tester (John)
- **Secondary**: Smart Home Network, Device Database

#### Preconditions
- Framework đã được cài đặt và cấu hình
- Tester có quyền truy cập vào mạng Smart Home
- Database đã được cập nhật với latest signatures

#### Main Success Scenario
1. **Network Discovery Phase**
   - John logs vào web interface
   - John nhập network range: 192.168.1.0/24
   - System thực hiện network scan trong 3 phút
   - System phát hiện 15 devices including:
     - 3 Smart cameras
     - 2 Door locks
     - 4 Smart sensors
     - 2 Smart plugs
     - 1 Smart thermostat
     - 1 Smart hub
     - 2 Unknown devices

2. **Device Classification Phase**
   - System tự động classify 13/15 devices thành công
   - 2 unknown devices được đánh dấu cần manual review
   - System extract được firmware versions cho 11 devices
   - Device profiles được tạo với confidence scores

3. **Assessment Configuration**
   - John chọn "Comprehensive Assessment" mode
   - System recommend test suites based on device types
   - John add custom OWASP IoT Top 10 tests
   - Assessment scheduled với parallel execution

4. **Vulnerability Testing Phase**
   - System thực hiện 45 security tests across all devices
   - Critical findings discovered:
     - 2 cameras với default credentials
     - 1 door lock có firmware vulnerability (CVE-2023-1234)
     - Smart hub exposed administrative interface
     - 3 devices use unencrypted HTTP communication
   - Testing completed trong 25 phút

5. **Analysis & Reporting**
   - System tự động calculate risk scores
   - Critical: 3 issues, High: 4 issues, Medium: 8 issues
   - Executive summary generated
   - Technical report với step-by-step remediation
   - Compliance mapping to NIST Cybersecurity Framework
   - Reports exported in PDF và JSON formats

#### Alternative Scenarios
- **2a**: Nếu >30% devices không classify được → System suggest manual fingerprinting
- **4a**: Nếu network timeout → System retry với adjusted timeouts
- **4b**: Nếu device offline during testing → Mark as "needs retry"

#### Postconditions
- Complete assessment report available
- All findings documented với evidence
- Remediation recommendations provided
- Results stored for future comparison

### 4.2 Kịch bản 2: IoT Manufacturer Product Testing

#### Background
ABC IoT Company cần test security của smart doorbell mới trước khi release commercial.

#### Actors
- **Primary**: IoT Security Engineer (Sarah)
- **Secondary**: Test Lab Network, CVE Database

#### Preconditions
- Prototype devices deployed in test environment
- Custom testing profiles configured
- Development team available for remediation

#### Main Success Scenario
1. **Test Environment Setup**
   - Sarah setup isolated test network: 10.0.1.0/24
   - 5 doorbell prototypes deployed với different firmware versions
   - Custom device signature added to database
   - Specialized test suite configured

2. **Targeted Device Testing**
   - System identifies all 5 doorbells correctly
   - Firmware versions: v1.0.1-beta, v1.0.2-beta, etc.
   - Device-specific test profile loaded
   - Custom vulnerability checks configured

3. **Security Assessment Execution**
   - Authentication testing: Default creds, weak passwords
   - Communication security: Encryption, certificate validation
   - Web interface testing: OWASP Top 10 checks
   - Mobile app integration testing
   - Firmware analysis: Binary vulnerability scanning

4. **Critical Findings**
   - Buffer overflow in video processing (Custom-2024-001)
   - Weak encryption keys in firmware
   - Cross-site scripting in web interface
   - Insecure API endpoints exposed

5. **Development Integration**
   - Findings exported to JIRA integration
   - Automatic ticket creation with priority labels
   - Evidence packages attached to tickets
   - Regression testing scheduled after fixes

### 4.3 Kịch bản 3: Enterprise Network Monitoring

#### Background
Enterprise IT team cần monitor IoT devices trong corporate network để ensure compliance và detect rogue devices.

#### Actors
- **Primary**: IT Security Administrator (Mike)
- **Secondary**: Corporate Network, SIEM System

#### Preconditions
- Framework deployed on corporate infrastructure
- Integration với SIEM system configured
- Compliance policies defined

#### Main Success Scenario
1. **Scheduled Scanning**
   - Daily automated scans configured cho 10 subnets
   - Scan runs at 2 AM để minimize business impact
   - Incremental scanning để detect new devices

2. **Device Inventory Management**
   - Known devices automatically classified
   - New devices trigger security alerts
   - Device changes tracked (firmware updates, configuration changes)
   - Compliance status monitored

3. **Anomaly Detection**
   - Rogue smart TV detected in finance subnet
   - Device communicating with suspicious external IPs
   - Unauthorized protocol usage detected
   - Vulnerability remediation tracking

4. **Compliance Reporting**
   - Monthly compliance reports generated
   - Mapping to security frameworks (ISO 27001, NIST)
   - Executive dashboards updated
   - Audit trails maintained

## 5. BIỂU ĐỒ LỚP PHÂN TÍCH

### 5.1 Core Domain Classes

```python
class Device:
    - device_id: str
    - ip_address: str
    - mac_address: str
    - hostname: str
    - manufacturer: str
    - device_type: str
    - model: str
    - firmware_version: str
    - protocols: List[str]
    - last_seen: datetime
    - confidence_score: float
    
    + discover()
    + classify()
    + update_info()
    + get_vulnerabilities()

class NetworkScanner:
    - target_network: str
    - scan_options: dict
    - discovered_devices: List[Device]
    
    + scan_network()
    + port_scan()
    + service_enumeration()
    + protocol_detection()

class VulnerabilityAssessment:
    - assessment_id: str
    - device: Device
    - test_suite: TestSuite
    - results: List[TestResult]
    - risk_score: float
    - status: str
    
    + execute_tests()
    + analyze_results()
    + calculate_risk()
    + generate_evidence()

class TestSuite:
    - suite_id: str
    - name: str
    - description: str
    - tests: List[SecurityTest]
    - device_types: List[str]
    
    + load_tests()
    + filter_by_device()
    + execute_all()

class SecurityTest:
    - test_id: str
    - name: str
    - description: str
    - severity: str
    - test_type: str
    - payload: str
    
    + execute()
    + validate_result()
    + collect_evidence()

class Report:
    - report_id: str
    - assessment: VulnerabilityAssessment
    - template: ReportTemplate
    - generated_at: datetime
    - format: str
    
    + generate_executive_summary()
    + generate_technical_report()
    + export_to_pdf()
    + export_to_json()
```

### 5.2 Infrastructure Classes

```python
class DatabaseManager:
    - connection: Connection
    - device_repository: DeviceRepository
    - vulnerability_repository: VulnRepository
    
    + save_device()
    + update_vulnerability_db()
    + get_device_history()
    + cleanup_old_data()

class ConfigurationManager:
    - config_file: str
    - settings: dict
    
    + load_config()
    + save_config()
    + get_setting()
    + validate_config()

class PluginManager:
    - plugin_directory: str
    - loaded_plugins: dict
    
    + load_plugins()
    + register_plugin()
    + execute_plugin()
    + unload_plugin()

class WebInterface:
    - app: Flask
    - api_routes: dict
    - template_engine: TemplateEngine
    
    + render_dashboard()
    + handle_api_request()
    + serve_static_files()
    + handle_authentication()
```

### 5.3 Class Relationships

```
Device *-- VulnerabilityAssessment
VulnerabilityAssessment *-- TestSuite
TestSuite *-- SecurityTest
VulnerabilityAssessment *-- Report

NetworkScanner --> Device : creates
VulnerabilityAssessment --> SecurityTest : executes
Report --> ReportTemplate : uses
DatabaseManager --> Device : persists

WebInterface --> NetworkScanner : controls
WebInterface --> VulnerabilityAssessment : manages
WebInterface --> Report : generates
```

## 6. BIỂU ĐỒ TUẦN TỰ (SEQUENCES)

### 6.1 Network Discovery Sequence

```mermaid
sequenceDiagram
    participant U as User
    participant W as WebInterface
    participant N as NetworkScanner
    participant D as Device
    participant DB as Database
    
    U->>W: Start Network Scan
    W->>N: scan_network(ip_range)
    N->>N: validate_ip_range()
    
    loop For each IP in range
        N->>D: ping_host(ip)
        alt Host is alive
            D-->>N: host_response
            N->>D: port_scan(ip)
            D-->>N: open_ports
            N->>D: service_enumeration(ports)
            D-->>N: service_info
            N->>D: create_device_profile()
        end
    end
    
    N->>DB: save_discovered_devices()
    DB-->>N: success
    N-->>W: scan_complete(device_list)
    W-->>U: Display Results
```

### 6.2 Vulnerability Assessment Sequence

```mermaid
sequenceDiagram
    participant U as User
    participant W as WebInterface
    participant V as VulnAssessment
    participant T as TestSuite
    participant S as SecurityTest
    participant DB as Database
    
    U->>W: Start Assessment
    W->>V: create_assessment(device_id)
    V->>DB: get_device_info(device_id)
    DB-->>V: device_details
    
    V->>T: load_test_suite(device_type)
    T->>DB: get_applicable_tests()
    DB-->>T: test_list
    
    loop For each test
        V->>S: execute_test(device, test_params)
        S->>S: send_payload()
        S->>S: analyze_response()
        S-->>V: test_result
        V->>DB: save_test_result()
    end
    
    V->>V: calculate_risk_score()
    V->>DB: save_assessment()
    V-->>W: assessment_complete
    W-->>U: Show Results
```

### 6.3 Report Generation Sequence

```mermaid
sequenceDiagram
    participant U as User
    participant W as WebInterface
    participant R as ReportEngine
    participant T as Template
    participant DB as Database
    participant F as FileSystem
    
    U->>W: Generate Report
    W->>R: generate_report(assessment_id, format)
    R->>DB: get_assessment_data(assessment_id)
    DB-->>R: assessment_data
    
    R->>T: load_template(report_type)
    T-->>R: template_content
    
    R->>R: process_template(data, template)
    R->>R: format_output(format)
    
    alt PDF Format
        R->>R: convert_to_pdf()
    else JSON Format
        R->>R: serialize_to_json()
    end
    
    R->>F: save_report_file()
    F-->>R: file_path
    R-->>W: report_ready(file_path)
    W-->>U: Download Link
```

## 7. THIẾT KẾ CƠ SỞ DỮ LIỆU (ERD)

### 7.1 Sơ đồ thiết kế cơ sở dữ liệu

```sql
-- Entity Relationship Diagram
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Users       │    │    Devices      │    │  Assessments    │
│─────────────────│    │─────────────────│    │─────────────────│
│ user_id (PK)    │    │ device_id (PK)  │    │ assessment_id(PK)│
│ username        │    │ ip_address      │    │ device_id (FK)  │
│ password_hash   │    │ mac_address     │    │ user_id (FK)    │
│ email           │    │ hostname        │    │ test_suite_id   │
│ role            │    │ manufacturer    │    │ status          │
│ created_at      │    │ device_type     │    │ started_at      │
│ last_login      │    │ model           │    │ completed_at    │
└─────────────────┘    │ firmware_version│    │ risk_score      │
         │              │ protocols       │    │ summary         │
         │              │ discovered_at   │    └─────────────────┘
         │              │ last_seen       │             │
         │              │ confidence      │             │
         │              │ notes           │             │
         │              └─────────────────┘             │
         │                       │                      │
         │                       │                      │
         └───────────────────────┼──────────────────────┘
                                 │
    ┌─────────────────┐         │         ┌─────────────────┐
    │   TestSuites    │         │         │   TestResults   │
    │─────────────────│         │         │─────────────────│
    │ suite_id (PK)   │         │         │ result_id (PK)  │
    │ name            │         │         │ assessment_id(FK)│
    │ description     │         │         │ test_id (FK)    │
    │ device_types    │         │         │ vulnerability_id │
    │ created_by      │         │         │ status          │
    │ created_at      │         │         │ severity        │
    └─────────────────┘         │         │ evidence        │
              │                 │         │ remediation     │
              │                 │         │ executed_at     │
              │                 │         └─────────────────┘
    ┌─────────────────┐         │                  │
    │  SecurityTests  │         │                  │
    │─────────────────│         │                  │
    │ test_id (PK)    │         │                  │
    │ suite_id (FK)   │─────────┘                  │
    │ name            │                            │
    │ description     │                            │
    │ test_type       │                            │
    │ payload         │                            │
    │ expected_result │                            │
    │ severity        │                            │
    │ remediation     │                            │
    └─────────────────┘                            │
              │                                    │
              │                                    │
    ┌─────────────────┐                           │
    │ Vulnerabilities │                           │
    │─────────────────│                           │
    │ vuln_id (PK)    │───────────────────────────┘
    │ cve_id          │
    │ title           │
    │ description     │
    │ severity        │
    │ cvss_score      │
    │ affected_devices│
    │ remediation     │
    │ published_date  │
    │ last_updated    │
    └─────────────────┘
```

### 7.2 Mô tả chức năng bảng CSDL

#### 7.2.1 Bảng Users
**Chức năng**: Quản lý thông tin người dùng và phân quyền
```sql
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    role ENUM('admin', 'tester', 'viewer') DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);
```
**Dữ liệu mẫu**:
- admin/admin123 (System Administrator)
- tester1/test123 (Security Tester) 
- viewer1/view123 (Read-only User)

#### 7.2.2 Bảng Devices
**Chức năng**: Lưu trữ thông tin thiết bị IoT được phát hiện
```sql
CREATE TABLE devices (
    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    manufacturer VARCHAR(100),
    device_type VARCHAR(50),
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    protocols TEXT, -- JSON array of supported protocols
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    confidence FLOAT DEFAULT 0.0, -- Classification confidence 0-1
    notes TEXT
);
```
**Index**: 
```sql
CREATE INDEX idx_devices_ip ON devices(ip_address);
CREATE INDEX idx_devices_type ON devices(device_type);
CREATE INDEX idx_devices_manufacturer ON devices(manufacturer);
```

#### 7.2.3 Bảng Assessments
**Chức năng**: Theo dõi các phiên đánh giá bảo mật
```sql
CREATE TABLE assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    test_suite_id INTEGER,
    status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    risk_score FLOAT DEFAULT 0.0, -- 0-10 scale
    summary TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (test_suite_id) REFERENCES test_suites(suite_id)
);
```

#### 7.2.4 Bảng TestSuites
**Chức năng**: Định nghĩa bộ kiểm tra bảo mật
```sql
CREATE TABLE test_suites (
    suite_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    device_types TEXT, -- JSON array of applicable device types
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (created_by) REFERENCES users(user_id)
);
```
**Dữ liệu mẫu**:
- "Smart Home Basic": Basic security tests for smart home devices
- "OWASP IoT Top 10": Tests based on OWASP IoT security guidelines
- "Industrial IoT": Specialized tests for industrial devices

#### 7.2.5 Bảng SecurityTests
**Chức năng**: Chi tiết các kiểm tra bảo mật cụ thể
```sql
CREATE TABLE security_tests (
    test_id INTEGER PRIMARY KEY AUTOINCREMENT,
    suite_id INTEGER NOT NULL,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    test_type ENUM('credential', 'protocol', 'web', 'network', 'firmware') NOT NULL,
    payload TEXT, -- Test payload or script
    expected_result TEXT,
    severity ENUM('info', 'low', 'medium', 'high', 'critical') DEFAULT 'medium',
    remediation TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (suite_id) REFERENCES test_suites(suite_id)
);
```

#### 7.2.6 Bảng TestResults
**Chức năng**: Lưu trữ kết quả kiểm tra chi tiết
```sql
CREATE TABLE test_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    test_id INTEGER NOT NULL,
    vulnerability_id INTEGER,
    status ENUM('pass', 'fail', 'error', 'skip') NOT NULL,
    severity ENUM('info', 'low', 'medium', 'high', 'critical'),
    evidence TEXT, -- JSON object with proof/screenshots
    remediation TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    execution_time INTEGER, -- milliseconds
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id),
    FOREIGN KEY (test_id) REFERENCES security_tests(test_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vuln_id)
);
```

#### 7.2.7 Bảng Vulnerabilities
**Chức năng**: Database các lỗ hổng bảo mật đã biết
```sql
CREATE TABLE vulnerabilities (
    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id VARCHAR(20) UNIQUE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    severity ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL,
    cvss_score FLOAT,
    affected_devices TEXT, -- JSON array of device patterns
    remediation TEXT,
    references TEXT, -- JSON array of reference URLs
    published_date DATE,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 7.3 Mô tả quan hệ các bảng

#### 7.3.1 Quan hệ One-to-Many

**Users → Assessments (1:N)**
- Một user có thể thực hiện nhiều assessments
- Mỗi assessment thuộc về một user cụ thể
- Foreign key: assessments.user_id → users.user_id

**Devices → Assessments (1:N)**
- Một device có thể được assess nhiều lần
- Mỗi assessment target một device cụ thể
- Foreign key: assessments.device_id → devices.device_id

**TestSuites → SecurityTests (1:N)**
- Một test suite chứa nhiều security tests
- Mỗi security test thuộc về một suite
- Foreign key: security_tests.suite_id → test_suites.suite_id

**Assessments → TestResults (1:N)**
- Một assessment tạo ra nhiều test results
- Mỗi test result thuộc về một assessment
- Foreign key: test_results.assessment_id → assessments.assessment_id

#### 7.3.2 Quan hệ Many-to-Many

**SecurityTests ↔ TestResults ↔ Vulnerabilities (M:N)**
- Một security test có thể phát hiện nhiều vulnerabilities
- Một vulnerability có thể được detect bởi nhiều tests
- Implemented through test_results table as junction table

#### 7.3.3 Business Rules

**Referential Integrity Rules**:
```sql
-- Cannot delete user if they have assessments
ALTER TABLE assessments ADD CONSTRAINT fk_user_assessments 
    FOREIGN KEY (user_id) REFERENCES users(user_id) 
    ON DELETE RESTRICT;

-- Cannot delete device if it has assessments
ALTER TABLE assessments ADD CONSTRAINT fk_device_assessments 
    FOREIGN KEY (device_id) REFERENCES devices(device_id) 
    ON DELETE RESTRICT;

-- Cascade delete test results when assessment is deleted
ALTER TABLE test_results ADD CONSTRAINT fk_assessment_results 
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) 
    ON DELETE CASCADE;
```

**Data Integrity Constraints**:
```sql
-- Risk score must be between 0 and 10
ALTER TABLE assessments ADD CONSTRAINT chk_risk_score 
    CHECK (risk_score >= 0 AND risk_score <= 10);

-- CVSS score must be between 0 and 10
ALTER TABLE vulnerabilities ADD CONSTRAINT chk_cvss_score 
    CHECK (cvss_score >= 0 AND cvss_score <= 10);

-- IP address format validation (simplified)
ALTER TABLE devices ADD CONSTRAINT chk_ip_format 
    CHECK (ip_address REGEXP '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} );
```

## 8. THIẾT KẾ GIAO DIỆN PHÁC THẢO

### 8.1 Dashboard Interface

#### 8.1.1 Main Dashboard Wireframe
```
┌────────────────────────────────────────────────────────────────┐
│  IoT Security Framework                    [User] [Logout]      │
├────────────────────────────────────────────────────────────────┤
│ [Dashboard] [Devices] [Assessments] [Reports] [Settings]       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  📊 Security Overview                    🔍 Quick Actions      │
│  ┌─────────────────────────────────┐    ┌─────────────────────┐ │
│  │ Total Devices: 127              │    │ [Start Network Scan]│ │
│  │ ⚠️  Critical Issues: 8           │    │ [New Assessment]    │ │
│  │ 📈 Medium Issues: 23            │    │ [View Latest Report]│ │
│  │ ✅ Secure Devices: 96           │    │ [Manage Plugins]    │ │
│  └─────────────────────────────────┘    └─────────────────────┘ │
│                                                                │
│  📊 Recent Activity                      🏆 Top Vulnerabilities │
│  ┌─────────────────────────────────┐    ┌─────────────────────┐ │
│  │ • Smart Camera assessment       │    │ • Default Creds: 15│ │
│  │   completed - 3 issues found    │    │ • Weak Encryption:12│ │
│  │   2 hours ago                   │    │ • Open Ports: 8     │ │
│  │                                 │    │ • Outdated FW: 6    │ │
│  │ • Network scan discovered       │    │ • Web Vulns: 4      │ │
│  │   5 new devices - 1 hour ago    │    │                     │ │
│  │                                 │    │                     │ │
│  │ • IoT Router assessment failed  │    │                     │ │
│  │   Device unreachable - 3h ago   │    │                     │ │
│  └─────────────────────────────────┘    └─────────────────────┘ │
│                                                                │
│  📈 Security Trend (Last 30 days)                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │     High ████████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓         │ │
│  │   Medium ████████████████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓         │ │
│  │      Low ████████████████████████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓         │ │
│  │     Safe ████████████████████████████████████████         │ │
│  │          Jan    Feb    Mar    Apr    May    Jun            │ │
│  └────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

#### 8.1.2 Device List Interface
```
┌────────────────────────────────────────────────────────────────┐
│  Device Management                         [Add Device] [Scan] │
├────────────────────────────────────────────────────────────────┤
│  Filters: [All Types ▼] [All Manufacturers ▼] [All Status ▼]  │
│  Search: [_________________] [🔍] Sort: [Risk Score ▼]         │
├────────────────────────────────────────────────────────────────┤
│  ☑️ IP Address    │ Type      │ Manufacturer │ Risk │ Actions   │
├────────────────────────────────────────────────────────────────┤
│  ☑️ 192.168.1.100│ Camera    │ Hikvision    │ 🔴 9.2│[Test][View]│
│  ☑️ 192.168.1.101│ Door Lock │ Yale         │ 🟠 7.5│[Test][View]│
│  ☑️ 192.168.1.102│ Sensor    │ Xiaomi       │ 🟡 4.2│[Test][View]│
│  ☑️ 192.168.1.103│ Router    │ TP-Link      │ 🟠 6.8│[Test][View]│
│  ☑️ 192.168.1.104│ Smart TV  │ Samsung      │ 🟡 3.1│[Test][View]│
│  ☑️ 192.168.1.105│ Thermostat│ Nest         │ 🟢 1.5│[Test][View]│
├────────────────────────────────────────────────────────────────┤
│  Selected: 6 devices    [Bulk Test] [Export CSV] [Delete]      │
│  Showing 1-10 of 127    [< Previous] [1][2][3]...[13] [Next >]│
└────────────────────────────────────────────────────────────────┘
```

#### 8.1.3 Assessment Configuration
```
┌────────────────────────────────────────────────────────────────┐
│  New Security Assessment                                       │
├────────────────────────────────────────────────────────────────┤
│  Target Selection                                              │
│  ○ Single Device  ● Multiple Devices  ○ Network Range         │
│                                                                │
│  Selected Devices: 3 devices                                  │
│  • 192.168.1.100 - Smart Camera (Hikvision)                  │
│  • 192.168.1.101 - Door Lock (Yale)                          │
│  • 192.168.1.102 - Motion Sensor (Xiaomi)                    │
│                                                                │
│  Test Suite Selection                                          │
│  ☑️ OWASP IoT Top 10           Comprehensive IoT security     │
│  ☑️ Default Credentials        Test common default passwords  │
│  ☑️ Network Security           Port scans and service tests   │
│  ☐ Custom Web Tests            Web application vulnerabilities│
│  ☐ Firmware Analysis           Binary analysis (Advanced)     │
│                                                                │
│  Assessment Options                                            │
│  Scan Intensity:  ○ Light  ● Normal  ○ Aggressive            │
│  Concurrent Tests: [5] devices at once                        │
│  Timeout:         [30] seconds per test                       │
│  ☑️ Generate detailed report                                  │
│  ☑️ Include remediation steps                                 │
│                                                                │
│  Scheduling                                                    │
│  ○ Run Now  ○ Schedule Later: [2024-08-15] [14:30]           │
│                                                                │
│         [Cancel]                              [Start Assessment]│
└────────────────────────────────────────────────────────────────┘
```

#### 8.1.4 Assessment Progress Interface
```
┌────────────────────────────────────────────────────────────────┐
│  Assessment in Progress - ID: ASS-2024-001                    │
├────────────────────────────────────────────────────────────────┤
│  Status: Running  │  Started: 14:25:30  │  Elapsed: 00:05:42   │
│  Progress: ████████████▓▓▓▓▓▓▓▓ 65%                           │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Device Progress:                                              │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ 192.168.1.100 - Smart Camera        ✅ Completed (8/8)  │ │
│  │ • Default Credentials    ❌ Failed - admin/admin found   │ │  
│  │ • Web Interface Tests    ⚠️  Warning - XSS vulnerability │ │
│  │ • Network Services       ✅ Passed                       │ │
│  │ • Encryption Tests       ❌ Failed - Unencrypted HTTP    │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ 192.168.1.101 - Door Lock           🔄 Running (3/6)    │ │
│  │ • Default Credentials    ✅ Passed                       │ │
│  │ • Protocol Security      ❌ Failed - Weak encryption     │ │
│  │ • Firmware Analysis      🔄 Running...                   │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ 192.168.1.102 - Motion Sensor       ⏳ Queued (0/4)     │ │
│  │ • Waiting for previous tests to complete...               │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
│  Current Findings: 🔴 2 Critical  🟠 1 High  🟡 3 Medium      │
│                                                                │
│                    [View Live Results]        [Stop Assessment]│
└────────────────────────────────────────────────────────────────┘
```

### 8.2 Report Interface Design

#### 8.2.1 Report Generation Interface
```
┌────────────────────────────────────────────────────────────────┐
│  Generate Assessment Report                                    │
├────────────────────────────────────────────────────────────────┤
│  Assessment: ASS-2024-001                                     │
│  Completed: 2024-08-15 14:45:30                              │
│  Devices Tested: 3                                           │
│  Total Issues: 12 (Critical: 3, High: 2, Medium: 7)          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Report Configuration                                          │
│                                                                │
│  Report Type:                                                 │
│  ○ Executive Summary    - High-level overview for management   │
│  ● Technical Report     - Detailed findings for IT teams      │
│  ○ Compliance Report    - Mapping to security frameworks      │
│  ○ Remediation Guide    - Step-by-step fixing instructions    │
│                                                                │
│  Include Sections:                                            │
│  ☑️ Executive Summary       ☑️ Risk Assessment                │
│  ☑️ Detailed Findings       ☑️ Evidence Screenshots          │
│  ☑️ Remediation Steps       ☑️ Device Inventory              │
│  ☐ Compliance Mapping       ☐ Technical Appendix             │
│                                                                │
│  Filter by Severity:                                          │
│  ☑️ Critical  ☑️ High  ☑️ Medium  ☐ Low  ☐ Info              │
│                                                                │
│  Output Format:                                               │
│  ● PDF Report  ☐ HTML Report  ☐ JSON Data  ☐ Excel Export    │
│                                                                │
│  Report Template:                                             │
│  [Professional ▼]  [Preview Template]                        │
│                                                                │
│         [Cancel]                              [Generate Report]│
└────────────────────────────────────────────────────────────────┘
```

#### 8.2.2 Report Preview Interface
```
┌────────────────────────────────────────────────────────────────┐
│  IoT Security Assessment Report - Preview                     │
├────────────────────────────────────────────────────────────────┤
│  📊 EXECUTIVE SUMMARY                                          │
│                                                                │
│  Assessment Overview                                           │
│  • Assessment ID: ASS-2024-001                               │
│  • Date: August 15, 2024                                     │
│  • Duration: 25 minutes                                       │
│  • Devices Tested: 3                                         │
│                                                                │
│  Risk Level: 🔴 HIGH RISK                                     │
│                                                                │
│  Key Findings                                                  │
│  • 3 Critical vulnerabilities requiring immediate attention   │
│  • Default credentials found on 1 device                     │
│  • Unencrypted communications detected                        │
│  • Web interface vulnerabilities present                      │
│                                                                │
│  Business Impact                                              │
│  • Data breach risk: HIGH                                     │
│  • Unauthorized access: HIGH                                  │
│  • Privacy violation: MEDIUM                                  │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│  🔍 DETAILED FINDINGS                                          │
│                                                                │
│  Finding #1: Default Credentials (Critical)                   │
│  Device: Smart Camera (192.168.1.100)                        │
│  Description: Device accessible with admin/admin              │
│  Impact: Full device compromise                               │
│  Recommendation: Change default password immediately          │
│                                                                │
│  Finding #2: Cross-Site Scripting (High)                     │
│  Device: Smart Camera (192.168.1.100)                        │
│  Description: XSS in web configuration interface             │
│  Impact: Session hijacking, credential theft                  │
│  Recommendation: Update firmware to latest version            │
│                                                                │
│  [...additional findings...]                                  │
│                                                                │
│                    [Download PDF]         [Back to Dashboard] │
└────────────────────────────────────────────────────────────────┘
```

### 8.3 Mobile Interface Design

#### 8.3.1 Mobile Dashboard
```
┌──────────────────────┐
│ IoT Security    [☰] │
├──────────────────────┤
│ 🏠 Dashboard         │
│                      │
│ ┌──────────────────┐ │
│ │ Security Status  │ │
│ │ 🔴 3 Critical    │ │
│ │ 🟠 5 High        │ │
│ │ 🟡 12 Medium     │ │
│ │ ✅ 107 Safe      │ │
│ └──────────────────┘ │
│                      │
│ ┌──────────────────┐ │
│ │ Quick Actions    │ │
│ │ [Scan Network]   │ │
│ │ [View Devices]   │ │
│ │ [Latest Report]  │ │
│ └──────────────────┘ │
│                      │
│ Recent Activity      │
│ • Camera scan done   │
│   2 issues found     │
│   1h ago             │
│                      │
│ • 3 new devices      │
│   discovered         │
│   3h ago             │
└──────────────────────┘
```

## 9. THUẬT TOÁN GỢI Ý CÔNG VIỆC

### 9.1 Network Discovery Algorithm

#### 9.1.1 Intelligent Network Scanning
```python
def intelligent_network_scan(network_range, scan_options=None):
    """
    Thuật toán quét mạng thông minh với optimization
    
    Args:
        network_range: CIDR notation (e.g., "192.168.1.0/24")
        scan_options: Dict với các tùy chọn scan
    
    Returns:
        List[Device]: Danh sách thiết bị được phát hiện
    """
    
    # Phase 1: Quick Host Discovery
    alive_hosts = []
    ip_list = generate_ip_list(network_range)
    
    # Parallel ping sweep với threading
    with ThreadPoolExecutor(max_workers=50) as executor:
        ping_results = executor.map(ping_host, ip_list)
        alive_hosts = [ip for ip, is_alive in zip(ip_list, ping_results) if is_alive]
    
    print(f"Discovered {len(alive_hosts)} active hosts")
    
    # Phase 2: Port Scanning với intelligent port selection
    devices = []
    for host_ip in alive_hosts:
        device = Device(ip_address=host_ip)
        
        # Smart port selection dựa trên device type hints
        ports_to_scan = select_smart_ports(host_ip)
        
        # Adaptive timeout dựa trên network latency
        timeout = calculate_adaptive_timeout(host_ip)
        
        # Thực hiện port scan
        open_ports = port_scan(host_ip, ports_to_scan, timeout)
        device.open_ports = open_ports
        
        # Service enumeration cho các port mở
        if open_ports:
            device.services = enumerate_services(host_ip, open_ports)
            device.protocols = detect_protocols(device.services)
            
            # IoT-specific fingerprinting
            device.fingerprint = iot_fingerprinting(device)
            
        devices.append(device)
    
    return devices

def select_smart_ports(ip_address):
    """
    Chọn ports để scan dựa trên IoT device patterns
    """
    # Common IoT ports
    base_ports = [21, 22, 23, 53, 80, 135, 139, 443, 445, 993, 995]
    
    # IoT-specific ports
    iot_ports = [
        1883,    # MQTT
        5683,    # CoAP
        8080,    # Alt HTTP
        8443,    # Alt HTTPS  
        9999,    # Common IoT admin
        37777,   # Dahua cameras
        554,     # RTSP
        8000,    # Common webcam
        10001,   # Ubiquiti
    ]
    
    # Network-based intelligent selection
    if is_likely_camera_subnet(ip_address):
        return base_ports + [554, 8000, 37777, 80, 443]
    elif is_likely_sensor_subnet(ip_address):
        return base_ports + [1883, 5683, 8080]
    else:
        return base_ports + iot_ports

def iot_fingerprinting(device):
    """
    IoT-specific device fingerprinting
    """
    fingerprint = {}
    
    # HTTP banner analysis
    if 80 in device.open_ports or 443 in device.open_ports:
        http_banner = get_http_banner(device.ip_address)
        fingerprint.update(analyze_http_banner(http_banner))
    
    # MQTT broker detection
    if 1883 in device.open_ports:
        mqtt_info = probe_mqtt_broker(device.ip_address)
        fingerprint.update(mqtt_info)
    
    # UPnP discovery
    upnp_devices = discover_upnp(device.ip_address)
    if upnp_devices:
        fingerprint['upnp_devices'] = upnp_devices
    
    # MAC address OUI lookup
    if device.mac_address:
        manufacturer = lookup_oui(device.mac_address)
        fingerprint['manufacturer'] = manufacturer
    
    return fingerprint
```

#### 9.1.2 Device Classification Algorithm
```python
class DeviceClassifier:
    def __init__(self, signature_db):
        self.signature_db = signature_db
        self.ml_model = load_classification_model()
    
    def classify_device(self, device):
        """
        Multi-stage device classification
        """
        classification_result = {
            'device_type': 'unknown',
            'manufacturer': 'unknown',
            'model': 'unknown',
            'confidence': 0.0,
            'method': 'none'
        }
        
        # Stage 1: Signature-based classification
        signature_result = self.signature_classification(device)
        
        if signature_result['confidence'] > 0.8:
            return signature_result
        
        # Stage 2: Heuristic-based classification
        heuristic_result = self.heuristic_classification(device)
        
        if heuristic_result['confidence'] > 0.6:
            return heuristic_result
        
        # Stage 3: ML-based classification (if available)
        if self.ml_model:
            ml_result = self.ml_classification(device)
            return ml_result
        
        return classification_result
    
    def signature_classification(self, device):
        """
        Database signature matching
        """
        best_match = {
            'device_type': 'unknown',
            'confidence': 0.0,
            'method': 'signature'
        }
        
        for signature in self.signature_db:
            match_score = self.calculate_signature_match(device, signature)
            
            if match_score > best_match['confidence']:
                best_match.update({
                    'device_type': signature['device_type'],
                    'manufacturer': signature['manufacturer'],
                    'model': signature['model'],
                    'confidence': match_score
                })
        
        return best_match
    
    def heuristic_classification(self, device):
        """
        Rule-based heuristic classification
        """
        score = 0.0
        device_type = 'unknown'
        
        # Port pattern analysis
        if set([554, 80]).issubset(device.open_ports):
            device_type = 'camera'
            score += 0.4
        
        if 1883 in device.open_ports:
            device_type = 'sensor'
            score += 0.3
        
        # HTTP response analysis
        if device.services.get('http'):
            server_header = device.services['http'].get('server', '')
            
            if 'camera' in server_header.lower():
                device_type = 'camera'
                score += 0.5
            elif 'router' in server_header.lower():
                device_type = 'router'
                score += 0.4
        
        # UPnP device description
        if device.fingerprint.get('upnp_devices'):
            for upnp_device in device.fingerprint['upnp_devices']:
                device_desc = upnp_device.get('device_type', '').lower()
                
                if 'mediaserver' in device_desc:
                    device_type = 'media_device'
                    score += 0.3
                elif 'internetgateway' in device_desc:
                    device_type = 'router'
                    score += 0.5
        
        return {
            'device_type': device_type,
            'confidence': min(score, 1.0),
            'method': 'heuristic'
        }
```

### 9.2 Vulnerability Assessment Algorithm

#### 9.2.1 Adaptive Test Selection
```python
def adaptive_test_selection(device, test_suite_config):
    """
    Intelligent test selection dựa trên device characteristics
    """
    selected_tests = []
    device_type = device.classification.get('device_type', 'unknown')
    manufacturer = device.classification.get('manufacturer', 'unknown')
    
    # Base tests cho tất cả devices
    base_tests = [
        'default_credentials',
        'open_ports_check',
        'service_enumeration'
    ]
    selected_tests.extend(base_tests)
    
    # Device-specific tests
    if device_type == 'camera':
        camera_tests = [
            'rtsp_authentication',
            'web_interface_security',
            'video_stream_encryption',
            'onvif_security'
        ]
        selected_tests.extend(camera_tests)
    
    elif device_type == 'router':
        router_tests = [
            'admin_interface_security',
            'upnp_vulnerabilities',
            'dns_security',
            'wifi_security'
        ]
        selected_tests.extend(router_tests)
    
    elif device_type == 'sensor':
        sensor_tests = [
            'mqtt_security',
            'coap_security',
            'data_encryption'
        ]
        selected_tests.extend(sensor_tests)
    
    # Manufacturer-specific tests
    if manufacturer.lower() == 'hikvision':
        selected_tests.extend(['hikvision_backdoor', 'sadp_protocol'])
    elif manufacturer.lower() == 'dahua':
        selected_tests.extend(['dahua_rce', 'dhip_protocol'])
    
    # Protocol-based tests
    for protocol in device.protocols:
        if protocol == 'http':
            selected_tests.extend(['http_security_headers', 'web_vulnerabilities'])
        elif protocol == 'mqtt':
            selected_tests.extend(['mqtt_authentication', 'mqtt_encryption'])
        elif protocol == 'coap':
            selected_tests.extend(['coap_discovery', 'coap_security'])
    
    # Remove duplicates và prioritize
    selected_tests = list(set(selected_tests))
    
    # Prioritize tests dựa trên risk và impact
    prioritized_tests = prioritize_tests(selected_tests, device)
    
    return prioritized_tests

def prioritize_tests(tests, device):
    """
    Sắp xếp tests theo mức độ ưu tiên
    """
    priority_weights = {
        # High priority - High risk, easy to exploit
        'default_credentials': 10,
        'admin_interface_security': 9,
        'web_vulnerabilities': 8,
        
        # Medium priority - Important but complex
        'service_enumeration': 6,
        'protocol_security': 5,
        'encryption_tests': 5,
        
        # Low priority - Information gathering
        'open_ports_check': 3,
        'banner_grabbing': 2,
        'device_info': 1
    }
    
    # Calculate scores cho mỗi test
    test_scores = []
    for test_name in tests:
        base_score = priority_weights.get(test_name, 5)
        
        # Adjust dựa trên device characteristics
        if device.classification.get('confidence', 0) > 0.8:
            base_score += 2  # More targeted tests for known devices
        
        if device.open_ports and len(device.open_ports) > 10:
            base_score += 1  # More comprehensive testing for complex devices
        
        test_scores.append((test_name, base_score))
    
    # Sort theo score (descending)
    test_scores.sort(key=lambda x: x[1], reverse=True)
    
    return [test[0] for test in test_scores]
```

#### 9.2.2 Risk Scoring Algorithm
```python
class RiskScoring:
    def __init__(self):
        self.severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        self.impact_multipliers = {
            'authentication_bypass': 2.0,
            'remote_code_execution': 2.5,
            'data_exposure': 1.8,
            'denial_of_service': 1.2,
            'information_disclosure': 1.0
        }
    
    def calculate_device_risk_score(self, device, test_results):
        """
        Tính risk score cho device dựa trên test results
        """
        total_score = 0.0
        max_possible_score = 0.0
        
        for result in test_results:
            if result.status == 'fail':
                # Base score từ severity
                base_score = self.severity_weights.get(result.severity, 5.0)
                
                # Impact multiplier
                impact_type = self.determine_impact_type(result)
                impact_multiplier = self.impact_multipliers.get(impact_type, 1.0)
                
                # Device type modifier
                device_modifier = self.get_device_type_modifier(device, result)
                
                # Environment modifier (network exposure)
                env_modifier = self.get_environment_modifier(device)
                
                # Final score calculation
                result_score = base_score * impact_multiplier * device_modifier * env_modifier
                total_score += result_score
            
            # Track maximum possible score for normalization
            max_possible_score += 10.0
        
        # Normalize to 0-10 scale
        if max_possible_score > 0:
            normalized_score = (total_score / max_possible_score) * 10.0
        else:
            normalized_score = 0.0
        
        return min(normalized_score, 10.0)
    
    def determine_impact_type(self, test_result):
        """
        Xác định loại impact của vulnerability
        """
        test_name = test_result.test_name.lower()
        
        if 'credential' in test_name or 'auth' in test_name:
            return 'authentication_bypass'
        elif 'rce' in test_name or 'code_execution' in test_name:
            return 'remote_code_execution'
        elif 'data' in test_name or 'leak' in test_name:
            return 'data_exposure'
        elif 'dos' in test_name or 'denial' in test_name:
            return 'denial_of_service'
        else:
            return 'information_disclosure'
    
    def get_device_type_modifier(self, device, test_result):
        """
        Device type có ảnh hưởng khác nhau đến risk
        """
        device_type = device.classification.get('device_type', 'unknown')
        
        modifiers = {
            'camera': 1.5,      # High privacy impact
            'door_lock': 1.8,   # Physical security impact
            'router': 1.6,      # Network infrastructure impact
            'sensor': 1.2,      # Data collection impact
            'smart_tv': 1.1,    # Limited impact
            'unknown': 1.0      # Default
        }
        
        return modifiers.get(device_type, 1.0)
    
    def get_environment_modifier(self, device):
        """
        Network environment ảnh hưởng đến risk exposure
        """
        # Check if device is internet-facing
        if self.is_internet_facing(device):
            return 1.5
        
        # Check network segment
        if self.is_dmz_network(device.ip_address):
            return 1.3
        elif self.is_internal_network(device.ip_address):
            return 1.0
        else:
            return 1.1
    
    def generate_risk_recommendations(self, device, risk_score):
        """
        Tạo recommendations dựa trên risk score
        """
        recommendations = []
        
        if risk_score >= 8.0:
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: This device poses critical security risks",
                "Disconnect device from network until vulnerabilities are addressed",
                "Contact vendor for emergency security patches",
                "Implement network segmentation to isolate device"
            ])
        elif risk_score >= 6.0:
            recommendations.extend([
                "HIGH PRIORITY: Address vulnerabilities within 48 hours",
                "Update firmware to latest version",
                "Change default credentials",
                "Enable all available security features"
            ])
        elif risk_score >= 4.0:
            recommendations.extend([
                "MEDIUM PRIORITY: Schedule security updates within 1 week",
                "Review device configuration settings",
                "Monitor device behavior for anomalies",
                "Consider additional network security controls"
            ])
        else:
            recommendations.extend([
                "LOW PRIORITY: Follow standard security practices",
                "Regular security updates and monitoring",
                "Periodic security assessments"
            ])
        
        return recommendations
```

### 9.3 Report Generation Algorithm

#### 9.3.1 Intelligent Report Composition
```python
class ReportGenerator:
    def __init__(self, template_engine, data_processor):
        self.template_engine = template_engine
        self.data_processor = data_processor
        
    def generate_adaptive_report(self, assessment_data, audience_type):
        """
        Generate report phù hợp với audience
        """
        # Determine report structure dựa trên audience
        if audience_type == 'executive':
            return self.generate_executive_report(assessment_data)
        elif audience_type == 'technical':
            return self.generate_technical_report(assessment_data)
        elif audience_type == 'compliance':
            return self.generate_compliance_report(assessment_data)
        else:
            return self.generate_comprehensive_report(assessment_data)
    
    def generate_executive_report(self, assessment_data):
        """
        Executive summary focus on business impact
        """
        report_sections = [
            self.create_executive_summary(assessment_data),
            self.create_risk_overview(assessment_data),
            self.create_business_impact_analysis(assessment_data),
            self.create_strategic_recommendations(assessment_data)
        ]
        
        return self.template_engine.render('executive_template', {
            'sections': report_sections,
            'charts': self.generate_executive_charts(assessment_data),
            'kpis': self.calculate_security_kpis(assessment_data)
        })
    
    def create_business_impact_analysis(self, assessment_data):
        """
        Analyze business impact của security findings
        """
        impact_analysis = {
            'financial_risk': 0,
            'operational_risk': 0,
            'reputation_risk': 0,
            'compliance_risk': 0
        }
        
        for device_result in assessment_data['devices']:
            device_type = device_result['classification']['device_type']
            risk_score = device_result['risk_score']
            
            # Financial impact calculation
            if device_type in ['camera', 'door_lock']:
                impact_analysis['financial_risk'] += risk_score * 0.3
            
            # Operational impact
            if device_type in ['router', 'gateway']:
                impact_analysis['operational_risk'] += risk_score * 0.4
            
            # Reputation risk (data privacy devices)
            if device_type in ['camera', 'microphone', 'sensor']:
                impact_analysis['reputation_risk'] += risk_score * 0.2
        
        # Normalize scores
        max_devices = len(assessment_data['devices'])
        for risk_type in impact_analysis:
            impact_analysis[risk_type] = min(
                impact_analysis[risk_type] / max_devices, 
                10.0
            )
        
        return {
            'title': 'Business Impact Analysis',
            'content': impact_analysis,
            'recommendations': self.generate_business_recommendations(impact_analysis)
        }

    def generate_technical_report(self, assessment_data):
        """
        Detailed technical report for IT teams
        """
        report_sections = [
            self.create_assessment_overview(assessment_data),
            self.create_detailed_findings(assessment_data),
            self.create_technical_evidence(assessment_data),
            self.create_remediation_guide(assessment_data),
            self.create_technical_appendix(assessment_data)
        ]
        
        return self.template_engine.render('technical_template', {
            'sections': report_sections,
            'network_diagrams': self.generate_network_diagrams(assessment_data),
            'vulnerability_details': self.extract_vulnerability_details(assessment_data)
        })
```

## 10. KẾT LUẬN

### 10.1 Tổng kết chương II

Chương II đã trình bày chi tiết về phân tích và thiết kế hệ thống IoT Security Framework, bao gồm:

**Phân tích hệ thống hoàn chỉnh:**
- Sơ đồ khối chức năng với 4 layers rõ ràng
- Định nghĩa 4 nhóm actors chính với vai trò cụ thể  
- 15+ use cases chi tiết với scenarios thực tế
- 3 kịch bản đầy đủ từ penetration testing đến enterprise monitoring

**Thiết kế kỹ thuật chi tiết:**
- Class diagram với 10+ core classes và relationships
- 3 sequence diagrams cho main workflows
- Database schema với 7 tables và đầy đủ constraints
- Comprehensive UI/UX design cho web và mobile interfaces

**Algorithms thông minh:**
- Intelligent network discovery với adaptive scanning
- Multi-stage device classification (signature + heuristic + ML)
- Advanced risk scoring với business impact analysis
- Adaptive report generation cho different audiences

### 10.2 Điểm mạnh của thiết kế

**Tính mở rộng cao:**
- Plugin architecture cho custom tests
- Flexible database schema hỗ trợ new device types
- RESTful API design cho integration
- Containerized deployment

**User experience tối ưu:**
- Intuitive web interface với real-time updates
- Mobile-friendly responsive design  
- Role-based access control
- Multiple report formats và templates

**Technical excellence:**
- Intelligent algorithms giảm false positives
- Parallel processing cho performance
- Comprehensive error handling
- Security-first approach trong design

### 10.3 Khả năng thực hiện

Thiết kế đã được optimize cho tính khả thi trong môi trường đồ án tốt nghiệp:

**Technology stack proven:**
- Python ecosystem mature với rich security libraries
- SQLite database không cần complex setup
- Flask framework lightweight và well-documented
- Docker containerization đơn giản deployment

**Scope manageable:**
- Focus vào Smart Home devices (limited scope)
- MVP approach với core features first
- Incremental development strategy
- Clear milestones và deliverables

**Resource requirements realistic:**
- Single developer có thể handle
- $500 budget đủ cho development và testing
- 6-month timeline phù hợp với thesis schedule
- Community support available cho open-source tools

---

# CHƯƠNG III: CÀI ĐẶT, THỬ NGHIỆM, TRIỂN KHAI

## 1. SƠ ĐỒ MÔ HÌNH TRIỂN KHAI

### 1.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │   Web Browser   │    │   Mobile App    │    │   CLI Tool  │  │
│  │                 │    │                 │    │             │  │
│  └─────────┬───────┘    └─────────┬───────┘    └──────┬──────┘  │
│            │                      │                   │         │
│            └──────────────────────┼───────────────────┘         │
│                                   │                             │
├─────────────────────────────────────────────────────────────────┤
│                          LOAD BALANCER                          │
│                         (Nginx/HAProxy)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │  Web Server 1   │    │  Web Server 2   │    │ API Gateway │  │
│  │   (Flask App)   │    │   (Flask App)   │    │  (Optional) │  │
│  │                 │    │                 │    │             │  │
│  └─────────┬───────┘    └─────────┬───────┘    └──────┬──────┘  │
│            │                      │                   │         │
│            └──────────────────────┼───────────────────┘         │
│                                   │                             │
├─────────────────────────────────────────────────────────────────┤
│                       BUSINESS LOGIC TIER                       │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │ Discovery       │    │ Assessment      │    │ Reporting   │  │
│  │ Service         │    │ Engine          │    │ Service     │  │
│  │                 │    │                 │    │             │  │
│  └─────────┬───────┘    └─────────┬───────┘    └──────┬──────┘  │
│            │                      │                   │         │
│            └──────────────────────┼───────────────────┘         │
│                                   │                             │
├─────────────────────────────────────────────────────────────────┤
│                       MESSAGE QUEUE                             │
│                    (Redis/RabbitMQ)                            │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │ Scan Workers    │    │ Test Workers    │    │Report Worker│  │
│  │ (Celery)        │    │ (Celery)        │    │ (Celery)    │  │
│  │                 │    │                 │    │             │  │
│  └─────────────────┘    └─────────────────┘    └─────────────┘  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                        DATA TIER                                │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │ Main Database   │    │   File Storage  │    │   Cache     │  │
│  │ (PostgreSQL/    │    │   (MinIO/S3)    │    │  (Redis)    │  │
│  │  SQLite)        │    │                 │    │             │  │
│  └─────────────────┘    └─────────────────┘    └─────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Container Architecture (Docker)

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Web Application
  web:
    build: 
      context: .
      dockerfile: Dockerfile
    image: iot-security-framework:latest
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/iot_security
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
      - ./reports:/app/reports
    restart: unless-stopped
    networks:
      - iot-security-net

  # Background Workers
  worker:
    build: 
      context: .
      dockerfile: Dockerfile
    command: celery worker -A app.celery --loglevel=info
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/iot_security
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    networks:
      - iot-security-net

  # Task Scheduler
  scheduler:
    build: 
      context: .
      dockerfile: Dockerfile
    command: celery beat -A app.celery --loglevel=info
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/iot_security
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    networks:
      - iot-security-net

  # Database
  db:
    image: postgres:13-alpine
    environment:
      - POSTGRES_DB=iot_security
      - POSTGRES_USER=iot_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    networks:
      - iot-security-net

  # Redis (Message Broker & Cache)
  redis:
    image: redis:6-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    restart: unless-stopped
    networks:
      - iot-security-net

  # Nginx (Load Balancer)
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    depends_on:
      - web
    restart: unless-stopped
    networks:
      - iot-security-net

volumes:
  postgres_data:
  redis_data:

networks:
  iot-security-net:
    driver: bridge
```

### 1.3 Cloud Deployment Architecture

#### 1.3.1 AWS Deployment
```
┌─────────────────────────────────────────────────────────────────┐
│                          AWS CLOUD                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    INTERNET GATEWAY                         │ │
│  └─────────────────────┬───────────────────────────────────────┘ │
│                        │                                         │
│  ┌─────────────────────▼───────────────────────────────────────┐ │
│  │              APPLICATION LOAD BALANCER                      │ │
│  │                    (ALB)                                    │ │
│  └─────────────────────┬───────────────────────────────────────┘ │
│                        │                                         │
│  ┌─────────────────────▼───────────────────────────────────────┐ │
│  │                  AVAILABILITY ZONES                         │ │
│  │                                                             │ │
│  │  AZ-1a                          AZ-1b                      │ │
│  │  ┌─────────────────┐             ┌─────────────────┐       │ │
│  │  │   ECS Service   │             │   ECS Service   │       │ │
│  │  │  ┌───────────┐  │             │  ┌───────────┐  │       │ │
│  │  │  │Flask App 1│  │             │  │Flask App 2│  │       │ │
│  │  │  └───────────┘  │             │  └───────────┘  │       │ │
│  │  │  ┌───────────┐  │             │  ┌───────────┐  │       │ │
│  │  │  │ Worker 1  │  │             │  │ Worker 2  │  │       │ │
│  │  │  └───────────┘  │             │  └───────────┘  │       │ │
│  │  └─────────────────┘             └─────────────────┘       │ │
│  └─────────────────────┬───────────────────┬───────────────────┘ │
│                        │                   │                     │
│  ┌─────────────────────▼───────────────────▼───────────────────┐ │
│  │                    RDS CLUSTER                              │ │
│  │                  (PostgreSQL)                              │ │
│  │  ┌─────────────────┐             ┌─────────────────┐       │ │
│  │  │   Primary DB    │             │   Read Replica  │       │ │
│  │  │    (AZ-1a)      │             │     (AZ-1b)     │       │ │
│  │  └─────────────────┘             └─────────────────┘       │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                 ELASTICACHE REDIS                           │ │
│  │  ┌─────────────────┐             ┌─────────────────┐       │ │
│  │  │   Redis Node    │             │   Redis Node    │       │ │
│  │  │    (AZ-1a)      │             │     (AZ-1b)     │       │ │
│  │  └─────────────────┘             └─────────────────┘       │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                      S3 BUCKET                              │ │
│  │              (Reports & Static Files)                      │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 2. MÔ HÌNH TRIỂN KHAI

### 2.1 Development Environment

#### 2.1.1 Local Development Setup
```bash
# Development environment setup
git clone https://github.com/username/iot-security-framework.git
cd iot-security-framework

# Virtual environment setup
python3.9 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements-dev.txt

# Environment configuration
cp .env.example .env
# Edit .env file with local settings

# Database initialization
python manage.py db init
python manage.py db migrate
python manage.py db upgrade

# Load sample data
python manage.py load-sample-data

# Start development server
python app.py
```

#### 2.1.2 Development Directory Structure
```
iot-security-framework/
├── app/
│   ├── __init__.py
│   ├── models/
│   │   ├── device.py
│   │   ├── assessment.py
│   │   └── user.py
│   ├── api/
│   │   ├── devices.py
│   │   ├── assessments.py
│   │   └── reports.py
│   ├── core/
│   │   ├── discovery/
│   │   │   ├── network_scanner.py
│   │   │   └── device_classifier.py
│   │   ├── assessment/
│   │   │   ├── vulnerability_scanner.py
│   │   │   └── test_executor.py
│   │   └── reporting/
│   │       ├── report_generator.py
│   │       └── templates/
│   ├── web/
│   │   ├── dashboard.py
│   │   ├── devices.py
│   │   └── reports.py
│   └── utils/
│       ├── config.py
│       ├── database.py
│       └── security.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/
├── scripts/
├── requirements.txt
├── requirements-dev.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── manage.py
```

### 2.2 Testing Environment

#### 2.2.1 Test Infrastructure Setup
```python
# conftest.py - Pytest configuration
import pytest
import tempfile
import os
from app import create_app, db
from app.models import User, Device, Assessment

@pytest.fixture(scope='session')
def test_app():
    """Create application for testing"""
    db_fd, db_path = tempfile.mkstemp()
    
    config = {
        'TESTING': True,
        'DATABASE_URL': f'sqlite:///{db_path}',
        'SECRET_KEY': 'test-key-12345'
    }
    
    app = create_app(config)
    
    with app.app_context():
        db.create_all()
        yield app
    
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(test_app):
    """Test client"""
    return test_app.test_client()

@pytest.fixture
def auth_headers(client):
    """Authentication headers for API testing"""
    # Create test user
    response = client.post('/api/auth/register', json={
        'username': 'testuser',
        'password': 'testpass123',
        'email': 'test@example.com'
    })
    
    # Login and get token
    response = client.post('/api/auth/login', json={
        'username': 'testuser',
        'password': 'testpass123'
    })
    
    token = response.json['access_token']
    return {'Authorization': f'Bearer {token}'}
```

#### 2.2.2 Test Lab Network Setup
```python
# test_lab_config.py
TEST_LAB_CONFIG = {
    'network_range': '192.168.100.0/24',
    'test_devices': [
        {
            'ip': '192.168.100.10',
            'type': 'smart_camera',
            'manufacturer': 'Hikvision',
            'model': 'DS-2CD2042WD-I',
            'vulnerabilities': ['default_credentials', 'weak_encryption']
        },
        {
            'ip': '192.168.100.11',
            'type': 'door_lock',
            'manufacturer': 'Yale',
            'model': 'YRD256',
            'vulnerabilities': ['protocol_weakness']
        },
        {
            'ip': '192.168.100.12',
            'type': 'sensor',
            'manufacturer': 'Xiaomi',
            'model': 'MCCGQ02HL',
            'vulnerabilities': []
        }
    ],
    'mock_services': {
        'http_server': 'http://192.168.100.10:80',
        'mqtt_broker': 'mqtt://192.168.100.50:1883',
        'coap_server': 'coap://192.168.100.51:5683'
    }
}

class TestLabManager:
    """Manage test lab environment"""
    
    def __init__(self):
        self.docker_client = docker.from_env()
        self.containers = {}
    
    def setup_test_lab(self):
        """Setup mock IoT devices using containers"""
        
        # Mock smart camera
        camera_container = self.docker_client.containers.run(
            'mock-iot-camera:latest',
            detach=True,
            ports={'80/tcp': ('192.168.100.10', 80)},
            environment={
                'DEVICE_TYPE': 'camera',
                'VULNERABILITIES': 'default_creds,weak_encryption'
            },
            name='test_camera'
        )
        self.containers['camera'] = camera_container
        
        # Mock MQTT broker
        mqtt_container = self.docker_client.containers.run(
            'eclipse-mosquitto:latest',
            detach=True,
            ports={'1883/tcp': ('192.168.100.50', 1883)},
            name='test_mqtt'
        )
        self.containers['mqtt'] = mqtt_container
        
        # Wait for services to start
        time.sleep(10)
    
    def teardown_test_lab(self):
        """Clean up test environment"""
        for container in self.containers.values():
            container.stop()
            container.remove()
```

### 2.3 Staging Environment

#### 2.3.1 Staging Deployment Configuration
```yaml
# staging-docker-compose.yml
version: '3.8'

services:
  web:
    image: iot-security-framework:staging
    environment:
      - FLASK_ENV=staging
      - DATABASE_URL=postgresql://staging_user:${STAGING_DB_PASSWORD}@staging-db:5432/iot_security_staging
      - REDIS_URL=redis://staging-redis:6379/0
      - LOG_LEVEL=DEBUG
    ports:
      - "8080:5000"
    depends_on:
      - staging-db
      - staging-redis
    volumes:
      - staging_logs:/app/logs
      - staging_reports:/app/reports

  staging-db:
    image: postgres:13-alpine
    environment:
      - POSTGRES_DB=iot_security_staging
      - POSTGRES_USER=staging_user
      - POSTGRES_PASSWORD=${STAGING_DB_PASSWORD}
    volumes:
      - staging_postgres_data:/var/lib/postgresql/data

  staging-redis:
    image: redis:6-alpine
    volumes:
      - staging_redis_data:/data

volumes:
  staging_postgres_data:
  staging_redis_data:
  staging_logs:
  staging_reports:
```

### 2.4 Production Environment

#### 2.4.1 Production Security Configuration
```python
# production_config.py
import os
from datetime import timedelta

class ProductionConfig:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL')
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 20,
        'max_overflow': 0
    }
    
    # Redis
    REDIS_URL = os.environ.get('REDIS_URL')
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    }
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s: %(message)s'
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = REDIS_URL
    RATELIMIT_DEFAULT = "1000 per hour"
    
    # File Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = '/app/uploads'
```

#### 2.4.2 Production Monitoring Setup
```python
# monitoring.py
import logging
import time
from prometheus_client import Counter, Histogram, Gauge, start_http_server
from functools import wraps

# Metrics
scan_requests_total = Counter('scan_requests_total', 'Total scan requests', ['method', 'endpoint'])
scan_duration_seconds = Histogram('scan_duration_seconds', 'Scan duration')
active_scans = Gauge('active_scans', 'Number of active scans')
devices_discovered = Counter('devices_discovered_total', 'Total devices discovered')

def monitor_scan_performance(f):
    """Decorator to monitor scan performance"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        active_scans.inc()
        
        try:
            result = f(*args, **kwargs)
            scan_requests_total.labels(method='success', endpoint=f.__name__).inc()
            return result
        except Exception as e:
            scan_requests_total.labels(method='error', endpoint=f.__name__).inc()
            raise
        finally:
            duration = time.time() - start_time
            scan_duration_seconds.observe(duration)
            active_scans.dec()
    
    return decorated_function

class HealthChecker:
    """Application health monitoring"""
    
    def __init__(self, app, db, redis_client):
        self.app = app
        self.db = db
        self.redis_client = redis_client
    
    def check_database_health(self):
        """Check database connectivity"""
        try:
            self.db.session.execute('SELECT 1')
            return {'status': 'healthy', 'response_time_ms': 0}
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}
    
    def check_redis_health(self):
        """Check Redis connectivity"""
        try:
            start_time = time.time()
            self.redis_client.ping()
            response_time = (time.time() - start_time) * 1000
            return {'status': 'healthy', 'response_time_ms': response_time}
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}
    
    def get_system_health(self):
        """Get overall system health"""
        db_health = self.check_database_health()
        redis_health = self.check_redis_health()
        
        overall_status = 'healthy'
        if db_health['status'] == 'unhealthy' or redis_health['status'] == 'unhealthy':
            overall_status = 'unhealthy'
        
        return {
            'status': overall_status,
            'timestamp': time.time(),
            'components': {
                'database': db_health,
                'redis': redis_health
            }
        }
```

## 3. TRIỂN KHAI THỰC TẾ

### 3.1 Implementation Phases

#### 3.1.1 Phase 1: Core Infrastructure (Tháng 1-2)

**Sprint 1.1: Project Setup & Basic Infrastructure**
```bash
# Week 1-2: Project initialization
- Setup development environment
- Initialize Git repository with branching strategy
- Create basic Flask application structure
- Setup database models và migrations
- Implement basic authentication system
- Create CI/CD pipeline với GitHub Actions
```

**Sprint 1.2: Network Discovery Module**
```python
# Week 3-4: Network scanning capabilities
class NetworkScanner:
    def __init__(self):
        self.nmap = nmap.PortScanner()
        
    def scan_network(self, network_range, scan_type='quick'):
        """
        Implementation priorities:
        1. Basic ping sweep
        2. Port scanning cho common IoT ports
        3. Service enumeration
        4. Protocol detection
        """
        # Implementation details...

# Deliverables:
- Basic network scanning functionality
- Device discovery and enumeration
- Simple web interface for initiating scans
- Unit tests for core scanning logic
```

**Sprint 1.3: Database Design & API Foundation**
```sql
-- Week 5-6: Database và API implementation
-- Implement core database tables
-- Create RESTful API endpoints
-- Add data validation và error handling
-- Implement basic security measures

-- Key deliverables:
- Complete database schema implementation
- CRUD operations for devices, assessments
- RESTful API với proper HTTP status codes
- API documentation với Swagger
```

**Sprint 1.4: Basic Web Interface**
```html
<!-- Week 7-8: Frontend development -->
<!-- Create responsive web interface -->
<!-- Implement dashboard với device list -->
<!-- Add scan initiation functionality -->
<!-- Basic reporting interface -->

Deliverables:
- Responsive web dashboard
- Device management interface
- Scan progress visualization
- Basic user authentication UI
```

#### 3.1.2 Phase 2: Security Assessment Engine (Tháng 3-4)

**Sprint 2.1: Device Classification System**
```python
# Week 9-10: Smart device classification
class DeviceClassifier:
    def __init__(self):
        self.signature_db = self.load_signatures()
        
    def classify_device(self, device_info):
        """
        Multi-stage classification:
        1. Signature matching
        2. Heuristic analysis  
        3. Protocol-based classification
        """
        # Implementation priorities:
        - Create device signature database
        - Implement pattern matching algorithms
        - Add manufacturer detection
        - Model/firmware identification

# Deliverables:
- Device classification engine
- Signature database với 100+ device types
- Classification confidence scoring
- Manual classification override capability
```

**Sprint 2.2: Vulnerability Assessment Framework**
```python
# Week 11-12: Security testing implementation
class VulnerabilityScanner:
    def __init__(self):
        self.test_modules = self.load_test_modules()
        
    def assess_device(self, device, test_suite):
        """
        Automated vulnerability assessment:
        1. Default credential testing
        2. Common IoT vulnerability checks
        3. Protocol-specific security tests
        4. Web interface security assessment
        """
        
# Implementation focus:
- Default credential database và testing
- Common IoT vulnerability patterns
- HTTP/HTTPS security assessment
- MQTT/CoAP protocol testing
- Custom payload injection capabilities

# Deliverables:
- Vulnerability assessment engine
- 20+ security test modules
- Risk scoring algorithm
- Evidence collection system
```

**Sprint 2.3: Reporting System**
```python
# Week 13-14: Report generation
class ReportGenerator:
    def generate_report(self, assessment_data, report_type):
        """
        Multi-format reporting:
        1. Executive summary
        2. Technical details
        3. Remediation guidance
        4. Export capabilities (PDF, HTML, JSON)
        """

# Implementation priorities:
- HTML report templates
- PDF generation capability
- Executive vs technical report variants
- Customizable report sections
- Automated remediation recommendations

# Deliverables:
- Comprehensive reporting system
- Multiple report formats
- Customizable templates
- Automated report generation
```

**Sprint 2.4: Background Task Processing**
```python
# Week 15-16: Asynchronous processing
# Implement Celery task queue
# Background scan processing
# Real-time progress updates
# Task scheduling capabilities

# Key features:
- Long-running scan operations
- Progress tracking và notifications
- Scheduled assessments
- Task retry mechanisms
- Resource usage monitoring

# Deliverables:
- Asynchronous task processing system
- Real-time scan progress updates
- Scheduled assessment capability
- Background job monitoring
```

#### 3.1.3 Phase 3: Advanced Features & Polish (Tháng 5-6)

**Sprint 3.1: Advanced Security Features**
```python
# Week 17-18: Enhanced security capabilities
# Advanced authentication (2FA)
# Role-based access control
# API security hardening
# Audit logging system

# Security enhancements:
- Multi-factor authentication
- JWT token management
- Rate limiting
- Input validation và sanitization
- Security headers implementation

# Deliverables:
- Production-ready security features
- Comprehensive audit logging
- Role-based permission system
- Security vulnerability assessment of framework itself
```

**Sprint 3.2: Performance Optimization**
```python
# Week 19-20: Performance tuning
# Database query optimization
# Caching implementation
# Concurrent scan processing
# Memory usage optimization

# Performance targets:
- <5 minute network scan for /24 subnet
- <2 second web page load times
- Support 50+ concurrent device assessments
- <2GB memory usage for typical workload

# Deliverables: 