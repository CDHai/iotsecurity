from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import enum

db = SQLAlchemy()

class DeviceType(enum.Enum):
    """Device types enumeration"""
    CAMERA = 'camera'
    DOOR_LOCK = 'door_lock'
    SENSOR = 'sensor'
    ROUTER = 'router'
    SMART_PLUG = 'smart_plug'
    THERMOSTAT = 'thermostat'
    SMART_TV = 'smart_tv'
    SMART_HUB = 'smart_hub'
    UNKNOWN = 'unknown'

class DeviceStatus(enum.Enum):
    """Device status enumeration"""
    ONLINE = 'online'
    OFFLINE = 'offline'
    UNKNOWN = 'unknown'

class Device(db.Model):
    """IoT Device model"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    mac_address = db.Column(db.String(17), nullable=True, index=True)
    hostname = db.Column(db.String(255), nullable=True)
    
    # Device classification
    manufacturer = db.Column(db.String(100), nullable=True, index=True)
    device_type = db.Column(db.Enum(DeviceType), default=DeviceType.UNKNOWN, nullable=False)
    model = db.Column(db.String(100), nullable=True)
    firmware_version = db.Column(db.String(50), nullable=True)
    
    # Network information
    open_ports = db.Column(db.Text, nullable=True)  # JSON array
    protocols = db.Column(db.Text, nullable=True)   # JSON array
    services = db.Column(db.Text, nullable=True)    # JSON object
    
    # Device fingerprint
    fingerprint = db.Column(db.Text, nullable=True)  # JSON object
    confidence_score = db.Column(db.Float, default=0.0)
    
    # Status and timestamps
    status = db.Column(db.Enum(DeviceStatus), default=DeviceStatus.UNKNOWN, nullable=False)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_scan = db.Column(db.DateTime, nullable=True)
    
    # Risk assessment
    risk_score = db.Column(db.Float, default=0.0)
    last_assessment = db.Column(db.DateTime, nullable=True)
    
    # Additional information
    notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    assessments = db.relationship('Assessment', backref='device', lazy='dynamic')
    
    def __init__(self, ip_address, mac_address=None, hostname=None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.hostname = hostname
    
    @property
    def open_ports_list(self):
        """Get open ports as list"""
        if self.open_ports:
            return json.loads(self.open_ports)
        return []
    
    @open_ports_list.setter
    def open_ports_list(self, ports):
        """Set open ports from list"""
        self.open_ports = json.dumps(ports) if ports else None
    
    @property
    def protocols_list(self):
        """Get protocols as list"""
        if self.protocols:
            return json.loads(self.protocols)
        return []
    
    @protocols_list.setter
    def protocols_list(self, protocols):
        """Set protocols from list"""
        self.protocols = json.dumps(protocols) if protocols else None
    
    @property
    def services_dict(self):
        """Get services as dictionary"""
        if self.services:
            return json.loads(self.services)
        return {}
    
    @services_dict.setter
    def services_dict(self, services):
        """Set services from dictionary"""
        self.services = json.dumps(services) if services else None
    
    @property
    def fingerprint_dict(self):
        """Get fingerprint as dictionary"""
        if self.fingerprint:
            return json.loads(self.fingerprint)
        return {}
    
    @fingerprint_dict.setter
    def fingerprint_dict(self, fingerprint):
        """Set fingerprint from dictionary"""
        self.fingerprint = json.dumps(fingerprint) if fingerprint else None
    
    def update_last_seen(self):
        """Update last seen timestamp"""
        self.last_seen = datetime.utcnow()
        db.session.commit()
    
    def update_status(self, status):
        """Update device status"""
        self.status = status
        self.update_last_seen()
    
    def update_risk_score(self, score):
        """Update risk score"""
        self.risk_score = max(0.0, min(10.0, score))
        self.last_assessment = datetime.utcnow()
        db.session.commit()
    
    def get_device_info(self):
        """Get comprehensive device information"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'manufacturer': self.manufacturer,
            'device_type': self.device_type.value if self.device_type else None,
            'model': self.model,
            'firmware_version': self.firmware_version,
            'open_ports': self.open_ports_list,
            'protocols': self.protocols_list,
            'services': self.services_dict,
            'fingerprint': self.fingerprint_dict,
            'confidence_score': self.confidence_score,
            'status': self.status.value if self.status else None,
            'risk_score': self.risk_score,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'last_assessment': self.last_assessment.isoformat() if self.last_assessment else None
        }
    
    def is_online(self):
        """Check if device is online"""
        return self.status == DeviceStatus.ONLINE
    
    def has_vulnerabilities(self):
        """Check if device has vulnerabilities (risk score > 5.0)"""
        return self.risk_score > 5.0
    
    def get_risk_level(self):
        """Get risk level based on score"""
        if self.risk_score >= 8.0:
            return 'critical'
        elif self.risk_score >= 6.0:
            return 'high'
        elif self.risk_score >= 4.0:
            return 'medium'
        elif self.risk_score >= 2.0:
            return 'low'
        else:
            return 'safe'
    
    def __repr__(self):
        return f'<Device {self.ip_address} ({self.device_type.value})>'
