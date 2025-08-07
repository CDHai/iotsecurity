"""
Device model for IoT device management and tracking
"""

import json
from datetime import datetime
from sqlalchemy import text
from app import db

class Device(db.Model):
    """Model representing an IoT device discovered on the network."""
    
    __tablename__ = 'devices'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Network identification
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # Support IPv6
    mac_address = db.Column(db.String(17), nullable=True, index=True)
    hostname = db.Column(db.String(255), nullable=True)
    
    # Device classification
    manufacturer = db.Column(db.String(100), nullable=True)
    device_type = db.Column(db.String(50), nullable=True, index=True)
    model = db.Column(db.String(100), nullable=True)
    firmware_version = db.Column(db.String(50), nullable=True)
    
    # Network information
    open_ports = db.Column(db.Text, nullable=True)  # JSON array of open ports
    protocols = db.Column(db.Text, nullable=True)   # JSON array of supported protocols
    services = db.Column(db.Text, nullable=True)    # JSON object of detected services
    
    # Classification confidence and status
    confidence_score = db.Column(db.Float, default=0.0)
    is_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Security status
    risk_level = db.Column(db.Enum('unknown', 'low', 'medium', 'high', 'critical', 
                                  name='risk_levels'), default='unknown')
    vulnerability_count = db.Column(db.Integer, default=0)
    last_assessment = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Additional metadata
    notes = db.Column(db.Text, nullable=True)
    tags = db.Column(db.Text, nullable=True)  # JSON array of tags
    
    # Relationships
    assessments = db.relationship('Assessment', backref='device', lazy='dynamic',
                                 cascade='all, delete-orphan')
    
    def __init__(self, ip_address, **kwargs):
        """Initialize device with IP address."""
        self.ip_address = ip_address
        
        # Set additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @property
    def open_ports_list(self):
        """Get open ports as Python list."""
        if self.open_ports:
            try:
                return json.loads(self.open_ports)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @open_ports_list.setter
    def open_ports_list(self, ports):
        """Set open ports from Python list."""
        if isinstance(ports, list):
            self.open_ports = json.dumps(ports)
        else:
            self.open_ports = None
    
    @property
    def protocols_list(self):
        """Get protocols as Python list."""
        if self.protocols:
            try:
                return json.loads(self.protocols)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @protocols_list.setter
    def protocols_list(self, protocols):
        """Set protocols from Python list."""
        if isinstance(protocols, list):
            self.protocols = json.dumps(protocols)
        else:
            self.protocols = None
    
    @property
    def services_dict(self):
        """Get services as Python dictionary."""
        if self.services:
            try:
                return json.loads(self.services)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    @services_dict.setter
    def services_dict(self, services):
        """Set services from Python dictionary."""
        if isinstance(services, dict):
            self.services = json.dumps(services)
        else:
            self.services = None
    
    @property
    def tags_list(self):
        """Get tags as Python list."""
        if self.tags:
            try:
                return json.loads(self.tags)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @tags_list.setter
    def tags_list(self, tags):
        """Set tags from Python list."""
        if isinstance(tags, list):
            self.tags = json.dumps(tags)
        else:
            self.tags = None
    
    def update_last_seen(self):
        """Update last seen timestamp."""
        self.last_seen = datetime.utcnow()
        self.is_active = True
        db.session.commit()
    
    def mark_inactive(self):
        """Mark device as inactive."""
        self.is_active = False
        db.session.commit()
    
    def update_risk_level(self):
        """Update risk level based on vulnerability count and assessments."""
        if self.vulnerability_count == 0:
            self.risk_level = 'low'
        elif self.vulnerability_count <= 2:
            self.risk_level = 'medium'
        elif self.vulnerability_count <= 5:
            self.risk_level = 'high'
        else:
            self.risk_level = 'critical'
        
        db.session.commit()
    
    def add_tag(self, tag):
        """Add a tag to the device."""
        current_tags = self.tags_list
        if tag not in current_tags:
            current_tags.append(tag)
            self.tags_list = current_tags
            db.session.commit()
    
    def remove_tag(self, tag):
        """Remove a tag from the device."""
        current_tags = self.tags_list
        if tag in current_tags:
            current_tags.remove(tag)
            self.tags_list = current_tags
            db.session.commit()
    
    def to_dict(self, include_relationships=False):
        """Convert device to dictionary representation."""
        data = {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'manufacturer': self.manufacturer,
            'device_type': self.device_type,
            'model': self.model,
            'firmware_version': self.firmware_version,
            'open_ports': self.open_ports_list,
            'protocols': self.protocols_list,
            'services': self.services_dict,
            'confidence_score': self.confidence_score,
            'is_verified': self.is_verified,
            'is_active': self.is_active,
            'risk_level': self.risk_level,
            'vulnerability_count': self.vulnerability_count,
            'last_assessment': self.last_assessment.isoformat() if self.last_assessment else None,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'notes': self.notes,
            'tags': self.tags_list
        }
        
        if include_relationships:
            data['assessments'] = [assessment.to_dict() for assessment in self.assessments]
        
        return data
    
    @classmethod
    def find_by_ip(cls, ip_address):
        """Find device by IP address."""
        return cls.query.filter_by(ip_address=ip_address).first()
    
    @classmethod
    def find_by_mac(cls, mac_address):
        """Find device by MAC address."""
        return cls.query.filter_by(mac_address=mac_address).first()
    
    @classmethod
    def get_active_devices(cls):
        """Get all active devices."""
        return cls.query.filter_by(is_active=True).all()
    
    @classmethod
    def get_devices_by_type(cls, device_type):
        """Get devices by type."""
        return cls.query.filter_by(device_type=device_type).all()
    
    @classmethod
    def get_high_risk_devices(cls):
        """Get devices with high or critical risk level."""
        return cls.query.filter(cls.risk_level.in_(['high', 'critical'])).all()
    
    @classmethod
    def search_devices(cls, query):
        """Search devices by IP, hostname, manufacturer, or model."""
        search_pattern = f'%{query}%'
        return cls.query.filter(
            db.or_(
                cls.ip_address.like(search_pattern),
                cls.hostname.like(search_pattern),
                cls.manufacturer.like(search_pattern),
                cls.model.like(search_pattern)
            )
        ).all()
    
    def __repr__(self):
        return f'<Device {self.ip_address} ({self.device_type})>'
