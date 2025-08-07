"""
Helper utility functions
"""

import re
import ipaddress
import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range in CIDR notation."""
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format."""
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac))

def normalize_mac_address(mac: str) -> str:
    """Normalize MAC address to standard format (xx:xx:xx:xx:xx:xx)."""
    if not validate_mac_address(mac):
        raise ValueError(f"Invalid MAC address: {mac}")
    
    # Remove separators and convert to lowercase
    clean_mac = re.sub(r'[:-]', '', mac.lower())
    
    # Add colons
    return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))

def generate_device_fingerprint(ip: str, mac: str = None, hostname: str = None, 
                               services: Dict = None) -> str:
    """Generate unique fingerprint for a device."""
    fingerprint_data = {
        'ip': ip,
        'mac': normalize_mac_address(mac) if mac else None,
        'hostname': hostname,
        'services': sorted(services.items()) if services else None
    }
    
    # Create hash from fingerprint data
    fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string into list of ports."""
    ports = []
    
    for part in port_range.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-', 1))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(list(set(ports)))  # Remove duplicates and sort

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def format_file_size(bytes_size: int) -> str:
    """Format file size in bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} PB"

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem usage."""
    # Remove or replace unsafe characters
    safe_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    safe_filename = safe_filename.strip(' .')
    
    # Limit length
    if len(safe_filename) > 255:
        name, ext = safe_filename.rsplit('.', 1) if '.' in safe_filename else (safe_filename, '')
        max_name_length = 255 - len(ext) - 1 if ext else 255
        safe_filename = name[:max_name_length] + ('.' + ext if ext else '')
    
    return safe_filename

def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return url

def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def calculate_risk_score(vulnerabilities: List[Dict[str, Any]]) -> float:
    """Calculate overall risk score from list of vulnerabilities."""
    if not vulnerabilities:
        return 0.0
    
    severity_weights = {
        'critical': 10.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 1.0
    }
    
    total_score = 0.0
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info')
        weight = severity_weights.get(severity, 1.0)
        
        # Apply CVSS score if available
        cvss_score = vuln.get('cvss_score', 5.0)
        adjusted_weight = weight * (cvss_score / 10.0)
        
        total_score += adjusted_weight
    
    # Normalize to 0-100 scale (assuming max 20 critical vulns as 100)
    max_possible = 20 * severity_weights['critical']
    normalized_score = min(100.0, (total_score / max_possible) * 100)
    
    return round(normalized_score, 1)

def generate_assessment_name(device_ip: str, scan_type: str = 'standard') -> str:
    """Generate assessment name based on device and scan type."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{scan_type}_scan_{device_ip}_{timestamp}"

def parse_nmap_ports(nmap_output: str) -> List[Dict[str, Any]]:
    """Parse nmap output to extract port information."""
    ports = []
    
    # Simple regex-based parsing (in production, use python-nmap library)
    port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)')
    
    for line in nmap_output.split('\n'):
        match = port_pattern.match(line.strip())
        if match:
            port_num, protocol, state, service = match.groups()
            ports.append({
                'port': int(port_num),
                'protocol': protocol,
                'state': state,
                'service': service.strip()
            })
    
    return ports

def detect_device_type(services: Dict[str, Any], hostname: str = None) -> str:
    """Detect device type based on services and hostname."""
    # Simple heuristic-based detection
    service_names = [s.lower() for s in services.values() if isinstance(s, str)]
    hostname_lower = hostname.lower() if hostname else ''
    
    # Camera detection
    camera_indicators = ['rtsp', 'onvif', 'camera', 'webcam', 'nvr', 'dvr']
    if any(indicator in ' '.join(service_names + [hostname_lower]) for indicator in camera_indicators):
        return 'camera'
    
    # Router detection
    router_indicators = ['router', 'gateway', 'wifi', 'wireless', 'access-point']
    if any(indicator in hostname_lower for indicator in router_indicators):
        return 'router'
    
    # IoT sensor detection
    sensor_indicators = ['sensor', 'temperature', 'humidity', 'motion']
    if any(indicator in hostname_lower for indicator in sensor_indicators):
        return 'sensor'
    
    # Smart switch/plug detection
    switch_indicators = ['switch', 'plug', 'outlet', 'relay']
    if any(indicator in hostname_lower for indicator in switch_indicators):
        return 'switch'
    
    # Default to unknown
    return 'unknown'

def extract_manufacturer(hostname: str = None, mac: str = None, 
                        banner: str = None) -> Optional[str]:
    """Extract manufacturer information from various sources."""
    # MAC address OUI lookup (simplified)
    mac_oui_mapping = {
        '00:1B:63': 'Hikvision',
        '00:12:12': 'Dahua',
        '28:C6:8E': 'TP-Link',
        '00:14:D1': 'TRENDnet',
        '00:0C:43': 'Raisecom',
        'B8:27:EB': 'Raspberry Pi Foundation',
        '18:FE:34': 'Espressif (ESP32)',
        '5C:CF:7F': 'Espressif (ESP8266)'
    }
    
    if mac:
        oui = mac.upper()[:8]  # First 3 octets
        if oui in mac_oui_mapping:
            return mac_oui_mapping[oui]
    
    # Hostname-based detection
    if hostname:
        hostname_lower = hostname.lower()
        if 'hikvision' in hostname_lower or 'hikv' in hostname_lower:
            return 'Hikvision'
        elif 'dahua' in hostname_lower:
            return 'Dahua'
        elif 'tplink' in hostname_lower or 'tp-link' in hostname_lower:
            return 'TP-Link'
        elif 'xiaomi' in hostname_lower or 'mi-' in hostname_lower:
            return 'Xiaomi'
        elif 'samsung' in hostname_lower:
            return 'Samsung'
    
    # Banner-based detection
    if banner:
        banner_lower = banner.lower()
        for manufacturer in ['hikvision', 'dahua', 'axis', 'bosch', 'sony', 'panasonic']:
            if manufacturer in banner_lower:
                return manufacturer.title()
    
    return None

def create_device_signature(device_info: Dict[str, Any]) -> Dict[str, Any]:
    """Create device signature for classification."""
    signature = {
        'manufacturer': device_info.get('manufacturer'),
        'device_type': device_info.get('device_type'),
        'model': device_info.get('model'),
        'open_ports': sorted(device_info.get('open_ports', [])),
        'services': device_info.get('services', {}),
        'protocols': sorted(device_info.get('protocols', []))
    }
    
    # Generate signature hash
    signature_str = json.dumps(signature, sort_keys=True)
    signature['hash'] = hashlib.md5(signature_str.encode()).hexdigest()
    
    return signature

def merge_scan_results(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Merge new scan results with existing device data."""
    merged = existing.copy()
    
    # Update basic info if new data is more complete
    for key in ['hostname', 'manufacturer', 'device_type', 'model', 'firmware_version']:
        if new.get(key) and (not existing.get(key) or len(str(new[key])) > len(str(existing.get(key, '')))):
            merged[key] = new[key]
    
    # Merge port lists
    existing_ports = set(existing.get('open_ports', []))
    new_ports = set(new.get('open_ports', []))
    merged['open_ports'] = sorted(list(existing_ports.union(new_ports)))
    
    # Merge services
    merged_services = existing.get('services', {}).copy()
    merged_services.update(new.get('services', {}))
    merged['services'] = merged_services
    
    # Merge protocols
    existing_protocols = set(existing.get('protocols', []))
    new_protocols = set(new.get('protocols', []))
    merged['protocols'] = sorted(list(existing_protocols.union(new_protocols)))
    
    # Update confidence score (take higher value)
    merged['confidence_score'] = max(
        existing.get('confidence_score', 0.0),
        new.get('confidence_score', 0.0)
    )
    
    return merged

def validate_assessment_config(config: Dict[str, Any]) -> List[str]:
    """Validate assessment configuration and return list of errors."""
    errors = []
    
    # Check required fields
    required_fields = ['device_id', 'scan_type']
    for field in required_fields:
        if not config.get(field):
            errors.append(f"Missing required field: {field}")
    
    # Validate scan type
    valid_scan_types = ['quick', 'standard', 'comprehensive', 'custom']
    if config.get('scan_type') not in valid_scan_types:
        errors.append(f"Invalid scan type. Must be one of: {valid_scan_types}")
    
    # Validate protocols if specified
    if 'target_protocols' in config:
        valid_protocols = ['http', 'https', 'ftp', 'ssh', 'telnet', 'smtp', 'pop3', 'imap', 'mqtt', 'coap']
        invalid_protocols = [p for p in config['target_protocols'] if p not in valid_protocols]
        if invalid_protocols:
            errors.append(f"Invalid protocols: {invalid_protocols}")
    
    # Validate timeout values
    if 'timeout' in config:
        timeout = config['timeout']
        if not isinstance(timeout, int) or timeout < 1 or timeout > 300:
            errors.append("Timeout must be an integer between 1 and 300 seconds")
    
    return errors
