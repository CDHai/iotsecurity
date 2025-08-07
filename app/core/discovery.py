import nmap
import asyncio
import aiohttp
import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional
from app.models.device import Device, DeviceType, DeviceStatus
from app import db

class NetworkScanner:
    """Network discovery and device detection"""
    
    def __init__(self):
        self.nmap = nmap.PortScanner()
        self.common_iot_ports = [
            21, 22, 23, 53, 80, 135, 139, 443, 445, 993, 995,
            1883, 5683, 8080, 8443, 9999, 37777, 554, 8000, 10001
        ]
    
    def scan_network(self, network_range: str, scan_options: Dict = None) -> List[Device]:
        """
        Scan network for IoT devices
        
        Args:
            network_range: CIDR notation (e.g., "192.168.1.0/24")
            scan_options: Additional scan options
            
        Returns:
            List of discovered devices
        """
        print(f"Starting network scan for {network_range}")
        
        # Phase 1: Quick host discovery
        alive_hosts = self._discover_hosts(network_range)
        print(f"Discovered {len(alive_hosts)} active hosts")
        
        # Phase 2: Port scanning and service enumeration
        devices = []
        for host_ip in alive_hosts:
            device = self._scan_device(host_ip)
            if device:
                devices.append(device)
        
        print(f"Completed scan. Found {len(devices)} IoT devices")
        return devices
    
    def _discover_hosts(self, network_range: str) -> List[str]:
        """Discover active hosts in network range"""
        try:
            # Quick ping sweep
            scan_result = self.nmap.scan(
                hosts=network_range,
                arguments='-sn -n --max-retries 2 --min-rate 100'
            )
            
            alive_hosts = []
            for host in scan_result['scan']:
                if scan_result['scan'][host]['status']['state'] == 'up':
                    alive_hosts.append(host)
            
            return alive_hosts
        except Exception as e:
            print(f"Error during host discovery: {e}")
            return []
    
    def _scan_device(self, ip_address: str) -> Optional[Device]:
        """Scan individual device for ports and services"""
        try:
            # Port scan with common IoT ports
            scan_result = self.nmap.scan(
                hosts=ip_address,
                ports=','.join(map(str, self.common_iot_ports)),
                arguments='-sS -sV -O --version-intensity 5'
            )
            
            if ip_address not in scan_result['scan']:
                return None
            
            host_info = scan_result['scan'][ip_address]
            if host_info['status']['state'] != 'up':
                return None
            
            # Extract device information
            device = Device(ip_address=ip_address)
            
            # Get MAC address if available
            if 'addresses' in host_info and 'mac' in host_info['addresses']:
                device.mac_address = host_info['addresses']['mac']
            
            # Get hostname if available
            if 'hostnames' in host_info and host_info['hostnames']:
                device.hostname = host_info['hostnames'][0]['name']
            
            # Extract open ports and services
            open_ports = []
            services = {}
            
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    if port_info['state'] == 'open':
                        open_ports.append(port)
                        services[port] = {
                            'name': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
            
            device.open_ports_list = open_ports
            device.services_dict = services
            device.protocols_list = self._detect_protocols(services)
            
            # Update device status
            device.status = DeviceStatus.ONLINE
            device.update_last_seen()
            
            return device
            
        except Exception as e:
            print(f"Error scanning device {ip_address}: {e}")
            return None
    
    def _detect_protocols(self, services: Dict) -> List[str]:
        """Detect protocols based on services"""
        protocols = []
        
        for port, service_info in services.items():
            service_name = service_info.get('name', '').lower()
            product = service_info.get('product', '').lower()
            
            # HTTP/HTTPS
            if port in [80, 443, 8080, 8443] or 'http' in service_name:
                protocols.append('http')
            
            # MQTT
            if port == 1883 or 'mqtt' in service_name:
                protocols.append('mqtt')
            
            # CoAP
            if port == 5683 or 'coap' in service_name:
                protocols.append('coap')
            
            # RTSP (cameras)
            if port == 554 or 'rtsp' in service_name:
                protocols.append('rtsp')
            
            # SSH
            if port == 22 or 'ssh' in service_name:
                protocols.append('ssh')
            
            # Telnet
            if port == 23 or 'telnet' in service_name:
                protocols.append('telnet')
            
            # FTP
            if port == 21 or 'ftp' in service_name:
                protocols.append('ftp')
        
        return list(set(protocols))  # Remove duplicates
    
    async def scan_network_async(self, network_range: str) -> List[Device]:
        """Asynchronous network scanning"""
        loop = asyncio.get_event_loop()
        
        # Run network scan in thread pool
        with ThreadPoolExecutor() as executor:
            devices = await loop.run_in_executor(
                executor, self.scan_network, network_range
            )
        
        return devices

class DeviceClassifier:
    """Device classification and fingerprinting"""
    
    def __init__(self):
        self.signature_db = self._load_signature_database()
    
    def classify_device(self, device: Device) -> Dict:
        """
        Classify device based on fingerprinting
        
        Args:
            device: Device to classify
            
        Returns:
            Classification result
        """
        classification = {
            'device_type': 'unknown',
            'manufacturer': 'unknown',
            'model': 'unknown',
            'confidence': 0.0,
            'method': 'none'
        }
        
        # Stage 1: Signature-based classification
        signature_result = self._signature_classification(device)
        if signature_result['confidence'] > 0.8:
            return signature_result
        
        # Stage 2: Heuristic-based classification
        heuristic_result = self._heuristic_classification(device)
        if heuristic_result['confidence'] > 0.6:
            return heuristic_result
        
        return classification
    
    def _signature_classification(self, device: Device) -> Dict:
        """Database signature matching"""
        best_match = {
            'device_type': 'unknown',
            'manufacturer': 'unknown',
            'model': 'unknown',
            'confidence': 0.0,
            'method': 'signature'
        }
        
        for signature in self.signature_db:
            match_score = self._calculate_signature_match(device, signature)
            
            if match_score > best_match['confidence']:
                best_match.update({
                    'device_type': signature['device_type'],
                    'manufacturer': signature['manufacturer'],
                    'model': signature['model'],
                    'confidence': match_score
                })
        
        return best_match
    
    def _heuristic_classification(self, device: Device) -> Dict:
        """Rule-based heuristic classification"""
        score = 0.0
        device_type = 'unknown'
        manufacturer = 'unknown'
        model = 'unknown'
        
        # Port pattern analysis
        open_ports = set(device.open_ports_list)
        
        # Camera detection
        if {554, 80}.issubset(open_ports) or {554, 443}.issubset(open_ports):
            device_type = 'camera'
            score += 0.4
        
        # Router detection
        if {80, 443, 22}.issubset(open_ports):
            device_type = 'router'
            score += 0.3
        
        # Sensor detection
        if 1883 in open_ports:
            device_type = 'sensor'
            score += 0.3
        
        # HTTP response analysis
        if device.services_dict:
            for port, service_info in device.services_dict.items():
                if port in [80, 443, 8080, 8443]:
                    server_header = service_info.get('product', '')
                    
                    # Camera manufacturers
                    if 'hikvision' in server_header.lower():
                        manufacturer = 'Hikvision'
                        score += 0.3
                    elif 'dahua' in server_header.lower():
                        manufacturer = 'Dahua'
                        score += 0.3
                    elif 'axis' in server_header.lower():
                        manufacturer = 'Axis'
                        score += 0.3
                    
                    # Router manufacturers
                    elif 'tp-link' in server_header.lower():
                        manufacturer = 'TP-Link'
                        device_type = 'router'
                        score += 0.3
                    elif 'asus' in server_header.lower():
                        manufacturer = 'ASUS'
                        device_type = 'router'
                        score += 0.3
        
        return {
            'device_type': device_type,
            'manufacturer': manufacturer,
            'model': model,
            'confidence': min(score, 1.0),
            'method': 'heuristic'
        }
    
    def _calculate_signature_match(self, device: Device, signature: Dict) -> float:
        """Calculate signature match score"""
        score = 0.0
        
        # Port matching
        device_ports = set(device.open_ports_list)
        signature_ports = set(signature.get('ports', []))
        
        if signature_ports:
            port_match = len(device_ports.intersection(signature_ports)) / len(signature_ports)
            score += port_match * 0.4
        
        # Service matching
        if device.services_dict and 'services' in signature:
            service_matches = 0
            total_services = len(signature['services'])
            
            for sig_service in signature['services']:
                for port, service_info in device.services_dict.items():
                    if (sig_service['port'] == port and 
                        sig_service['name'] == service_info.get('name', '')):
                        service_matches += 1
                        break
            
            if total_services > 0:
                score += (service_matches / total_services) * 0.4
        
        # Manufacturer matching
        if (device.manufacturer and 
            signature.get('manufacturer', '').lower() == device.manufacturer.lower()):
            score += 0.2
        
        return min(score, 1.0)
    
    def _load_signature_database(self) -> List[Dict]:
        """Load device signature database"""
        # This would typically load from a database or file
        # For now, return a basic signature set
        return [
            {
                'device_type': 'camera',
                'manufacturer': 'Hikvision',
                'model': 'DS-2CD2042WD-I',
                'ports': [80, 443, 554, 8000],
                'services': [
                    {'port': 80, 'name': 'http'},
                    {'port': 443, 'name': 'https'},
                    {'port': 554, 'name': 'rtsp'}
                ]
            },
            {
                'device_type': 'router',
                'manufacturer': 'TP-Link',
                'model': 'Archer C7',
                'ports': [80, 443, 22],
                'services': [
                    {'port': 80, 'name': 'http'},
                    {'port': 443, 'name': 'https'},
                    {'port': 22, 'name': 'ssh'}
                ]
            },
            {
                'device_type': 'sensor',
                'manufacturer': 'Xiaomi',
                'model': 'MCCGQ02HL',
                'ports': [1883],
                'services': [
                    {'port': 1883, 'name': 'mqtt'}
                ]
            }
        ]
    
    def update_device_classification(self, device: Device, classification: Dict):
        """Update device with classification results"""
        if classification['device_type'] != 'unknown':
            device.device_type = DeviceType(classification['device_type'])
        
        if classification['manufacturer'] != 'unknown':
            device.manufacturer = classification['manufacturer']
        
        if classification['model'] != 'unknown':
            device.model = classification['model']
        
        device.confidence_score = classification['confidence']
        
        # Update fingerprint
        fingerprint = {
            'classification_method': classification['method'],
            'classification_confidence': classification['confidence'],
            'classification_timestamp': time.time()
        }
        device.fingerprint_dict = fingerprint
        
        db.session.commit()
