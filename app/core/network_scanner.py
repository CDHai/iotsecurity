"""
Network discovery and device detection module
"""

import nmap
import socket
import subprocess
import json
import re
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import logging

from app.utils.helpers import (
    validate_ip_address, validate_ip_range, normalize_mac_address,
    detect_device_type, extract_manufacturer, parse_nmap_ports
)

logger = logging.getLogger(__name__)

class NetworkScanner:
    """Network scanner for IoT device discovery."""
    
    def __init__(self, timeout: int = 30, max_threads: int = 50):
        self.timeout = timeout
        self.max_threads = max_threads
        self.nm = nmap.PortScanner()
        self.discovered_devices = []
        
    def scan_network(self, network_range: str, scan_type: str = 'ping') -> List[Dict[str, Any]]:
        """
        Scan network range for active devices.
        
        Args:
            network_range: CIDR notation (e.g., '192.168.1.0/24')
            scan_type: 'ping', 'tcp_connect', 'tcp_syn', 'udp'
        
        Returns:
            List of discovered devices
        """
        logger.info(f"Starting network scan: {network_range} with {scan_type}")
        
        if not validate_ip_range(network_range):
            raise ValueError(f"Invalid network range: {network_range}")
        
        try:
            # Configure nmap scan based on type
            nmap_args = self._get_nmap_args(scan_type)
            
            # Perform scan
            self.nm.scan(network_range, arguments=nmap_args)
            
            devices = []
            for host in self.nm.all_hosts():
                device_info = self._analyze_host(host)
                if device_info:
                    devices.append(device_info)
            
            logger.info(f"Discovered {len(devices)} devices")
            self.discovered_devices = devices
            return devices
            
        except Exception as e:
            logger.error(f"Network scan failed: {str(e)}")
            raise
    
    def _get_nmap_args(self, scan_type: str) -> str:
        """Get nmap arguments based on scan type."""
        args_map = {
            'ping': '-sn',  # Ping scan only
            'tcp_connect': '-sT -p 22,23,80,443,554,8080',  # Common IoT ports
            'tcp_syn': '-sS -p 1-1000',  # SYN scan
            'udp': '-sU -p 53,67,123,161,1900,5353',  # Common UDP ports
            'comprehensive': '-sS -sU -p 1-65535 -A'  # Full scan with OS detection
        }
        
        return args_map.get(scan_type, '-sn')
    
    def _analyze_host(self, host: str) -> Optional[Dict[str, Any]]:
        """Analyze discovered host and extract device information."""
        try:
            host_info = self.nm[host]
            
            # Skip if host is down
            if host_info.state() != 'up':
                return None
            
            device_info = {
                'ip_address': host,
                'hostname': None,
                'mac_address': None,
                'manufacturer': None,
                'device_type': 'unknown',
                'open_ports': [],
                'services': {},
                'protocols': [],
                'confidence_score': 0.0,
                'last_seen': datetime.utcnow(),
                'scan_info': {
                    'os_match': None,
                    'device_match': None,
                    'uptime': None
                }
            }
            
            # Extract hostname
            if 'hostnames' in host_info and host_info['hostnames']:
                device_info['hostname'] = host_info['hostnames'][0]['name']
            
            # Extract MAC address and vendor
            if 'addresses' in host_info:
                if 'mac' in host_info['addresses']:
                    mac = host_info['addresses']['mac']
                    device_info['mac_address'] = normalize_mac_address(mac)
                    
                    # Try to get vendor info
                    if 'vendor' in host_info and host_info['vendor']:
                        device_info['manufacturer'] = list(host_info['vendor'].values())[0]
            
            # Extract port and service information
            if 'tcp' in host_info or 'udp' in host_info:
                device_info.update(self._extract_port_info(host_info))
            
            # Try additional device detection methods
            device_info.update(self._enhanced_device_detection(host))
            
            # Calculate confidence score
            device_info['confidence_score'] = self._calculate_confidence(device_info)
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error analyzing host {host}: {str(e)}")
            return None
    
    def _extract_port_info(self, host_info: Dict) -> Dict[str, Any]:
        """Extract port and service information."""
        open_ports = []
        services = {}
        protocols = set()
        
        # TCP ports
        if 'tcp' in host_info:
            for port, port_info in host_info['tcp'].items():
                if port_info['state'] == 'open':
                    open_ports.append(port)
                    service_name = port_info.get('name', 'unknown')
                    services[f"tcp/{port}"] = service_name
                    protocols.add('tcp')
                    
                    # Add protocol-specific detection
                    if service_name in ['http', 'http-alt', 'http-proxy']:
                        protocols.add('http')
                    elif service_name in ['https', 'ssl/http']:
                        protocols.add('https')
                    elif service_name == 'ssh':
                        protocols.add('ssh')
                    elif service_name == 'telnet':
                        protocols.add('telnet')
                    elif service_name == 'rtsp':
                        protocols.add('rtsp')
        
        # UDP ports
        if 'udp' in host_info:
            for port, port_info in host_info['udp'].items():
                if port_info['state'] in ['open', 'open|filtered']:
                    open_ports.append(port)
                    service_name = port_info.get('name', 'unknown')
                    services[f"udp/{port}"] = service_name
                    protocols.add('udp')
                    
                    # Add protocol-specific detection
                    if port == 1883:
                        protocols.add('mqtt')
                    elif port == 5683:
                        protocols.add('coap')
                    elif port == 161:
                        protocols.add('snmp')
        
        return {
            'open_ports': sorted(open_ports),
            'services': services,
            'protocols': sorted(list(protocols))
        }
    
    def _enhanced_device_detection(self, host: str) -> Dict[str, Any]:
        """Enhanced device detection using multiple methods."""
        detection_info = {
            'manufacturer': None,
            'device_type': 'unknown'
        }
        
        try:
            # HTTP banner grabbing
            http_info = self._http_banner_grab(host)
            if http_info:
                detection_info.update(http_info)
            
            # SNMP detection
            snmp_info = self._snmp_detection(host)
            if snmp_info:
                detection_info.update(snmp_info)
            
            # UPnP detection
            upnp_info = self._upnp_detection(host)
            if upnp_info:
                detection_info.update(upnp_info)
            
        except Exception as e:
            logger.debug(f"Enhanced detection failed for {host}: {str(e)}")
        
        return detection_info
    
    def _http_banner_grab(self, host: str) -> Optional[Dict[str, Any]]:
        """Grab HTTP banners for device identification."""
        try:
            import requests
            
            # Try common HTTP ports
            ports = [80, 8080, 443, 8443]
            
            for port in ports:
                try:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    url = f"{protocol}://{host}:{port}"
                    
                    response = requests.get(
                        url, 
                        timeout=5, 
                        verify=False,
                        allow_redirects=False
                    )
                    
                    # Extract server header
                    server = response.headers.get('Server', '')
                    
                    # Device-specific patterns
                    patterns = {
                        'camera': ['hikvision', 'dahua', 'axis', 'vivotek', 'foscam'],
                        'router': ['mikrotik', 'ubiquiti', 'tp-link', 'netgear', 'asus'],
                        'nas': ['synology', 'qnap', 'drobo'],
                        'printer': ['hp', 'canon', 'epson', 'brother'],
                        'iot_hub': ['samsung smartthings', 'philips hue', 'wink']
                    }
                    
                    # Check response content for device indicators
                    content = response.text.lower()
                    
                    for device_type, keywords in patterns.items():
                        if any(keyword in server.lower() or keyword in content for keyword in keywords):
                            return {
                                'device_type': device_type,
                                'manufacturer': self._extract_manufacturer_from_banner(server, content)
                            }
                    
                    break  # Successfully connected, stop trying other ports
                    
                except requests.exceptions.RequestException:
                    continue
            
        except Exception as e:
            logger.debug(f"HTTP banner grab failed for {host}: {str(e)}")
        
        return None
    
    def _snmp_detection(self, host: str) -> Optional[Dict[str, Any]]:
        """SNMP-based device detection."""
        try:
            from pysnmp.hlapi import *
            
            # Common SNMP community strings
            communities = ['public', 'private', 'admin']
            
            for community in communities:
                try:
                    # Get system description (1.3.6.1.2.1.1.1.0)
                    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                        SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((host, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
                        lexicographicMode=False,
                        maxRows=1
                    ):
                        if errorIndication or errorStatus:
                            continue
                        
                        for varBind in varBinds:
                            sys_descr = str(varBind[1])
                            
                            # Parse system description for device info
                            return self._parse_snmp_sysdescr(sys_descr)
                
                except Exception:
                    continue
                    
        except ImportError:
            logger.debug("pysnmp not available for SNMP detection")
        except Exception as e:
            logger.debug(f"SNMP detection failed for {host}: {str(e)}")
        
        return None
    
    def _upnp_detection(self, host: str) -> Optional[Dict[str, Any]]:
        """UPnP-based device detection."""
        try:
            import socket
            
            # Send M-SEARCH request
            msg = (
                'M-SEARCH * HTTP/1.1\r\n'
                'HOST: 239.255.255.250:1900\r\n'
                'MAN: "ssdp:discover"\r\n'
                'ST: upnp:rootdevice\r\n'
                'MX: 3\r\n\r\n'
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(msg.encode(), (host, 1900))
            
            try:
                response, addr = sock.recvfrom(1024)
                response_text = response.decode()
                
                # Parse UPnP response for device info
                if 'SERVER:' in response_text:
                    server_line = [line for line in response_text.split('\r\n') 
                                 if line.startswith('SERVER:')][0]
                    
                    # Extract device information from server string
                    return self._parse_upnp_server(server_line)
                    
            except socket.timeout:
                pass
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"UPnP detection failed for {host}: {str(e)}")
        
        return None
    
    def _extract_manufacturer_from_banner(self, server: str, content: str) -> Optional[str]:
        """Extract manufacturer from HTTP banner or content."""
        manufacturers = {
            'hikvision': 'Hikvision',
            'dahua': 'Dahua',
            'axis': 'Axis Communications',
            'vivotek': 'Vivotek',
            'foscam': 'Foscam',
            'tp-link': 'TP-Link',
            'netgear': 'Netgear',
            'asus': 'ASUS',
            'synology': 'Synology',
            'qnap': 'QNAP'
        }
        
        combined_text = (server + ' ' + content).lower()
        
        for keyword, manufacturer in manufacturers.items():
            if keyword in combined_text:
                return manufacturer
        
        return None
    
    def _parse_snmp_sysdescr(self, sys_descr: str) -> Dict[str, Any]:
        """Parse SNMP system description for device information."""
        sys_descr_lower = sys_descr.lower()
        
        # Device type patterns
        if any(keyword in sys_descr_lower for keyword in ['camera', 'ipcam', 'webcam']):
            device_type = 'camera'
        elif any(keyword in sys_descr_lower for keyword in ['router', 'gateway', 'switch']):
            device_type = 'router'
        elif any(keyword in sys_descr_lower for keyword in ['printer', 'print']):
            device_type = 'printer'
        elif any(keyword in sys_descr_lower for keyword in ['nas', 'storage']):
            device_type = 'nas'
        else:
            device_type = 'unknown'
        
        # Extract manufacturer
        manufacturer = self._extract_manufacturer_from_banner(sys_descr, '')
        
        return {
            'device_type': device_type,
            'manufacturer': manufacturer,
            'system_description': sys_descr
        }
    
    def _parse_upnp_server(self, server_line: str) -> Dict[str, Any]:
        """Parse UPnP server line for device information."""
        # Example: "SERVER: Linux/3.14.0 UPnP/1.0 Portable SDK for UPnP devices/1.6.19"
        
        device_info = {'device_type': 'unknown'}
        
        if 'upnp' in server_line.lower():
            device_info['protocols'] = ['upnp']
        
        # Look for OS information
        if 'linux' in server_line.lower():
            device_info['operating_system'] = 'Linux'
        elif 'windows' in server_line.lower():
            device_info['operating_system'] = 'Windows'
        
        return device_info
    
    def _calculate_confidence(self, device_info: Dict[str, Any]) -> float:
        """Calculate confidence score for device identification."""
        score = 0.0
        
        # Base score for successful detection
        score += 0.3
        
        # Bonus for having MAC address
        if device_info.get('mac_address'):
            score += 0.2
        
        # Bonus for having manufacturer
        if device_info.get('manufacturer'):
            score += 0.2
        
        # Bonus for having hostname
        if device_info.get('hostname'):
            score += 0.1
        
        # Bonus for open ports
        if device_info.get('open_ports'):
            score += min(0.2, len(device_info['open_ports']) * 0.05)
        
        # Bonus for identified device type (not unknown)
        if device_info.get('device_type') != 'unknown':
            score += 0.2
        
        return min(1.0, score)

class DeviceFingerprinter:
    """Device fingerprinting and classification."""
    
    def __init__(self):
        self.signatures = self._load_device_signatures()
    
    def _load_device_signatures(self) -> Dict[str, Any]:
        """Load device signatures database."""
        # This would normally load from a file or database
        return {
            'hikvision_camera': {
                'patterns': {
                    'http_server': ['hikvision', 'webs'],
                    'ports': [80, 554, 8000],
                    'paths': ['/ISAPI/System/deviceInfo', '/onvif/device_service']
                },
                'device_type': 'camera',
                'manufacturer': 'Hikvision'
            },
            'dahua_camera': {
                'patterns': {
                    'http_server': ['dahua', 'webs'],
                    'ports': [80, 554, 37777],
                    'paths': ['/cgi-bin/magicBox.cgi']
                },
                'device_type': 'camera',
                'manufacturer': 'Dahua'
            },
            'tplink_router': {
                'patterns': {
                    'http_server': ['tp-link'],
                    'ports': [80, 443],
                    'hostname_patterns': ['tplinkwifi', 'tp-link']
                },
                'device_type': 'router',
                'manufacturer': 'TP-Link'
            }
        }
    
    def fingerprint_device(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fingerprint device based on collected information."""
        best_match = None
        best_score = 0.0
        
        for signature_name, signature in self.signatures.items():
            score = self._match_signature(device_info, signature)
            if score > best_score:
                best_score = score
                best_match = signature
        
        if best_match and best_score > 0.7:
            device_info.update({
                'device_type': best_match['device_type'],
                'manufacturer': best_match['manufacturer'],
                'confidence_score': max(device_info.get('confidence_score', 0), best_score)
            })
        
        return device_info
    
    def _match_signature(self, device_info: Dict[str, Any], signature: Dict[str, Any]) -> float:
        """Match device info against signature."""
        score = 0.0
        total_checks = 0
        
        patterns = signature.get('patterns', {})
        
        # Check HTTP server patterns
        if 'http_server' in patterns and 'services' in device_info:
            total_checks += 1
            services_text = ' '.join(device_info['services'].values()).lower()
            if any(pattern in services_text for pattern in patterns['http_server']):
                score += 1.0
        
        # Check port patterns
        if 'ports' in patterns and 'open_ports' in device_info:
            total_checks += 1
            matching_ports = set(patterns['ports']) & set(device_info['open_ports'])
            if matching_ports:
                score += len(matching_ports) / len(patterns['ports'])
        
        # Check hostname patterns
        if 'hostname_patterns' in patterns and device_info.get('hostname'):
            total_checks += 1
            hostname_lower = device_info['hostname'].lower()
            if any(pattern in hostname_lower for pattern in patterns['hostname_patterns']):
                score += 1.0
        
        return score / total_checks if total_checks > 0 else 0.0

# Async network scanner for better performance
class AsyncNetworkScanner:
    """Asynchronous network scanner for better performance."""
    
    def __init__(self, max_concurrent: int = 100, timeout: int = 5):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_network_async(self, network_range: str) -> List[Dict[str, Any]]:
        """Asynchronously scan network range."""
        import ipaddress
        
        network = ipaddress.ip_network(network_range, strict=False)
        tasks = []
        
        for ip in network.hosts():
            task = self._scan_host_async(str(ip))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        devices = []
        for result in results:
            if isinstance(result, dict):
                devices.append(result)
        
        return devices
    
    async def _scan_host_async(self, host: str) -> Optional[Dict[str, Any]]:
        """Asynchronously scan single host."""
        async with self.semaphore:
            try:
                # Ping check
                if not await self._ping_host_async(host):
                    return None
                
                # Port scan
                open_ports = await self._port_scan_async(host)
                
                if not open_ports:
                    return None
                
                # Basic device info
                device_info = {
                    'ip_address': host,
                    'open_ports': open_ports,
                    'last_seen': datetime.utcnow(),
                    'confidence_score': 0.5
                }
                
                # Try to get more info
                hostname = await self._get_hostname_async(host)
                if hostname:
                    device_info['hostname'] = hostname
                
                return device_info
                
            except Exception as e:
                logger.debug(f"Async scan failed for {host}: {str(e)}")
                return None
    
    async def _ping_host_async(self, host: str) -> bool:
        """Asynchronously ping host."""
        try:
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '2', host,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(process.wait(), timeout=self.timeout)
            return process.returncode == 0
        except:
            return False
    
    async def _port_scan_async(self, host: str) -> List[int]:
        """Asynchronously scan common ports."""
        common_ports = [22, 23, 80, 443, 554, 1883, 5683, 8080, 8443]
        open_ports = []
        
        tasks = []
        for port in common_ports:
            task = self._check_port_async(host, port)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, result in zip(common_ports, results):
            if result is True:
                open_ports.append(port)
        
        return open_ports
    
    async def _check_port_async(self, host: str, port: int) -> bool:
        """Asynchronously check if port is open."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def _get_hostname_async(self, host: str) -> Optional[str]:
        """Asynchronously resolve hostname."""
        try:
            return await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyaddr, host
                ),
                timeout=self.timeout
            )
        except:
            return None
