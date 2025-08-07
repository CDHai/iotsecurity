"""
Device discovery service integrating network scanning with database
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from app import db
from app.models.device import Device
from app.core.network_scanner import NetworkScanner, DeviceFingerprinter, AsyncNetworkScanner
from app.utils.helpers import merge_scan_results, generate_device_fingerprint

logger = logging.getLogger(__name__)

class DeviceDiscoveryService:
    """Service for discovering and managing IoT devices."""
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.async_scanner = AsyncNetworkScanner()
        self.fingerprinter = DeviceFingerprinter()
        
    def discover_devices(self, network_range: str, scan_type: str = 'tcp_connect', 
                        save_to_db: bool = True) -> List[Dict[str, Any]]:
        """
        Discover devices on network and optionally save to database.
        
        Args:
            network_range: CIDR notation (e.g., '192.168.1.0/24')
            scan_type: Type of scan to perform
            save_to_db: Whether to save results to database
            
        Returns:
            List of discovered devices
        """
        logger.info(f"Starting device discovery for {network_range}")
        
        try:
            # Perform network scan
            discovered_devices = self.scanner.scan_network(network_range, scan_type)
            
            # Enhance with fingerprinting
            for device_info in discovered_devices:
                device_info = self.fingerprinter.fingerprint_device(device_info)
            
            # Save to database if requested
            if save_to_db:
                self._save_discovered_devices(discovered_devices)
            
            logger.info(f"Discovery completed. Found {len(discovered_devices)} devices")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"Device discovery failed: {str(e)}")
            raise
    
    async def discover_devices_async(self, network_range: str, 
                                   save_to_db: bool = True) -> List[Dict[str, Any]]:
        """Asynchronous device discovery for better performance."""
        logger.info(f"Starting async device discovery for {network_range}")
        
        try:
            # Perform async network scan
            discovered_devices = await self.async_scanner.scan_network_async(network_range)
            
            # Enhance with fingerprinting
            for device_info in discovered_devices:
                device_info = self.fingerprinter.fingerprint_device(device_info)
            
            # Save to database if requested
            if save_to_db:
                self._save_discovered_devices(discovered_devices)
            
            logger.info(f"Async discovery completed. Found {len(discovered_devices)} devices")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"Async device discovery failed: {str(e)}")
            raise
    
    def _save_discovered_devices(self, discovered_devices: List[Dict[str, Any]]):
        """Save discovered devices to database."""
        saved_count = 0
        updated_count = 0
        
        for device_info in discovered_devices:
            try:
                # Check if device already exists
                existing_device = Device.find_by_ip(device_info['ip_address'])
                
                if existing_device:
                    # Update existing device
                    updated_info = merge_scan_results(
                        existing_device.to_dict(), 
                        device_info
                    )
                    
                    # Update device attributes
                    for key, value in updated_info.items():
                        if hasattr(existing_device, key) and key != 'id':
                            if key == 'open_ports':
                                existing_device.open_ports_list = value
                            elif key == 'protocols':
                                existing_device.protocols_list = value
                            elif key == 'services':
                                existing_device.services_dict = value
                            elif key == 'tags':
                                existing_device.tags_list = value
                            else:
                                setattr(existing_device, key, value)
                    
                    existing_device.update_last_seen()
                    updated_count += 1
                    
                else:
                    # Create new device
                    new_device = Device(
                        ip_address=device_info['ip_address'],
                        hostname=device_info.get('hostname'),
                        mac_address=device_info.get('mac_address'),
                        manufacturer=device_info.get('manufacturer'),
                        device_type=device_info.get('device_type', 'unknown'),
                        confidence_score=device_info.get('confidence_score', 0.0)
                    )
                    
                    # Set complex fields
                    if device_info.get('open_ports'):
                        new_device.open_ports_list = device_info['open_ports']
                    if device_info.get('protocols'):
                        new_device.protocols_list = device_info['protocols']
                    if device_info.get('services'):
                        new_device.services_dict = device_info['services']
                    
                    db.session.add(new_device)
                    saved_count += 1
                
            except Exception as e:
                logger.error(f"Error saving device {device_info.get('ip_address')}: {str(e)}")
                continue
        
        try:
            db.session.commit()
            logger.info(f"Saved {saved_count} new devices, updated {updated_count} existing devices")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to commit device changes: {str(e)}")
            raise
    
    def rescan_device(self, device_id: int) -> Dict[str, Any]:
        """Rescan a specific device."""
        device = Device.query.get(device_id)
        if not device:
            raise ValueError(f"Device with ID {device_id} not found")
        
        logger.info(f"Rescanning device {device.ip_address}")
        
        try:
            # Scan single host
            self.scanner.nm.scan(device.ip_address, arguments='-sS -p 1-1000')
            
            if device.ip_address in self.scanner.nm.all_hosts():
                device_info = self.scanner._analyze_host(device.ip_address)
                
                if device_info:
                    # Enhance with fingerprinting
                    device_info = self.fingerprinter.fingerprint_device(device_info)
                    
                    # Update device in database
                    self._save_discovered_devices([device_info])
                    
                    return device_info
                else:
                    # Device is offline
                    device.mark_inactive()
                    return {'status': 'offline', 'ip_address': device.ip_address}
            else:
                device.mark_inactive()
                return {'status': 'offline', 'ip_address': device.ip_address}
                
        except Exception as e:
            logger.error(f"Failed to rescan device {device.ip_address}: {str(e)}")
            raise
    
    def cleanup_stale_devices(self, days: int = 7):
        """Mark devices as inactive if not seen for specified days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        stale_devices = Device.query.filter(
            Device.last_seen < cutoff_date,
            Device.is_active == True
        ).all()
        
        for device in stale_devices:
            device.mark_inactive()
        
        db.session.commit()
        
        logger.info(f"Marked {len(stale_devices)} devices as inactive")
        return len(stale_devices)
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """Get device discovery statistics."""
        total_devices = Device.query.count()
        active_devices = Device.query.filter_by(is_active=True).count()
        
        # Device type distribution
        device_types = db.session.query(
            Device.device_type,
            db.func.count(Device.id)
        ).filter(Device.is_active == True).group_by(Device.device_type).all()
        
        # Manufacturer distribution
        manufacturers = db.session.query(
            Device.manufacturer,
            db.func.count(Device.id)
        ).filter(
            Device.is_active == True,
            Device.manufacturer.isnot(None)
        ).group_by(Device.manufacturer).all()
        
        # Recent discoveries (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_discoveries = Device.query.filter(
            Device.created_at >= yesterday
        ).count()
        
        return {
            'total_devices': total_devices,
            'active_devices': active_devices,
            'inactive_devices': total_devices - active_devices,
            'recent_discoveries': recent_discoveries,
            'device_types': dict(device_types),
            'manufacturers': dict(manufacturers)
        }
    
    def schedule_network_scan(self, network_range: str, scan_type: str = 'tcp_connect',
                            interval_hours: int = 24) -> Dict[str, Any]:
        """Schedule periodic network scanning."""
        # This would integrate with Celery for background tasks
        # For now, return configuration that could be used by a scheduler
        
        scan_config = {
            'network_range': network_range,
            'scan_type': scan_type,
            'interval_hours': interval_hours,
            'next_scan': datetime.utcnow() + timedelta(hours=interval_hours),
            'enabled': True
        }
        
        logger.info(f"Scheduled network scan for {network_range} every {interval_hours} hours")
        return scan_config
    
    def export_devices(self, format: str = 'json', active_only: bool = True) -> str:
        """Export device list in specified format."""
        query = Device.query
        
        if active_only:
            query = query.filter_by(is_active=True)
        
        devices = query.all()
        
        if format.lower() == 'json':
            import json
            device_data = [device.to_dict() for device in devices]
            return json.dumps(device_data, indent=2, default=str)
        
        elif format.lower() == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                'IP Address', 'Hostname', 'MAC Address', 'Manufacturer', 
                'Device Type', 'Model', 'Open Ports', 'Last Seen', 'Risk Level'
            ])
            
            # Data rows
            for device in devices:
                writer.writerow([
                    device.ip_address,
                    device.hostname or '',
                    device.mac_address or '',
                    device.manufacturer or '',
                    device.device_type or '',
                    device.model or '',
                    ','.join(map(str, device.open_ports_list)),
                    device.last_seen.isoformat() if device.last_seen else '',
                    device.risk_level or ''
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported export format: {format}")

# Background task functions (for Celery integration)
def periodic_network_scan(network_range: str, scan_type: str = 'tcp_connect'):
    """Background task for periodic network scanning."""
    discovery_service = DeviceDiscoveryService()
    
    try:
        devices = discovery_service.discover_devices(network_range, scan_type)
        logger.info(f"Periodic scan completed. Found {len(devices)} devices")
        return len(devices)
    except Exception as e:
        logger.error(f"Periodic scan failed: {str(e)}")
        raise

def cleanup_stale_devices_task(days: int = 7):
    """Background task for cleaning up stale devices."""
    discovery_service = DeviceDiscoveryService()
    
    try:
        count = discovery_service.cleanup_stale_devices(days)
        logger.info(f"Cleanup task completed. Marked {count} devices as inactive")
        return count
    except Exception as e:
        logger.error(f"Cleanup task failed: {str(e)}")
        raise
