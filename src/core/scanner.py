"""Core scanning orchestrator"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum
import logging

from src.scanners.zap import ZAPScanner
from src.scanners.nuclei import NucleiScanner
from src.scanners.nikto import NiktoScanner
from src.core.config import settings

logger = logging.getLogger(__name__)

class ScanStatus(Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanOrchestrator:
    """Manages security scans across multiple tools"""
    
    def __init__(self):
        self.scans: Dict[str, Dict] = {}
        self.scanners = {
            'zap': ZAPScanner(),
            'nuclei': NucleiScanner(),
            'nikto': NiktoScanner()
        }
        self._scan_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)
    
    async def start_scan(self, target_url: str, scan_types: List[str] = None) -> str:
        """Start a new security scan"""
        scan_id = str(uuid.uuid4())
        
        if scan_types is None:
            scan_types = ['zap', 'nuclei', 'nikto']
            
        scan_info = {
            'id': scan_id,
            'target_url': target_url,
            'scan_types': scan_types,
            'status': ScanStatus.PENDING.value,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'results': {},
            'errors': [],
            'progress': 0
        }
        
        self.scans[scan_id] = scan_info
        
        # Start scan asynchronously
        asyncio.create_task(self._execute_scan(scan_id, target_url, scan_types))
        
        return scan_id
    
    async def _execute_scan(self, scan_id: str, target_url: str, scan_types: List[str]):
        """Execute the scan"""
        async with self._scan_semaphore:
            scan_info = self.scans[scan_id]
            
            try:
                scan_info['status'] = ScanStatus.RUNNING.value
                scan_info['updated_at'] = datetime.utcnow().isoformat()
                
                logger.info(f"Starting scan {scan_id} for {target_url}")
                
                results = {}
                total_tasks = len(scan_types)
                completed_tasks = 0
                
                for scan_type in scan_types:
                    if scan_type in self.scanners:
                        try:
                            scanner = self.scanners[scan_type]
                            raw_result = await asyncio.wait_for(
                                scanner.scan(target_url), 
                                timeout=settings.SCAN_TIMEOUT
                            )
                            result = await scanner.parse_results(raw_result)
                            results[scan_type] = result
                            
                            completed_tasks += 1
                            scan_info['progress'] = int((completed_tasks / total_tasks) * 100)
                            logger.info(f"Completed {scan_type} scan for {scan_id}")
                            
                        except asyncio.TimeoutError:
                            error_msg = f"{scan_type} scan timed out"
                            scan_info['errors'].append(error_msg)
                            logger.error(error_msg)
                        except Exception as e:
                            error_msg = f"{scan_type} scan failed: {str(e)}"
                            scan_info['errors'].append(error_msg)
                            logger.error(error_msg)
                
                scan_info['results'] = results
                scan_info['status'] = ScanStatus.COMPLETED.value
                scan_info['progress'] = 100
                scan_info['completed_at'] = datetime.utcnow().isoformat()
                
                logger.info(f"Completed scan {scan_id}")
                
            except Exception as e:
                scan_info['status'] = ScanStatus.FAILED.value
                scan_info['errors'].append(f"Scan execution failed: {str(e)}")
                logger.error(f"Scan {scan_id} failed: {str(e)}")
            
            finally:
                scan_info['updated_at'] = datetime.utcnow().isoformat()
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID"""
        return self.scans.get(scan_id)
    
    def get_all_scans(self) -> List[Dict]:
        """Get all scans"""
        return list(self.scans.values())
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan"""
        if scan_id in self.scans:
            del self.scans[scan_id]
            return True
        return False

# Global orchestrator instance
orchestrator = ScanOrchestrator()