"""API routes for Security Testing Framework"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
import logging

from src.core.scanner import orchestrator
from src.core.config import settings

logger = logging.getLogger(__name__)

# Request/Response models
class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_types: Optional[List[str]] = ["zap", "nuclei", "nikto"]

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

# Initialize router
router = APIRouter(tags=["security-scanning"])

@router.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Start a new security scan"""
    try:
        logger.info(f"Starting scan for {request.target_url}")
        
        scan_id = await orchestrator.start_scan(
            target_url=str(request.target_url),
            scan_types=request.scan_types
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Scan started successfully with ID: {scan_id}"
        )
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status and results"""
    scan = orchestrator.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan

@router.get("/scans")
async def get_all_scans(limit: int = 50, offset: int = 0):
    """Get all scans with pagination"""
    all_scans = orchestrator.get_all_scans()
    
    # Simple pagination
    total = len(all_scans)
    scans = all_scans[offset:offset + limit]
    
    return {
        "scans": scans,
        "total": total,
        "limit": limit,
        "offset": offset
    }

@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan"""
    success = orchestrator.delete_scan(scan_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {"message": "Scan deleted successfully"}

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "active_scans": len([s for s in orchestrator.get_all_scans() if s['status'] == 'running'])
    }