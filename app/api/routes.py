from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime
import os

from app.core.orchestrator import orchestrator
from app.report.generator import ReportGenerator
from app.core.config import settings

logger = logging.getLogger(__name__)

# Pydantic models
class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_types: Optional[List[str]] = ["zap", "nuclei", "nikto"]
    options: Optional[Dict[str, Any]] = {}

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class ScanStatusResponse(BaseModel):
    id: str
    target_url: str
    scan_types: List[str]
    status: str
    created_at: str
    updated_at: str
    progress: int
    results: Dict = {}
    errors: List[str] = []

# Initialize router
router = APIRouter(prefix="/api", tags=["security-testing"])

# MANDATORY API ENDPOINTS - NO MODIFICATIONS ALLOWED

@router.post("/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest):
    """Start a new security scan"""
    try:
        logger.info(f"Starting scan for {scan_request.target_url}")
        
        scan_id = await orchestrator.start_scan(
            target_url=str(scan_request.target_url),
            scan_types=scan_request.scan_types,
            options=scan_request.options
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Scan started successfully with ID: {scan_id}"
        )
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get status of a specific scan"""
    try:
        scan_info = orchestrator.get_scan_status(scan_id)
        
        if not scan_info:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanStatusResponse(**scan_info)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")

@router.get("/report/{scan_id}")
async def get_scan_report(scan_id: str, format: str = "html"):
    """Get scan report in specified format"""
    try:
        scan_info = orchestrator.get_scan_status(scan_id)
        
        if not scan_info:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan_info['status'] != 'completed':
            raise HTTPException(status_code=400, detail="Scan not completed yet")
        
        # Generate report
        report_generator = ReportGenerator()
        
        if format.lower() == "html":
            report_path = await report_generator.generate_html_report(
                scan_id=scan_id,
                scan_data=scan_info
            )
            return FileResponse(
                path=report_path,
                media_type="text/html",
                filename=f"security_report_{scan_id}.html"
            )
        elif format.lower() == "json":
            return scan_info
        elif format.lower() == "pdf":
            report_path = await report_generator.generate_pdf_report(
                scan_id=scan_id,
                scan_data=scan_info
            )
            return FileResponse(
                path=report_path,
                media_type="application/pdf",
                filename=f"security_report_{scan_id}.pdf"
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use html, json, or pdf")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

@router.get("/scans")
async def get_all_scans(limit: int = 50, offset: int = 0):
    """Get all scans with pagination"""
    try:
        all_scans = orchestrator.get_all_scans()
        
        # Sort by created_at descending
        sorted_scans = sorted(
            all_scans, 
            key=lambda x: x.get('created_at', ''), 
            reverse=True
        )
        
        # Apply pagination
        paginated_scans = sorted_scans[offset:offset + limit]
        
        return {
            "scans": paginated_scans,
            "total": len(all_scans),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Failed to get scans: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get scans: {str(e)}")

# Additional utility endpoints
@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan"""
    try:
        success = orchestrator.delete_scan(scan_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {"message": f"Scan {scan_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "active_scans": len([s for s in orchestrator.get_all_scans() if s['status'] == 'running'])
    }

@router.get("/scanners")
async def get_scanner_info():
    """Get information about available scanners"""
    return {
        "scanners": {
            "zap": {
                "name": "OWASP ZAP",
                "description": "Web Application Security Scanner",
                "version": "2.12.0"
            },
            "nuclei": {
                "name": "Nuclei",
                "description": "Vulnerability Scanner",
                "version": "2.9.4"
            },
            "nikto": {
                "name": "Nikto",
                "description": "Web Server Scanner",
                "version": "2.1.6"
            }
        }
    }

@router.get("/owasp-categories")
async def get_owasp_categories():
    """Get OWASP Top 10 categories"""
    return {
        "categories": settings.OWASP_CATEGORIES,
        "version": "2021"
    }