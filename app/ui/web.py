from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional, List
import logging

from app.api.routes import router as api_router
from app.core.orchestrator import orchestrator
from app.core.config import settings

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Security Testing Framework Web Interface"
)

# Setup templates and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include API routes
app.include_router(api_router)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page"""
    try:
        # Get recent scans for dashboard
        recent_scans = orchestrator.get_all_scans()
        recent_scans = sorted(
            recent_scans,
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )[:5]
        
        # Calculate stats
        total_scans = len(orchestrator.get_all_scans())
        active_scans = len([s for s in orchestrator.get_all_scans() if s['status'] == 'running'])
        completed_scans = len([s for s in orchestrator.get_all_scans() if s['status'] == 'completed'])
        
        stats = {
            'total_scans': total_scans,
            'active_scans': active_scans,
            'completed_scans': completed_scans,
            'success_rate': round((completed_scans / total_scans * 100) if total_scans > 0 else 0, 1)
        }
        
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "recent_scans": recent_scans,
                "stats": stats,
                "owasp_categories": settings.OWASP_CATEGORIES
            }
        )
    except Exception as e:
        logger.error(f"Error loading home page: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """Scan configuration page"""
    return templates.TemplateResponse(
        "scan.html",
        {
            "request": request,
            "available_scanners": ["zap", "nuclei", "nikto"]
        }
    )

@app.post("/scan")
async def start_web_scan(
    request: Request,
    target_url: str = Form(...),
    scanners: Optional[List[str]] = Form(default=["zap", "nuclei", "nikto"])
):
    """Start a new scan from web interface"""
    try:
        if isinstance(scanners, str):
            scanners = [scanners]
        
        scan_id = await orchestrator.start_scan(target_url, scanners)
        
        # Redirect to scan status page
        return RedirectResponse(
            url=f"/scan/{scan_id}",
            status_code=303
        )
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return templates.TemplateResponse(
            "scan.html",
            {
                "request": request,
                "error": f"Failed to start scan: {str(e)}",
                "available_scanners": ["zap", "nuclei", "nikto"]
            }
        )

@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_status_page(request: Request, scan_id: str):
    """Scan status and results page"""
    try:
        scan_info = orchestrator.get_scan_status(scan_id)
        
        if not scan_info:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Prepare vulnerability summary for display
        vuln_summary = {}
        if scan_info.get('results'):
            for scanner_name, scanner_results in scan_info['results'].items():
                if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                    vulns = scanner_results['vulnerabilities']
                    vuln_summary[scanner_name] = {
                        'total': len(vulns),
                        'high': len([v for v in vulns if v.get('severity') == 'high']),
                        'medium': len([v for v in vulns if v.get('severity') == 'medium']),
                        'low': len([v for v in vulns if v.get('severity') == 'low']),
                        'info': len([v for v in vulns if v.get('severity') == 'info'])
                    }
        
        return templates.TemplateResponse(
            "scan_status.html",
            {
                "request": request,
                "scan": scan_info,
                "vuln_summary": vuln_summary
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading scan status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/scans", response_class=HTMLResponse)
async def scans_list_page(request: Request, status: Optional[str] = None):
    """List all scans page"""
    try:
        all_scans = orchestrator.get_all_scans()
        
        # Filter by status if specified
        if status:
            all_scans = [s for s in all_scans if s.get('status') == status]
        
        # Sort by created_at descending
        sorted_scans = sorted(
            all_scans,
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )
        
        return templates.TemplateResponse(
            "scans_list.html",
            {
                "request": request,
                "scans": sorted_scans,
                "filter_status": status
            }
        )
    except Exception as e:
        logger.error(f"Error loading scans list: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def view_report(request: Request, scan_id: str):
    """View scan report"""
    try:
        scan_info = orchestrator.get_scan_status(scan_id)
        
        if not scan_info:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan_info['status'] != 'completed':
            raise HTTPException(status_code=400, detail="Scan not completed yet")
        
        # Group vulnerabilities by OWASP category
        vulnerabilities_by_category = {}
        
        # Initialize all OWASP categories
        for category in settings.OWASP_CATEGORIES:
            vulnerabilities_by_category[category] = []
        vulnerabilities_by_category['Other'] = []
        
        # Group vulnerabilities
        results = scan_info.get('results', {})
        for scanner_name, scanner_results in results.items():
            if isinstance(scanner_results, dict) and 'vulnerabilities' in scanner_results:
                for vuln in scanner_results['vulnerabilities']:
                    category = vuln.get('owasp_category', 'Other')
                    vuln_with_scanner = vuln.copy()
                    vuln_with_scanner['scanner'] = scanner_name
                    
                    if category in vulnerabilities_by_category:
                        vulnerabilities_by_category[category].append(vuln_with_scanner)
                    else:
                        vulnerabilities_by_category['Other'].append(vuln_with_scanner)
        
        # Remove empty categories
        vulnerabilities_by_category = {
            k: v for k, v in vulnerabilities_by_category.items() if v
        }
        
        # Calculate overall statistics
        total_vulns = sum(len(vulns) for vulns in vulnerabilities_by_category.values())
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vulns in vulnerabilities_by_category.values():
            for vuln in vulns:
                severity = vuln.get('severity', 'info')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return templates.TemplateResponse(
            "report.html",
            {
                "request": request,
                "scan": scan_info,
                "vulnerabilities_by_category": vulnerabilities_by_category,
                "total_vulnerabilities": total_vulns,
                "severity_counts": severity_counts,
                "owasp_categories": settings.OWASP_CATEGORIES
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading report: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.delete("/scan/{scan_id}")
async def delete_web_scan(scan_id: str):
    """Delete a scan"""
    try:
        success = orchestrator.delete_scan(scan_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return {"message": f"Scan {scan_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting scan: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 errors"""
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "error_code": 404,
            "error_message": "Page not found"
        },
        status_code=404
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    """Handle 500 errors"""
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "error_code": 500,
            "error_message": "Internal server error"
        },
        status_code=500
    )

# WebSocket endpoint for real-time scan updates
from fastapi import WebSocket, WebSocketDisconnect
import json
import asyncio

@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates"""
    await websocket.accept()
    
    try:
        while True:
            scan_info = orchestrator.get_scan_status(scan_id)
            
            if scan_info:
                await websocket.send_text(json.dumps({
                    'status': scan_info['status'],
                    'progress': scan_info.get('progress', 0),
                    'errors': scan_info.get('errors', [])
                }))
                
                # Stop sending updates if scan is complete or failed
                if scan_info['status'] in ['completed', 'failed']:
                    break
            
            await asyncio.sleep(2)  # Update every 2 seconds
            
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT)