"""Web UI routes"""

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import List, Optional

from src.core.scanner import orchestrator
from src.core.config import settings

# Initialize templates
templates = Jinja2Templates(directory="templates")
router = APIRouter(tags=["web-ui"])

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page with scan form"""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "version": settings.VERSION
    })

@router.post("/scan", response_class=HTMLResponse)
async def create_scan(
    request: Request,
    target_url: str = Form(...),
    scan_zap: Optional[bool] = Form(False),
    scan_nuclei: Optional[bool] = Form(False),
    scan_nikto: Optional[bool] = Form(False)
):
    """Create new scan from web form"""
    try:
        # Determine scan types
        scan_types = []
        if scan_zap:
            scan_types.append("zap")
        if scan_nuclei:
            scan_types.append("nuclei")
        if scan_nikto:
            scan_types.append("nikto")
        
        if not scan_types:
            scan_types = ["zap", "nuclei", "nikto"]  # Default to all
        
        # Start scan
        scan_id = await orchestrator.start_scan(target_url, scan_types)
        
        return templates.TemplateResponse("scan_created.html", {
            "request": request,
            "scan_id": scan_id,
            "target_url": target_url,
            "scan_types": scan_types
        })
        
    except Exception as e:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "title": "Scan Creation Failed"
        })

@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_details(request: Request, scan_id: str):
    """Show scan details and results"""
    scan = orchestrator.get_scan(scan_id)
    
    if not scan:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Scan not found",
            "title": "Scan Not Found"
        })
    
    return templates.TemplateResponse("scan_details.html", {
        "request": request,
        "scan": scan
    })

@router.get("/scans", response_class=HTMLResponse)
async def scan_list(request: Request):
    """List all scans"""
    scans = orchestrator.get_all_scans()
    
    return templates.TemplateResponse("scan_list.html", {
        "request": request,
        "scans": scans
    })

@router.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    """About page"""
    return templates.TemplateResponse("about.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "version": settings.VERSION,
        "owasp_categories": settings.OWASP_CATEGORIES
    })