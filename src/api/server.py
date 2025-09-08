"""FastAPI server setup"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import router
from src.core.config import settings

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.VERSION,
        description="A comprehensive web security scanner",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include API routes
    app.include_router(router, prefix="/api")
    
    # Static files
    try:
        app.mount("/static", StaticFiles(directory="static"), name="static")
    except RuntimeError:
        pass  # Static directory doesn't exist
    
    return app