"""
RICO FastAPI Backend

Production-ready web API for RICO security scanning.
Deployable on Render and other cloud platforms.
"""

import os
import uuid
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import asyncio

from fastapi import FastAPI, File, UploadFile, Form, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl

# In-memory storage for scan results (replace with Redis/DB in production)
SCAN_STORAGE: Dict[str, Dict[str, Any]] = {}
MAX_STORED_SCANS = 100  # Limit to prevent memory exhaustion
MAX_CONCURRENT_SCANS = 5  # Limit concurrent background scans


# Pydantic models
class ScanRequest(BaseModel):
    """Scan request model for JSON body."""
    spec_url: Optional[str] = None
    base_url: str
    token: Optional[str] = None
    max_endpoints: Optional[int] = None
    use_ai: bool = False
    use_agentic_ai: bool = False


class ScanResponse(BaseModel):
    """Scan initiation response."""
    scan_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    """Scan status response."""
    scan_id: str
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    timestamp: str


# Initialize semaphore for concurrent scan limiting
_scan_semaphore = None


def get_scan_semaphore():
    """Get or create scan semaphore."""
    global _scan_semaphore
    if _scan_semaphore is None:
        _scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
    return _scan_semaphore


# Initialize FastAPI app
app = FastAPI(
    title="RICO Security Scanner API",
    description="AI-powered API security testing platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def run_scan_background(
    scan_id: str,
    spec_path: str,
    base_url: str,
    token: Optional[str],
    max_endpoints: Optional[int],
    use_ai: bool,
    use_agentic_ai: bool,
    temp_dir: str
):
    """
    Background task to run security scan.
    
    Args:
        scan_id: Unique scan identifier
        spec_path: Path to OpenAPI spec file
        base_url: Target API base URL
        token: Optional authentication token
        max_endpoints: Maximum endpoints to test
        use_ai: Enable AI-powered testing
        use_agentic_ai: Enable agentic AI analysis
        temp_dir: Temporary directory for reports
    """
    from rico.services.scan_service import run_scan
    
    # Acquire semaphore to limit concurrent scans
    semaphore = get_scan_semaphore()
    async with semaphore:
        try:
        # Update status to running
        SCAN_STORAGE[scan_id]["status"] = "running"
        SCAN_STORAGE[scan_id]["started_at"] = datetime.utcnow().isoformat()
        
        # Prepare report formats
        report_dir = Path(temp_dir) / scan_id
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_formats = {
            "json": str(report_dir / "report.json"),
            "html": str(report_dir / "report.html"),
            "md": str(report_dir / "report.md")
        }
        
        # Run scan
        result = run_scan(
            spec_path=spec_path,
            base_url=base_url,
            token=token,
            max_endpoints=max_endpoints,
            use_ai=use_ai,
            use_agentic_ai=use_agentic_ai,
            output_dir=str(report_dir),
            report_formats=report_formats
        )
        
            # Store result
            SCAN_STORAGE[scan_id]["status"] = "completed"
            SCAN_STORAGE[scan_id]["result"] = result
            SCAN_STORAGE[scan_id]["completed_at"] = datetime.utcnow().isoformat()
            SCAN_STORAGE[scan_id]["report_dir"] = str(report_dir)
            
        except Exception as e:
            # Store error
            SCAN_STORAGE[scan_id]["status"] = "failed"
            SCAN_STORAGE[scan_id]["error"] = str(e)
            SCAN_STORAGE[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        
        finally:
            # Clean up spec file
            try:
                if os.path.exists(spec_path):
                    os.remove(spec_path)
            except:
                pass
            
            # Cleanup old scans if storage exceeds limit
            _cleanup_old_scans()


def _cleanup_old_scans():
    """Remove oldest scans if storage exceeds limit."""
    if len(SCAN_STORAGE) > MAX_STORED_SCANS:
        # Sort by creation time and remove oldest
        sorted_scans = sorted(
            SCAN_STORAGE.items(),
            key=lambda x: x[1].get("created_at", ""),
        )
        
        # Remove oldest scans
        num_to_remove = len(SCAN_STORAGE) - MAX_STORED_SCANS
        for scan_id, scan_data in sorted_scans[:num_to_remove]:
            # Clean up report directory if exists
            if "report_dir" in scan_data:
                report_dir = Path(scan_data["report_dir"])
                if report_dir.exists():
                    import shutil
                    try:
                        shutil.rmtree(report_dir)
                    except:
                        pass
            
            # Remove from storage
            del SCAN_STORAGE[scan_id]


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint."""
    return {
        "message": "RICO Security Scanner API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns service status and version information.
    """
    return HealthResponse(
        status="ok",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat()
    )


@app.post("/scan", response_model=ScanResponse)
async def create_scan(
    background_tasks: BackgroundTasks,
    spec_file: UploadFile = File(..., description="OpenAPI specification file (YAML/JSON)"),
    base_url: str = Form(..., description="Base URL of the API to test"),
    token: Optional[str] = Form(None, description="Optional authentication token"),
    max_endpoints: Optional[int] = Form(None, description="Maximum endpoints to test"),
    use_ai: bool = Form(False, description="Enable AI-powered attack planning"),
    use_agentic_ai: bool = Form(False, description="Enable agentic AI reasoning")
):
    """
    Initiate a new security scan.
    
    Accepts an OpenAPI specification file and configuration parameters.
    Returns a scan ID that can be used to check scan status.
    
    The scan runs asynchronously in the background.
    """
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Create temporary directory for this scan
    temp_dir = tempfile.gettempdir()
    scan_temp_dir = Path(temp_dir) / "rico_scans"
    scan_temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Save uploaded spec file
    spec_filename = f"{scan_id}_{spec_file.filename}"
    spec_path = scan_temp_dir / spec_filename
    
    try:
        # Write uploaded file
        content = await spec_file.read()
        with open(spec_path, "wb") as f:
            f.write(content)
        
        # Initialize scan storage
        SCAN_STORAGE[scan_id] = {
            "status": "queued",
            "scan_id": scan_id,
            "base_url": base_url,
            "spec_filename": spec_file.filename,
            "created_at": datetime.utcnow().isoformat(),
            "result": None,
            "error": None
        }
        
        # Add background task
        background_tasks.add_task(
            run_scan_background,
            scan_id=scan_id,
            spec_path=str(spec_path),
            base_url=base_url,
            token=token,
            max_endpoints=max_endpoints,
            use_ai=use_ai,
            use_agentic_ai=use_agentic_ai,
            temp_dir=str(scan_temp_dir)
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Scan initiated successfully. Use GET /scan/{scan_id} to check status."
        )
    
    except Exception as e:
        # Clean up on error
        if spec_path.exists():
            spec_path.unlink()
        
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initiate scan: {str(e)}"
        )


@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """
    Get scan status and results.
    
    Returns the current status of a scan. If completed, includes full results.
    
    Status values:
    - queued: Scan is waiting to start
    - running: Scan is in progress
    - completed: Scan finished successfully
    - failed: Scan encountered an error
    """
    if scan_id not in SCAN_STORAGE:
        raise HTTPException(
            status_code=404,
            detail=f"Scan ID not found: {scan_id}"
        )
    
    scan_data = SCAN_STORAGE[scan_id]
    
    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan_data["status"],
        result=scan_data.get("result"),
        error=scan_data.get("error")
    )


@app.get("/scans", response_model=Dict[str, Any])
async def list_scans(limit: int = 10, offset: int = 0):
    """
    List all scans.
    
    Returns a paginated list of all scans with their current status.
    """
    scans = list(SCAN_STORAGE.values())
    
    # Sort by creation time (newest first)
    scans.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    
    # Paginate
    total = len(scans)
    scans_page = scans[offset:offset + limit]
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": scans_page
    }


@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete a scan and its results.
    
    Removes scan data from storage and cleans up associated files.
    """
    if scan_id not in SCAN_STORAGE:
        raise HTTPException(
            status_code=404,
            detail=f"Scan ID not found: {scan_id}"
        )
    
    scan_data = SCAN_STORAGE[scan_id]
    
    # Clean up report directory if it exists
    if "report_dir" in scan_data:
        report_dir = Path(scan_data["report_dir"])
        if report_dir.exists():
            import shutil
            try:
                shutil.rmtree(report_dir)
            except:
                pass
    
    # Remove from storage
    del SCAN_STORAGE[scan_id]
    
    return {"message": f"Scan {scan_id} deleted successfully"}


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found"}
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    """Handle 500 errors."""
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    port = int(os.getenv("PORT", 10000))
    print("🚀 RICO Security Scanner API starting...")
    print(f"📚 API Documentation: http://0.0.0.0:{port}/docs")
    print(f"🏥 Health Check: http://0.0.0.0:{port}/health")
    print(f"⚙️  Max concurrent scans: {MAX_CONCURRENT_SCANS}")
    print(f"💾 Max stored scans: {MAX_STORED_SCANS}")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("👋 RICO Security Scanner API shutting down...")


if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment (Render uses PORT env var)
    port = int(os.getenv("PORT", 10000))
    
    uvicorn.run(
        "rico.web.main:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )
