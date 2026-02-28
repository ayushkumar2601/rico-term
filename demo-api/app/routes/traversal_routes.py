"""Path Traversal testing routes."""

from fastapi import APIRouter, HTTPException, Request
from pathlib import Path
import os
from app.utils import add_response_metadata, sanitize_filename
from app.config import settings

router = APIRouter()

# 🔴 VULNERABLE: Path traversal
@router.get("/download/vulnerable")
async def download_vulnerable(request: Request, file: str):
    """
    🔴 VULNERABLE: File download with path traversal.
    
    No path sanitization - allows directory traversal.
    
    Test payloads:
    - file=config.json (normal)
    - file=../../../etc/passwd (traversal)
    - file=../../app/database.py (traversal)
    - file=secret.txt (sensitive file)
    """
    try:
        # Vulnerable - directly uses user input
        file_path = Path(settings.FILES_DIRECTORY) / file
        
        # Try to read file
        if file_path.exists():
            content = file_path.read_text()
            return add_response_metadata({
                "filename": file,
                "content": content,
                "size": len(content)
            }, request.state.request_id)
        else:
            raise HTTPException(status_code=404, detail="File not found")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# 🟢 SECURE: Path traversal protection
@router.get("/download/secure")
async def download_secure(request: Request, file: str):
    """
    🟢 SECURE: File download with path sanitization.
    
    Sanitizes filename to prevent traversal.
    """
    # Sanitize filename
    safe_filename = sanitize_filename(file)
    
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    try:
        file_path = Path(settings.FILES_DIRECTORY) / safe_filename
        
        # Ensure file is within allowed directory
        if not str(file_path.resolve()).startswith(str(Path(settings.FILES_DIRECTORY).resolve())):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if file_path.exists():
            content = file_path.read_text()
            return add_response_metadata({
                "filename": safe_filename,
                "content": content,
                "size": len(content)
            }, request.state.request_id)
        else:
            raise HTTPException(status_code=404, detail="File not found")
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# List available files
@router.get("/list")
async def list_files(request: Request):
    """
    List available files in the data directory.
    """
    try:
        files_dir = Path(settings.FILES_DIRECTORY)
        files = [f.name for f in files_dir.iterdir() if f.is_file()]
        
        return add_response_metadata({
            "files": files,
            "directory": settings.FILES_DIRECTORY
        }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# Read file with POST (vulnerable)
@router.post("/read/vulnerable")
async def read_file_vulnerable(request: Request, filepath: str):
    """
    🔴 VULNERABLE: Read file with POST request.
    
    Allows reading arbitrary files.
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        return add_response_metadata({
            "filepath": filepath,
            "content": content
        }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
