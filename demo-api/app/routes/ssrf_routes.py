"""SSRF (Server-Side Request Forgery) testing routes."""

from fastapi import APIRouter, HTTPException, Request
import httpx
from app.utils import add_response_metadata, is_internal_ip

router = APIRouter()

# 🔴 VULNERABLE: SSRF without validation
@router.get("/fetch/vulnerable")
async def ssrf_vulnerable(request: Request, url: str):
    """
    🔴 VULNERABLE: Fetch URL without validation.
    
    SSRF vulnerability - can access internal services.
    
    Test payloads:
    - url=http://localhost:8000/internal/metadata
    - url=http://127.0.0.1:8000/internal/admin
    - url=http://169.254.169.254/latest/meta-data/
    - url=http://metadata.google.internal/computeMetadata/v1/
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            
            return add_response_metadata({
                "url": url,
                "status_code": response.status_code,
                "content": response.text[:1000],  # Limit response size
                "headers": dict(response.headers)
            }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {str(e)}")

# 🟢 SECURE: SSRF with validation
@router.get("/fetch/secure")
async def ssrf_secure(request: Request, url: str):
    """
    🟢 SECURE: Fetch URL with internal IP blocking.
    
    Blocks access to internal/private IPs.
    """
    # Validate URL
    if is_internal_ip(url):
        raise HTTPException(
            status_code=400,
            detail="Access to internal/private IPs is not allowed"
        )
    
    # Additional validation
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL scheme")
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            
            return add_response_metadata({
                "url": url,
                "status_code": response.status_code,
                "content": response.text[:1000]
            }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {str(e)}")

# Webhook endpoint (SSRF target)
@router.post("/webhook")
async def webhook(request: Request, callback_url: str, data: dict):
    """
    🔴 VULNERABLE: Webhook with SSRF.
    
    Sends data to callback URL without validation.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(callback_url, json=data)
            
            return add_response_metadata({
                "message": "Webhook sent",
                "callback_url": callback_url,
                "status_code": response.status_code
            }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Webhook error: {str(e)}")
