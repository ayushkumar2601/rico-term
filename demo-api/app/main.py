"""
RICO Security Testing Playground - Main Application

This is an intentionally vulnerable API for testing RICO's security scanning capabilities.
DO NOT deploy this in production. For testing purposes only.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import uuid
from datetime import datetime

from app.routes import (
    auth_routes,
    user_routes,
    sqli_routes,
    ssrf_routes,
    traversal_routes,
    command_routes,
    business_logic_routes,
    admin_routes
)
from app.config import settings
from app.database import init_database

# Initialize FastAPI app
app = FastAPI(
    title="RICO Security Testing Playground",
    description="Intentionally vulnerable API for security testing. DO NOT use in production.",
    version="1.0.0",
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

# Rate limiting storage
rate_limit_storage = {}

# Middleware for request logging and dynamic response fields
@app.middleware("http")
async def add_dynamic_fields(request: Request, call_next):
    """Add timestamp, request_id, and rate limiting to all responses."""
    
    # Rate limiting check
    client_ip = request.client.host
    current_time = time.time()
    
    # Clean old entries
    rate_limit_storage[client_ip] = [
        t for t in rate_limit_storage.get(client_ip, [])
        if current_time - t < 1.0
    ]
    
    # Check rate limit (5 requests per second)
    if len(rate_limit_storage.get(client_ip, [])) >= settings.RATE_LIMIT_PER_SECOND:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "message": f"Maximum {settings.RATE_LIMIT_PER_SECOND} requests per second",
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": str(uuid.uuid4())
            }
        )
    
    # Record request
    if client_ip not in rate_limit_storage:
        rate_limit_storage[client_ip] = []
    rate_limit_storage[client_ip].append(current_time)
    
    # Generate request ID
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Process request
    response = await call_next(request)
    
    # Add headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Timestamp"] = datetime.utcnow().isoformat()
    
    return response

# Include routers
app.include_router(auth_routes.router, prefix="/auth", tags=["Authentication"])
app.include_router(user_routes.router, prefix="/users", tags=["Users"])
app.include_router(sqli_routes.router, prefix="/sqli", tags=["SQL Injection Tests"])
app.include_router(ssrf_routes.router, prefix="/ssrf", tags=["SSRF Tests"])
app.include_router(traversal_routes.router, prefix="/files", tags=["Path Traversal Tests"])
app.include_router(command_routes.router, prefix="/cmd", tags=["Command Injection Tests"])
app.include_router(business_logic_routes.router, prefix="/business", tags=["Business Logic"])
app.include_router(admin_routes.router, prefix="/admin", tags=["Admin"])

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database with mock data."""
    init_database()
    print("✅ Database initialized")
    print("🔥 RICO Security Testing Playground started")
    print("⚠️  WARNING: This API contains intentional vulnerabilities")
    print("📚 Documentation: http://localhost:8000/docs")

# Root endpoint
@app.get("/", tags=["Health"])
async def root(request: Request):
    """Root endpoint with API information."""
    return {
        "message": "RICO Security Testing Playground",
        "version": "1.0.0",
        "warning": "This API contains intentional vulnerabilities for testing purposes",
        "documentation": "/docs",
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request.state.request_id
    }

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check(request: Request):
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request.state.request_id,
        "uptime": time.time()
    }

# Internal metadata endpoint (for SSRF testing)
@app.get("/internal/metadata", tags=["Internal"])
async def internal_metadata(request: Request):
    """Internal metadata endpoint (simulates cloud metadata service)."""
    return {
        "instance_id": "i-1234567890abcdef0",
        "instance_type": "t2.micro",
        "region": "us-east-1",
        "credentials": {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "token": "AQoDYXdzEJr...<truncated>...example"
        },
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request.state.request_id
    }

# Internal admin endpoint (for SSRF testing)
@app.get("/internal/admin", tags=["Internal"])
async def internal_admin(request: Request):
    """Internal admin endpoint (should not be accessible externally)."""
    return {
        "admin_panel": "enabled",
        "users": ["admin", "root", "system"],
        "database_password": "super_secret_password_123",
        "api_keys": ["sk-1234567890", "sk-0987654321"],
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request.state.request_id
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
