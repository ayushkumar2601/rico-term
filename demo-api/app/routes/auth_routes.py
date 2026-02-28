"""Authentication routes."""

from fastapi import APIRouter, HTTPException, Request
from app.models import LoginRequest, LoginResponse
from app.security import authenticate_user, create_jwt_token
from app.utils import add_response_metadata

router = APIRouter()

@router.post("/login", response_model=LoginResponse)
async def login(request: Request, credentials: LoginRequest):
    """
    🟢 SECURE: User login endpoint.
    
    Returns JWT token for authenticated users.
    
    Test credentials:
    - alice / password123 (user)
    - bob / password456 (user)
    - admin / admin123 (admin)
    """
    user = authenticate_user(credentials.username, credentials.password)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(
        username=user["username"],
        role=user["role"],
        user_id=user["id"]
    )
    
    response_data = {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }
    
    return add_response_metadata(response_data, request.state.request_id)

@router.post("/register")
async def register(request: Request, credentials: LoginRequest):
    """
    User registration endpoint (simplified for testing).
    """
    # Simplified registration - just return success
    return add_response_metadata({
        "message": "Registration successful",
        "username": credentials.username
    }, request.state.request_id)
