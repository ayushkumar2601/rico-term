"""Security utilities including JWT handling."""

from datetime import datetime, timedelta
from typing import Optional, Dict
import jwt
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.database import get_user_by_username

security = HTTPBearer()

def create_jwt_token(username: str, role: str, user_id: int) -> str:
    """Create JWT token with user claims."""
    payload = {
        "sub": username,
        "role": role,
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token

def verify_jwt_token(token: str) -> Dict:
    """
    Verify JWT token (SECURE version).
    Properly validates signature and expiration.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def verify_jwt_token_vulnerable(token: str) -> Dict:
    """
    🔴 VULNERABLE: Verify JWT token without signature validation.
    This is intentionally insecure for testing JWT tampering.
    """
    try:
        # Decode without verification - VULNERABLE!
        payload = jwt.decode(
            token,
            options={"verify_signature": False}
        )
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token decode error: {str(e)}")

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict:
    """
    Get current user from JWT token (SECURE version).
    """
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    user = get_user_by_username(payload.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

def get_current_user_vulnerable(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict:
    """
    🔴 VULNERABLE: Get current user without proper token validation.
    """
    token = credentials.credentials
    payload = verify_jwt_token_vulnerable(token)
    
    # Trust the token claims without validation
    return {
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "user_id": payload.get("user_id")
    }

def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    """Require admin role (SECURE version)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def require_admin_vulnerable(user: Dict = Depends(get_current_user_vulnerable)) -> Dict:
    """
    🔴 VULNERABLE: Require admin role but trust unverified token.
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """Authenticate user with username and password."""
    user = get_user_by_username(username)
    if not user:
        return None
    
    # Simple password check (plain text for testing)
    if user["password"] == password:
        return user
    
    return None
