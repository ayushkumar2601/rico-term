"""Admin routes for JWT tampering and privilege escalation testing."""

from fastapi import APIRouter, HTTPException, Request, Depends
from app.security import require_admin, require_admin_vulnerable, get_current_user
from app.database import database, get_user_by_id
from app.utils import add_response_metadata

router = APIRouter()

# 🔴 VULNERABLE: Admin endpoint with weak JWT validation
@router.get("/users/vulnerable")
async def list_users_vulnerable(
    request: Request,
    current_user: dict = Depends(require_admin_vulnerable)
):
    """
    🔴 VULNERABLE: List all users (admin only, but JWT not properly validated).
    
    JWT Tampering Test:
    1. Login as regular user (alice:password123)
    2. Modify JWT payload: change "role": "user" to "role": "admin"
    3. Use modified token (signature not validated!)
    4. Access admin endpoint
    
    Attack vector: JWT signature bypass
    """
    return add_response_metadata({
        "message": "Admin access granted",
        "users": list(database["users"].values()),
        "accessed_by": current_user["username"]
    }, request.state.request_id)

# 🟢 SECURE: Admin endpoint with proper JWT validation
@router.get("/users/secure")
async def list_users_secure(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """
    🟢 SECURE: List all users (admin only, JWT properly validated).
    
    Validates:
    1. JWT signature
    2. Token expiration
    3. User role from database (not token)
    """
    return add_response_metadata({
        "message": "Admin access granted",
        "users": list(database["users"].values()),
        "accessed_by": current_user["username"]
    }, request.state.request_id)

# 🔴 VULNERABLE: Delete user endpoint (no ownership check)
@router.delete("/users/{user_id}/vulnerable")
async def delete_user_vulnerable(
    request: Request,
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    🔴 VULNERABLE: Delete user without proper authorization check.
    
    Vulnerability: Any authenticated user can delete any user
    
    Test:
    1. Login as alice
    2. DELETE /admin/users/2/vulnerable (delete bob)
    3. Success! (should require admin role)
    """
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # VULNERABLE: No admin check!
    del database["users"][user_id]
    
    return add_response_metadata({
        "message": f"User {user_id} deleted",
        "deleted_by": current_user["username"]
    }, request.state.request_id)

# 🟢 SECURE: Delete user endpoint with proper authorization
@router.delete("/users/{user_id}/secure")
async def delete_user_secure(
    request: Request,
    user_id: int,
    current_user: dict = Depends(require_admin)
):
    """
    🟢 SECURE: Delete user with proper admin authorization.
    """
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deletion
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    del database["users"][user_id]
    
    return add_response_metadata({
        "message": f"User {user_id} deleted",
        "deleted_by": current_user["username"]
    }, request.state.request_id)

# 🔴 VULNERABLE: Promote user to admin (JWT alg=none bypass)
@router.post("/promote/{user_id}/vulnerable")
async def promote_user_vulnerable(request: Request, user_id: int):
    """
    🔴 VULNERABLE: Promote user to admin without authentication.
    
    JWT alg=none bypass test:
    1. Create JWT with alg=none in header
    2. Set payload: {"sub": "alice", "role": "admin"}
    3. No signature required
    4. Access this endpoint
    
    Attack vector: JWT algorithm confusion
    """
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # VULNERABLE: No authentication check!
    database["users"][user_id]["role"] = "admin"
    
    return add_response_metadata({
        "message": f"User {user_id} promoted to admin",
        "user": database["users"][user_id]
    }, request.state.request_id)

# 🟢 SECURE: Promote user with proper authorization
@router.post("/promote/{user_id}/secure")
async def promote_user_secure(
    request: Request,
    user_id: int,
    current_user: dict = Depends(require_admin)
):
    """
    🟢 SECURE: Promote user to admin with proper authorization.
    """
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    database["users"][user_id]["role"] = "admin"
    
    return add_response_metadata({
        "message": f"User {user_id} promoted to admin",
        "user": database["users"][user_id],
        "promoted_by": current_user["username"]
    }, request.state.request_id)

# System configuration endpoint (for testing)
@router.get("/config")
async def get_config(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Get system configuration (admin only)."""
    return add_response_metadata({
        "database_url": "postgresql://admin:secret@localhost:5432/prod",
        "api_keys": {
            "stripe": "sk_live_1234567890",
            "aws": "AKIAIOSFODNN7EXAMPLE"
        },
        "debug_mode": True,
        "secret_key": "super_secret_key_do_not_share"
    }, request.state.request_id)
