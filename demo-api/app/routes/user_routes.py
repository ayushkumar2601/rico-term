"""User management routes (IDOR testing)."""

from fastapi import APIRouter, HTTPException, Request, Depends
from app.database import get_user_by_id, get_order_by_id
from app.security import get_current_user
from app.utils import add_response_metadata

router = APIRouter()

# List all users (for testing) - Must be defined BEFORE /{user_id} to avoid conflicts
@router.get("/list")
async def list_users(request: Request):
    """
    List all users (public endpoint for testing).
    """
    from app.database import database
    
    users = [
        {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
        for user in database["users"].values()
    ]
    
    return add_response_metadata({"users": users}, request.state.request_id)

# 🔴 VULNERABLE: IDOR - No ownership check
@router.get("/{user_id}")
async def get_user_vulnerable(request: Request, user_id: int):
    """
    🔴 VULNERABLE: Get user by ID without authentication or authorization.
    
    IDOR vulnerability - any user can access any other user's data.
    Test with different user IDs: 1, 2, 3
    
    Examples:
    - GET /users/1 → Returns alice's data
    - GET /users/2 → Returns bob's data
    - GET /users/3 → Returns admin's data
    """
    user = get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Return sensitive data without checking ownership
    return add_response_metadata({
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "balance": user["balance"],  # Sensitive!
            "created_at": user["created_at"]
        }
    }, request.state.request_id)

# 🟢 SECURE: Proper authorization check
@router.get("/secure/{user_id}")
async def get_user_secure(
    request: Request,
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    🟢 SECURE: Get user by ID with proper authorization.
    
    Users can only access their own data unless they're admin.
    Requires valid JWT token.
    """
    user = get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check ownership or admin role
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    return add_response_metadata({
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "balance": user["balance"],
            "created_at": user["created_at"]
        }
    }, request.state.request_id)

# 🔴 VULNERABLE: Order IDOR
@router.get("/{user_id}/orders")
async def get_user_orders_vulnerable(request: Request, user_id: int):
    """
    🔴 VULNERABLE: Get user orders without authorization.
    
    IDOR vulnerability - any user can access any other user's orders.
    
    Examples:
    - GET /users/1/orders → Returns alice's orders
    - GET /users/2/orders → Returns bob's orders
    """
    from app.database import database
    
    # Get all orders for this user
    user_orders = [
        order for order in database["orders"].values()
        if order["user_id"] == user_id
    ]
    
    return add_response_metadata({
        "user_id": user_id,
        "orders": user_orders,
        "count": len(user_orders)
    }, request.state.request_id)

# 🟢 SECURE: Order with authorization
@router.get("/{user_id}/orders/secure")
async def get_user_orders_secure(
    request: Request,
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    """
    🟢 SECURE: Get user orders with proper authorization.
    
    Users can only access their own orders unless they're admin.
    Requires valid JWT token.
    """
    from app.database import database
    
    # Check ownership
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get all orders for this user
    user_orders = [
        order for order in database["orders"].values()
        if order["user_id"] == user_id
    ]
    
    return add_response_metadata({
        "user_id": user_id,
        "orders": user_orders,
        "count": len(user_orders)
    }, request.state.request_id)
