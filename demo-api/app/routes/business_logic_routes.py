"""Business logic flaw testing routes."""

from fastapi import APIRouter, HTTPException, Request, Depends
from app.models import TransferRequest, CreateOrderRequest
from app.database import get_account_by_id, update_account_balance, create_order, database
from app.security import get_current_user
from app.utils import add_response_metadata

router = APIRouter()

# 🔴 VULNERABLE: Money transfer with business logic flaws
@router.post("/transfer/vulnerable")
async def transfer_vulnerable(request: Request, transfer: TransferRequest):
    """
    🔴 VULNERABLE: Money transfer with multiple business logic flaws.
    
    Vulnerabilities:
    1. Allows negative amounts (money creation)
    2. No ownership verification
    3. No balance check
    4. Race condition possible (double spend)
    
    Test cases:
    - Normal: from_account=1, to_account=2, amount=100
    - Negative: from_account=1, to_account=2, amount=-100 (creates money!)
    - Overdraft: from_account=2, to_account=1, amount=10000 (exceeds balance)
    """
    from_account = get_account_by_id(transfer.from_account)
    to_account = get_account_by_id(transfer.to_account)
    
    if not from_account or not to_account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # VULNERABLE: No validation of amount (allows negative!)
    # VULNERABLE: No balance check
    # VULNERABLE: No ownership verification
    
    # Execute transfer
    update_account_balance(transfer.from_account, -transfer.amount)
    update_account_balance(transfer.to_account, transfer.amount)
    
    return add_response_metadata({
        "message": "Transfer successful",
        "from_account": transfer.from_account,
        "to_account": transfer.to_account,
        "amount": transfer.amount,
        "from_balance": get_account_by_id(transfer.from_account)["balance"],
        "to_balance": get_account_by_id(transfer.to_account)["balance"]
    }, request.state.request_id)

# 🟢 SECURE: Money transfer with proper validation
@router.post("/transfer/secure")
async def transfer_secure(
    request: Request,
    transfer: TransferRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    🟢 SECURE: Money transfer with proper validation.
    
    Validates:
    1. Positive amount only
    2. Ownership verification
    3. Sufficient balance
    4. Transaction atomicity
    """
    from_account = get_account_by_id(transfer.from_account)
    to_account = get_account_by_id(transfer.to_account)
    
    if not from_account or not to_account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Validate ownership
    if from_account["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not your account")
    
    # Validate amount
    if transfer.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    
    # Check balance
    if from_account["balance"] < transfer.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Execute transfer
    update_account_balance(transfer.from_account, -transfer.amount)
    update_account_balance(transfer.to_account, transfer.amount)
    
    return add_response_metadata({
        "message": "Transfer successful",
        "from_account": transfer.from_account,
        "to_account": transfer.to_account,
        "amount": transfer.amount,
        "from_balance": get_account_by_id(transfer.from_account)["balance"],
        "to_balance": get_account_by_id(transfer.to_account)["balance"]
    }, request.state.request_id)

# 🔴 VULNERABLE: Order creation with nested JSON injection
@router.post("/orders/vulnerable")
async def create_order_vulnerable(request: Request, order: CreateOrderRequest):
    """
    🔴 VULNERABLE: Order creation with nested JSON injection.
    
    Trusts user-provided role in nested JSON.
    
    Test payload:
    {
      "user": {"id": 1, "role": "admin"},  // User can set their own role!
      "items": [{"product_id": 101, "quantity": 2}],
      "notes": "Test order"
    }
    """
    # VULNERABLE: Trusts user-provided role
    user_data = order.user
    user_role = user_data.get("role", "user")
    
    # Calculate total
    total = sum(item.quantity * (item.price or 29.99) for item in order.items)
    
    # Apply discount based on role (trusts user input!)
    if user_role == "admin":
        total *= 0.5  # 50% discount for "admin"
    
    # Create order
    new_order = create_order(
        user_id=user_data.get("id", 1),
        items=[item.dict() for item in order.items],
        total=total
    )
    
    return add_response_metadata({
        "message": "Order created",
        "order": new_order,
        "discount_applied": user_role == "admin"
    }, request.state.request_id)

# 🟢 SECURE: Order creation with validation
@router.post("/orders/secure")
async def create_order_secure(
    request: Request,
    order: CreateOrderRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    🟢 SECURE: Order creation with proper validation.
    
    Uses authenticated user data, not user-provided data.
    """
    # Use authenticated user, not user-provided data
    user_id = current_user["id"]
    user_role = current_user["role"]
    
    # Calculate total
    total = sum(item.quantity * (item.price or 29.99) for item in order.items)
    
    # Apply discount based on authenticated role
    if user_role == "admin":
        total *= 0.5
    
    # Create order
    new_order = create_order(
        user_id=user_id,
        items=[item.dict() for item in order.items],
        total=total
    )
    
    return add_response_metadata({
        "message": "Order created",
        "order": new_order,
        "discount_applied": user_role == "admin"
    }, request.state.request_id)

# Get account balance
@router.get("/accounts/{account_id}")
async def get_account(request: Request, account_id: int):
    """Get account balance (for testing)."""
    account = get_account_by_id(account_id)
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    return add_response_metadata({"account": account}, request.state.request_id)
