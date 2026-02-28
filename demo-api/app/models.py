"""Pydantic models for request/response validation."""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., example="alice")
    password: str = Field(..., example="password123")


class LoginResponse(BaseModel):
    """Login response model."""
    access_token: str
    token_type: str = "bearer"
    user: dict


class UserResponse(BaseModel):
    """User response model."""
    id: int
    username: str
    email: str
    role: str
    balance: float
    created_at: str


class OrderItem(BaseModel):
    """Order item model."""
    product_id: int = Field(..., example=101)
    quantity: int = Field(..., ge=1, example=2)
    price: Optional[float] = None


class CreateOrderRequest(BaseModel):
    """Create order request model."""
    user: dict = Field(..., example={"id": 1, "role": "user"})
    items: List[OrderItem]
    notes: Optional[str] = None


class TransferRequest(BaseModel):
    """Money transfer request model."""
    from_account: int = Field(..., example=1)
    to_account: int = Field(..., example=2)
    amount: float = Field(..., example=100.0)


class CommandRequest(BaseModel):
    """Command execution request model."""
    command: str = Field(..., example="echo hello")


class FetchURLRequest(BaseModel):
    """Fetch URL request model."""
    url: str = Field(..., example="https://example.com")
