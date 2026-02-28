"""In-memory database simulation for testing."""

from typing import Dict, List, Optional
from datetime import datetime
import uuid

# In-memory database
database = {
    "users": {},
    "orders": {},
    "accounts": {},
    "products": {}
}

def init_database():
    """Initialize database with mock data."""
    
    # Users
    database["users"] = {
        1: {
            "id": 1,
            "username": "alice",
            "email": "alice@example.com",
            "password": "password123",  # Plain text for testing
            "role": "user",
            "balance": 1000.0,
            "created_at": "2024-01-01T00:00:00Z"
        },
        2: {
            "id": 2,
            "username": "bob",
            "email": "bob@example.com",
            "password": "password456",
            "role": "user",
            "balance": 500.0,
            "created_at": "2024-01-02T00:00:00Z"
        },
        3: {
            "id": 3,
            "username": "admin",
            "email": "admin@example.com",
            "password": "admin123",
            "role": "admin",
            "balance": 10000.0,
            "created_at": "2024-01-01T00:00:00Z"
        }
    }
    
    # Orders
    database["orders"] = {
        1: {
            "id": 1,
            "user_id": 1,
            "items": [
                {"product_id": 101, "quantity": 2, "price": 29.99},
                {"product_id": 102, "quantity": 1, "price": 49.99}
            ],
            "total": 109.97,
            "status": "completed",
            "created_at": "2024-01-15T10:30:00Z"
        },
        2: {
            "id": 2,
            "user_id": 2,
            "items": [
                {"product_id": 103, "quantity": 1, "price": 99.99}
            ],
            "total": 99.99,
            "status": "pending",
            "created_at": "2024-01-16T14:20:00Z"
        }
    }
    
    # Accounts (for business logic testing)
    database["accounts"] = {
        1: {"id": 1, "user_id": 1, "balance": 1000.0},
        2: {"id": 2, "user_id": 2, "balance": 500.0},
        3: {"id": 3, "user_id": 3, "balance": 10000.0}
    }
    
    # Products
    database["products"] = {
        101: {"id": 101, "name": "Widget A", "price": 29.99, "stock": 100},
        102: {"id": 102, "name": "Widget B", "price": 49.99, "stock": 50},
        103: {"id": 103, "name": "Widget C", "price": 99.99, "stock": 25}
    }

def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get user by ID."""
    return database["users"].get(user_id)

def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username."""
    for user in database["users"].values():
        if user["username"] == username:
            return user
    return None

def get_order_by_id(order_id: int) -> Optional[Dict]:
    """Get order by ID."""
    return database["orders"].get(order_id)

def get_account_by_id(account_id: int) -> Optional[Dict]:
    """Get account by ID."""
    return database["accounts"].get(account_id)

def create_order(user_id: int, items: List[Dict], total: float) -> Dict:
    """Create a new order."""
    order_id = max(database["orders"].keys()) + 1 if database["orders"] else 1
    order = {
        "id": order_id,
        "user_id": user_id,
        "items": items,
        "total": total,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat()
    }
    database["orders"][order_id] = order
    return order

def update_account_balance(account_id: int, amount: float) -> bool:
    """Update account balance."""
    if account_id in database["accounts"]:
        database["accounts"][account_id]["balance"] += amount
        return True
    return False

def execute_raw_query(query: str) -> List[Dict]:
    """
    Simulate SQL query execution (vulnerable to SQL injection).
    This is intentionally insecure for testing purposes.
    """
    query_lower = query.lower()
    
    # Simulate SQL injection detection
    if "union" in query_lower or "select" in query_lower:
        # Return simulated SQL error for error-based SQLi testing
        if "'" in query and ("or" in query_lower or "and" in query_lower):
            raise Exception("SQL syntax error: You have an error in your SQL syntax near 'OR 1=1'")
    
    # Simulate boolean-based blind SQLi
    if "and 1=1" in query_lower or "and '1'='1'" in query_lower:
        # TRUE condition - return normal data
        return list(database["users"].values())
    elif "and 1=2" in query_lower or "and '1'='2'" in query_lower:
        # FALSE condition - return empty
        return []
    
    # Normal query simulation
    if "select * from users where id" in query_lower:
        try:
            # Extract ID from query
            user_id = int(query.split("=")[-1].strip().strip("'\""))
            user = database["users"].get(user_id)
            return [user] if user else []
        except:
            return []
    
    return list(database["users"].values())

def execute_safe_query(user_id: int) -> Optional[Dict]:
    """
    Execute parameterized query (secure).
    This demonstrates proper SQL injection prevention.
    """
    return database["users"].get(user_id)
