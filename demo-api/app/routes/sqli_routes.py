"""SQL Injection testing routes."""

from fastapi import APIRouter, HTTPException, Request
import time
from app.database import execute_raw_query, execute_safe_query
from app.utils import add_response_metadata

router = APIRouter()

# 🔴 VULNERABLE: Error-based SQL Injection
@router.get("/error-based")
async def sqli_error_based(request: Request, id: str = "1"):
    """
    🔴 VULNERABLE: Error-based SQL injection.
    
    Directly concatenates user input into SQL query.
    
    Test payloads:
    - id=1' OR '1'='1
    - id=1' UNION SELECT NULL--
    - id=1' AND 1=1--
    """
    try:
        # Vulnerable query construction
        query = f"SELECT * FROM users WHERE id = '{id}'"
        results = execute_raw_query(query)
        
        return add_response_metadata({
            "query": query,
            "results": results
        }, request.state.request_id)
    
    except Exception as e:
        # Return SQL error (helps attacker)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 🔴 VULNERABLE: Boolean-based Blind SQL Injection
@router.get("/boolean-blind")
async def sqli_boolean_blind(request: Request, id: str = "1"):
    """
    🔴 VULNERABLE: Boolean-based blind SQL injection.
    
    No error messages, but response differs based on TRUE/FALSE conditions.
    
    Test payloads:
    - id=1' AND 1=1-- (TRUE - returns data)
    - id=1' AND 1=2-- (FALSE - returns empty)
    - id=1' AND 'a'='a'-- (TRUE)
    - id=1' AND 'a'='b'-- (FALSE)
    """
    try:
        query = f"SELECT * FROM users WHERE id = '{id}'"
        results = execute_raw_query(query)
        
        # Different response based on query result
        if results:
            return add_response_metadata({
                "status": "success",
                "data": results,
                "count": len(results)
            }, request.state.request_id)
        else:
            return add_response_metadata({
                "status": "success",
                "data": [],
                "count": 0
            }, request.state.request_id)
    
    except Exception:
        # Suppress errors for blind SQLi
        return add_response_metadata({
            "status": "error",
            "data": [],
            "count": 0
        }, request.state.request_id)

# 🔴 VULNERABLE: Time-based Blind SQL Injection
@router.get("/time-based")
async def sqli_time_based(request: Request, id: str = "1"):
    """
    🔴 VULNERABLE: Time-based blind SQL injection.
    
    Simulates SLEEP() function for time-based detection.
    
    Test payloads:
    - id=1' AND SLEEP(5)-- (delays 5 seconds)
    - id=1' OR SLEEP(5)-- (delays 5 seconds)
    - id=1' WAITFOR DELAY '00:00:05'-- (MSSQL syntax)
    """
    try:
        # Simulate time-based SQLi
        query_lower = id.lower()
        
        # Check for SLEEP injection
        if "sleep(" in query_lower:
            # Extract sleep duration
            try:
                sleep_duration = int(query_lower.split("sleep(")[1].split(")")[0])
                sleep_duration = min(sleep_duration, 10)  # Cap at 10 seconds
                time.sleep(sleep_duration)
            except:
                time.sleep(5)  # Default 5 seconds
        
        # Check for WAITFOR DELAY
        elif "waitfor delay" in query_lower:
            time.sleep(5)
        
        query = f"SELECT * FROM users WHERE id = '{id}'"
        results = execute_raw_query(query)
        
        return add_response_metadata({
            "status": "success",
            "data": results
        }, request.state.request_id)
    
    except Exception:
        return add_response_metadata({
            "status": "error",
            "data": []
        }, request.state.request_id)

# 🟢 SECURE: Parameterized query
@router.get("/secure")
async def sqli_secure(request: Request, id: int = 1):
    """
    🟢 SECURE: Parameterized query prevents SQL injection.
    
    Uses type validation (int) and parameterized query.
    """
    user = execute_safe_query(id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return add_response_metadata({
        "status": "success",
        "data": user
    }, request.state.request_id)

# Search endpoint (vulnerable) - Enhanced for boolean-blind detection
@router.get("/search")
async def sqli_search(request: Request, name: str = ""):
    """
    🔴 VULNERABLE: Search users by name with SQL injection.
    
    This endpoint is designed for realistic SQLi testing:
    - Error-based: Returns SQL errors
    - Boolean-blind: Different responses for TRUE/FALSE conditions
    - Response inference: Content changes based on query result
    
    Test payloads:
    - name=alice → Returns alice
    - name=alice' OR '1'='1 → Returns all users (TRUE condition)
    - name=alice' AND '1'='2 → Returns empty (FALSE condition)
    - name=alice' AND 1=1-- → Returns alice (TRUE)
    - name=alice' AND 1=2-- → Returns empty (FALSE)
    - name=' UNION SELECT * FROM users-- → SQL error
    """
    try:
        from app.database import database
        
        # Vulnerable query construction
        sql_query = f"SELECT * FROM users WHERE username LIKE '%{name}%'"
        
        # Simulate SQL injection behavior
        name_lower = name.lower()
        
        # Error-based SQLi detection
        if "union" in name_lower and "select" in name_lower:
            raise Exception("SQL syntax error: You have an error in your SQL syntax near 'UNION SELECT'")
        
        # Boolean-based blind SQLi simulation
        if "' or '1'='1" in name_lower or "' or 1=1" in name_lower:
            # TRUE condition - return all users
            results = list(database["users"].values())
        elif "' and '1'='2" in name_lower or "' and 1=2" in name_lower:
            # FALSE condition - return empty
            results = []
        elif "' and '1'='1" in name_lower or "' and 1=1" in name_lower:
            # TRUE condition - return matching users (or all if no match)
            results = [u for u in database["users"].values() if name.split("'")[0].lower() in u["username"].lower()]
            if not results:
                results = list(database["users"].values())
        else:
            # Normal search
            results = [u for u in database["users"].values() if name.lower() in u["username"].lower()]
        
        return add_response_metadata({
            "query": sql_query,
            "results": results,
            "count": len(results)
        }, request.state.request_id)
    
    except Exception as e:
        # Return SQL error (helps attacker with error-based SQLi)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# 🟢 SECURE: Search with parameterized query
@router.get("/search/secure")
async def sqli_search_secure(request: Request, name: str = ""):
    """
    🟢 SECURE: Search users by name with parameterized query.
    
    Uses proper input validation and parameterized queries.
    """
    from app.database import database
    
    # Safe search - no SQL injection possible
    results = [u for u in database["users"].values() if name.lower() in u["username"].lower()]
    
    return add_response_metadata({
        "results": results,
        "count": len(results)
    }, request.state.request_id)
