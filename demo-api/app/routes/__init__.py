"""Route modules for RICO Security Testing Playground."""

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

__all__ = [
    "auth_routes",
    "user_routes",
    "sqli_routes",
    "ssrf_routes",
    "traversal_routes",
    "command_routes",
    "business_logic_routes",
    "admin_routes"
]
