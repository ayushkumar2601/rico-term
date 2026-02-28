"""Playwright-based browser automation for login and session capture."""

from typing import Dict, Any, Optional
from playwright.async_api import async_playwright, Browser, Page
import asyncio


async def login_and_get_session(
    login_config: Dict[str, Any],
    headless: bool = True,
    timeout: int = 30000
) -> Dict[str, Any]:
    """
    Automate login flow and capture session data.
    
    Args:
        login_config: Login configuration dict with:
            - login_url: URL of login page
            - username: Username/email
            - password: Password
            - username_selector: CSS selector for username field
            - password_selector: CSS selector for password field
            - submit_selector: CSS selector for submit button
            - token_storage: Where token is stored (cookie/localStorage/header)
        headless: Run browser in headless mode
        timeout: Maximum time to wait (ms)
        
    Returns:
        Dict with session data:
        - cookies: List of cookies
        - local_storage: localStorage data
        - session_storage: sessionStorage data
        - success: Whether login succeeded
        - error: Error message if failed
    """
    try:
        async with async_playwright() as p:
            # Launch browser
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context()
            page = await context.new_page()
            
            # Navigate to login page
            await page.goto(login_config["login_url"], timeout=timeout)
            await page.wait_for_load_state("networkidle")
            
            # Fill login form
            await page.fill(
                login_config["username_selector"],
                login_config["username"]
            )
            await page.fill(
                login_config["password_selector"],
                login_config["password"]
            )
            
            # Submit form
            await page.click(login_config["submit_selector"])
            
            # Wait for navigation after login
            try:
                await page.wait_for_load_state("networkidle", timeout=timeout)
            except:
                pass  # Some sites don't redirect
            
            # Give time for tokens to be set
            await asyncio.sleep(2)
            
            # Extract session data
            cookies = await context.cookies()
            
            # Extract localStorage
            local_storage = await page.evaluate("() => Object.assign({}, window.localStorage)")
            
            # Extract sessionStorage
            session_storage = await page.evaluate("() => Object.assign({}, window.sessionStorage)")
            
            # Close browser
            await browser.close()
            
            return {
                "success": True,
                "cookies": cookies,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "error": None
            }
            
    except Exception as e:
        return {
            "success": False,
            "cookies": [],
            "local_storage": {},
            "session_storage": {},
            "error": str(e)
        }


async def test_session_reuse(
    session_data: Dict[str, Any],
    test_url: str,
    headless: bool = True
) -> bool:
    """
    Test if captured session is valid by visiting a protected page.
    
    Args:
        session_data: Session data from login_and_get_session
        test_url: URL to test with session
        headless: Run browser in headless mode
        
    Returns:
        True if session is valid, False otherwise
    """
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context()
            
            # Add cookies to context
            if session_data.get("cookies"):
                await context.add_cookies(session_data["cookies"])
            
            page = await context.new_page()
            
            # Set localStorage if available
            if session_data.get("local_storage"):
                await page.goto(test_url)
                for key, value in session_data["local_storage"].items():
                    await page.evaluate(
                        f"window.localStorage.setItem('{key}', '{value}')"
                    )
            
            # Navigate to test URL
            response = await page.goto(test_url)
            
            # Check if we got a successful response (not redirected to login)
            success = response.status < 400
            
            await browser.close()
            
            return success
            
    except Exception:
        return False
