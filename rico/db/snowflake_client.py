"""Snowflake connection client for RICO Security Intelligence Warehouse."""
import snowflake.connector
import os
import logging
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logger
logger = logging.getLogger("rico.snowflake")


def get_connection():
    """
    Create and return a Snowflake connection.
    
    Uses environment variables for configuration:
    - SNOWFLAKE_USER
    - SNOWFLAKE_PASSWORD
    - SNOWFLAKE_ACCOUNT
    - SNOWFLAKE_WAREHOUSE
    
    Returns:
        snowflake.connector.connection: Active Snowflake connection
        
    Raises:
        ValueError: If required environment variables are missing
        snowflake.connector.errors.Error: If connection fails
    """
    # Get credentials from environment
    user = os.getenv("SNOWFLAKE_USER")
    password = os.getenv("SNOWFLAKE_PASSWORD")
    account = os.getenv("SNOWFLAKE_ACCOUNT")
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE")
    
    # Validate credentials
    if not all([user, password, account, warehouse]):
        missing = []
        if not user:
            missing.append("SNOWFLAKE_USER")
        if not password:
            missing.append("SNOWFLAKE_PASSWORD")
        if not account:
            missing.append("SNOWFLAKE_ACCOUNT")
        if not warehouse:
            missing.append("SNOWFLAKE_WAREHOUSE")
        
        raise ValueError(
            f"Missing required Snowflake environment variables: {', '.join(missing)}. "
            f"Please set them in your .env file or environment."
        )
    
    try:
        logger.info(f"Connecting to Snowflake account: {account}")
        
        conn = snowflake.connector.connect(
            user=user,
            password=password,
            account=account,
            warehouse=warehouse,
            database="RICO_INTEL",
            schema="SECURITY"
        )
        
        logger.info("✓ Snowflake connection established successfully")
        return conn
        
    except snowflake.connector.errors.DatabaseError as e:
        logger.error(f"Snowflake connection failed: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error connecting to Snowflake: {str(e)}")
        raise


def test_connection() -> bool:
    """
    Test Snowflake connection and return success status.
    
    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        # Test query
        cur.execute("SELECT CURRENT_VERSION()")
        version = cur.fetchone()[0]
        
        logger.info(f"✓ Snowflake connection test successful (Version: {version})")
        
        cur.close()
        conn.close()
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Snowflake connection test failed: {str(e)}")
        return False


def is_snowflake_enabled() -> bool:
    """
    Check if Snowflake integration is enabled (credentials available).
    
    Returns:
        bool: True if all required credentials are set
    """
    user = os.getenv("SNOWFLAKE_USER")
    password = os.getenv("SNOWFLAKE_PASSWORD")
    account = os.getenv("SNOWFLAKE_ACCOUNT")
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE")
    
    return all([user, password, account, warehouse])
