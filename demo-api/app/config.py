"""Configuration settings for the security testing playground."""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings."""
    
    # App settings
    APP_NAME: str = "RICO Security Testing Playground"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Security settings
    JWT_SECRET_KEY: str = "insecure_secret_key_for_testing_only_do_not_use_in_production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60
    
    # Rate limiting
    RATE_LIMIT_PER_SECOND: int = 5
    
    # Database
    DATABASE_URL: str = "sqlite:///./test.db"
    
    # File paths
    FILES_DIRECTORY: str = "data"
    
    # SSRF settings
    SSRF_ALLOW_INTERNAL: bool = False  # Set to True for vulnerable endpoint
    SSRF_BLOCKED_IPS: list = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "169.254.169.254",  # AWS metadata
        "metadata.google.internal",  # GCP metadata
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
