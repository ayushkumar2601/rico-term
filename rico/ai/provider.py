"""
AI Provider Abstraction Layer

This module provides a unified interface for AI reasoning engines.
Supports both Groq (current) and Snowflake Cortex (future).

Architecture:
- Snowflake: Security Intelligence Warehouse (storage + retrieval)
- Groq/Cortex: LLM Reasoning Engine (adaptive payload generation)
"""
import os
import logging

logger = logging.getLogger("rico.ai.provider")

# Configuration: Which AI provider to use
USE_CORTEX = os.getenv("USE_CORTEX", "false").lower() == "true"


def get_provider_info() -> dict:
    """
    Get information about the current AI provider configuration.
    
    Returns:
        dict: Provider configuration details
    """
    return {
        "provider": "Snowflake Cortex" if USE_CORTEX else "Groq",
        "cortex_enabled": USE_CORTEX,
        "groq_configured": bool(os.getenv("GROQ_API_KEY")),
        "reasoning_engine": "Cortex LLM" if USE_CORTEX else "Groq LLM"
    }


def generate_completion(prompt: str, temperature: float = 0.3, max_tokens: int = 300) -> str:
    """
    Generate AI completion using the configured provider.
    
    This abstraction allows seamless switching between:
    - Groq (current default)
    - Snowflake Cortex (future, when available in region)
    
    Args:
        prompt: The prompt to send to the AI
        temperature: Sampling temperature (0.0 = deterministic, 1.0 = creative)
        max_tokens: Maximum tokens in response
        
    Returns:
        str: Generated completion text
        
    Raises:
        RuntimeError: If no AI provider is configured
    """
    if USE_CORTEX:
        logger.info("Using Snowflake Cortex for reasoning")
        from rico.ai.cortex import cortex_complete
        return cortex_complete(prompt, temperature=temperature, max_tokens=max_tokens)
    else:
        logger.info("Using Groq for reasoning")
        from rico.ai.groq_client import groq_complete
        return groq_complete(prompt, temperature=temperature, max_tokens=max_tokens)


def is_ai_enabled() -> bool:
    """
    Check if any AI provider is available and configured.
    
    Returns:
        bool: True if AI reasoning is available
    """
    if USE_CORTEX:
        # Check if Cortex is available (would need Snowflake connection)
        try:
            from rico.db.snowflake_client import is_snowflake_enabled
            return is_snowflake_enabled()
        except Exception:
            return False
    else:
        # Check if Groq API key is configured
        return bool(os.getenv("GROQ_API_KEY"))


def log_provider_status():
    """Log the current AI provider configuration for transparency."""
    info = get_provider_info()
    
    logger.info("=" * 60)
    logger.info("AI Provider Configuration:")
    logger.info(f"  Provider: {info['provider']}")
    logger.info(f"  Reasoning Engine: {info['reasoning_engine']}")
    logger.info(f"  Cortex Available: {info['cortex_enabled']}")
    logger.info(f"  Groq Configured: {info['groq_configured']}")
    logger.info("=" * 60)
