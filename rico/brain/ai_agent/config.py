"""Configuration loader for AI agent."""

import os
from typing import Dict, Any, Optional


def load_ai_config() -> Dict[str, Any]:
    """
    Load AI configuration from environment variables.
    
    Returns:
        Dict with provider, API keys, and model settings
    """
    # Determine provider priority: GROQ > OpenAI > Anthropic
    groq_key = os.getenv("GROQ_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    
    # Auto-detect provider based on available keys
    if groq_key:
        default_provider = "groq"
        default_model = "llama-3.1-8b-instant"
    elif openai_key:
        default_provider = "openai"
        default_model = "gpt-3.5-turbo"
    elif anthropic_key:
        default_provider = "anthropic"
        default_model = "claude-3-haiku-20240307"
    else:
        default_provider = None
        default_model = None
    
    # Allow manual override via AI_PROVIDER env var
    provider = os.getenv("AI_PROVIDER", default_provider)
    
    return {
        "provider": provider,
        "openai_key": openai_key,
        "anthropic_key": anthropic_key,
        "groq_key": groq_key,
        "model": os.getenv("AI_MODEL", default_model)
    }


def get_provider_name(config: Dict[str, Any]) -> Optional[str]:
    """
    Get human-readable provider name.
    
    Args:
        config: AI configuration dict
        
    Returns:
        Provider name or None
    """
    provider = config.get("provider")
    if not provider:
        return None
    
    provider_names = {
        "groq": "Groq",
        "openai": "OpenAI",
        "anthropic": "Anthropic Claude"
    }
    
    return provider_names.get(provider, provider.title())
