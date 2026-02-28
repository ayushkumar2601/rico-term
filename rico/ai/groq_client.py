"""
Groq LLM Client

Provides LLM reasoning capabilities using Groq's API.
This is the current default reasoning engine for RICO's adaptive intelligence.

Architecture Role:
- Snowflake: Stores and retrieves historical exploit intelligence
- Groq: Analyzes patterns and generates adaptive payloads
"""
import os
import logging
from typing import Optional
from groq import Groq

logger = logging.getLogger("rico.ai.groq")


def groq_complete(
    prompt: str,
    temperature: float = 0.3,
    max_tokens: int = 300,
    model: str = "llama-3.3-70b-versatile"
) -> str:
    """
    Generate completion using Groq's LLM API.
    
    Args:
        prompt: The prompt to send to the LLM
        temperature: Sampling temperature (0.0-1.0)
            - 0.0-0.3: Focused, deterministic (good for exploits)
            - 0.4-0.7: Balanced
            - 0.8-1.0: Creative, diverse
        max_tokens: Maximum tokens in response
        model: Groq model to use (default: llama-3.3-70b-versatile)
        
    Returns:
        str: Generated completion text
        
    Raises:
        RuntimeError: If Groq API key is not configured
        Exception: If API call fails
    """
    api_key = os.getenv("GROQ_API_KEY")
    
    if not api_key:
        raise RuntimeError(
            "Groq API key not configured. Set GROQ_API_KEY environment variable. "
            "Get your free API key at: https://console.groq.com/keys"
        )
    
    try:
        client = Groq(api_key=api_key)
        
        logger.debug(f"Sending prompt to Groq (model: {model}, temp: {temperature})")
        
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert API security researcher. "
                        "Generate precise, effective security payloads based on historical patterns. "
                        "Be concise and technical."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        completion = response.choices[0].message.content.strip()
        logger.debug(f"Received completion: {len(completion)} characters")
        
        return completion
        
    except Exception as e:
        logger.error(f"Groq API error: {str(e)}")
        raise


def test_groq_connection() -> bool:
    """
    Test if Groq API is accessible and working.
    
    Returns:
        bool: True if connection successful
    """
    try:
        response = groq_complete(
            prompt="Say 'OK' if you can read this.",
            temperature=0.0,
            max_tokens=10
        )
        return "ok" in response.lower()
    except Exception as e:
        logger.error(f"Groq connection test failed: {str(e)}")
        return False


def get_available_models() -> list:
    """
    Get list of available Groq models.
    
    Returns:
        list: Available model names
    """
    # Current working models as of 2024
    return [
        "llama-3.3-70b-versatile",  # Recommended: Fast, high-quality
        "llama-3.1-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
    ]
