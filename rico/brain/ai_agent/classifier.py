"""AI-powered endpoint classification module."""

from typing import Dict, Any, Optional
import re
import json
from rico.brain.ai_agent.prompts import CLASSIFICATION_PROMPT
from rico.brain.ai_agent.config import load_ai_config


def classify_endpoint_heuristic(method: str, path: str, parameters: list[str]) -> Dict[str, Any]:
    """
    Classify endpoint using heuristic rules (fallback when LLM unavailable).
    
    Args:
        method: HTTP method
        path: Endpoint path
        parameters: List of parameters
        
    Returns:
        Classification dict with type, sensitivity, and reason
    """
    path_lower = path.lower()
    
    # Auth endpoints
    if any(keyword in path_lower for keyword in ['login', 'auth', 'token', 'signin', 'signup', 'register']):
        return {
            "type": "auth",
            "sensitivity": "high",
            "reason": "Authentication endpoint - handles credentials"
        }
    
    # Admin endpoints
    if any(keyword in path_lower for keyword in ['admin', 'manage', 'config', 'settings']):
        return {
            "type": "admin",
            "sensitivity": "high",
            "reason": "Administrative endpoint - requires elevated privileges"
        }
    
    # Resource endpoints with ID parameter
    if re.search(r'\{id\}|\{[a-z]+_id\}|/\d+', path_lower):
        return {
            "type": "resource",
            "sensitivity": "medium",
            "reason": "Resource endpoint with ID parameter - potential IDOR target"
        }
    
    # Public endpoints
    if any(keyword in path_lower for keyword in ['public', 'health', 'status', 'ping', 'version']):
        return {
            "type": "public",
            "sensitivity": "low",
            "reason": "Public endpoint - no authentication required"
        }
    
    # Default: resource endpoint
    if method in ['POST', 'PUT', 'DELETE']:
        return {
            "type": "resource",
            "sensitivity": "medium",
            "reason": f"{method} operation on resource - requires authorization"
        }
    
    return {
        "type": "resource",
        "sensitivity": "medium",
        "reason": "Standard resource endpoint"
    }


async def classify_endpoint_llm(method: str, path: str, parameters: list[str]) -> Optional[Dict[str, Any]]:
    """
    Classify endpoint using LLM (OpenAI/Claude/Groq).
    
    Args:
        method: HTTP method
        path: Endpoint path
        parameters: List of parameters
        
    Returns:
        Classification dict or None if LLM unavailable
    """
    # Load AI config
    config = load_ai_config()
    provider = config.get("provider")
    
    if not provider:
        return None
    
    try:
        # Format prompt
        params_str = ", ".join(parameters) if parameters else "None"
        prompt = CLASSIFICATION_PROMPT.format(
            method=method,
            path=path,
            parameters=params_str
        )
        
        # Try Groq first (priority)
        if provider == "groq" and config.get("groq_key"):
            from groq import Groq
            client = Groq(api_key=config["groq_key"])
            
            response = client.chat.completions.create(
                model=config.get("model", "llama-3.1-8b-instant"),
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing API endpoints. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=200
            )
            
            result = json.loads(response.choices[0].message.content)
            return result
        
        # Try OpenAI
        elif provider == "openai" and config.get("openai_key"):
            import openai
            openai.api_key = config["openai_key"]
            
            response = await openai.ChatCompletion.acreate(
                model=config.get("model", "gpt-3.5-turbo"),
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing API endpoints."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=200
            )
            
            result = json.loads(response.choices[0].message.content)
            return result
        
        # Try Anthropic Claude
        elif provider == "anthropic" and config.get("anthropic_key"):
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=config["anthropic_key"])
            
            response = await client.messages.create(
                model=config.get("model", "claude-3-haiku-20240307"),
                max_tokens=200,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            result = json.loads(response.content[0].text)
            return result
            
    except Exception as e:
        # Fallback to heuristic on error
        return None
    
    return None


async def classify_endpoint(method: str, path: str, parameters: list[str]) -> Dict[str, Any]:
    """
    Classify an API endpoint using AI or heuristic rules.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: Endpoint path
        parameters: List of parameters
        
    Returns:
        Classification dict with:
        - type: auth|resource|admin|public
        - sensitivity: low|medium|high
        - reason: explanation
    """
    # Try LLM classification first
    llm_result = await classify_endpoint_llm(method, path, parameters)
    if llm_result:
        return llm_result
    
    # Fallback to heuristic rules
    return classify_endpoint_heuristic(method, path, parameters)
