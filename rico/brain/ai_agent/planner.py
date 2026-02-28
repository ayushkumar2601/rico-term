"""AI-powered attack planning module."""

from typing import Dict, Any, List, Optional
import json
from rico.brain.ai_agent.prompts import ATTACK_PLANNER_PROMPT
from rico.brain.ai_agent.config import load_ai_config


def plan_attacks_heuristic(endpoint_type: str, sensitivity: str, method: str) -> Dict[str, Any]:
    """
    Plan attacks using heuristic rules (fallback when LLM unavailable).
    
    Args:
        endpoint_type: Type of endpoint (auth/resource/admin/public)
        sensitivity: Sensitivity level (low/medium/high)
        method: HTTP method
        
    Returns:
        Dict with attacks list and reasoning
    """
    attacks = []
    reasoning = []
    
    # Auth endpoints - focus on SQLi
    if endpoint_type == "auth":
        attacks.append("SQL Injection")
        reasoning.append("Auth endpoints often query databases with user input")
        
        if method in ["POST", "PUT"]:
            attacks.append("Missing Auth")
            reasoning.append("Verify authentication is properly enforced")
    
    # Resource endpoints - focus on IDOR
    elif endpoint_type == "resource":
        attacks.append("IDOR")
        reasoning.append("Resource endpoints with IDs are vulnerable to IDOR")
        
        attacks.append("Missing Auth")
        reasoning.append("Ensure proper authorization for resource access")
        
        if method in ["GET", "POST"]:
            attacks.append("SQL Injection")
            reasoning.append("Check for SQL injection in query parameters")
    
    # Admin endpoints - all attacks
    elif endpoint_type == "admin":
        attacks.extend(["Missing Auth", "IDOR", "SQL Injection"])
        reasoning.append("Admin endpoints require comprehensive security testing")
    
    # Public endpoints - limited testing
    elif endpoint_type == "public":
        if method in ["GET", "POST"]:
            attacks.append("SQL Injection")
            reasoning.append("Check for SQL injection even in public endpoints")
    
    # Default: test all
    if not attacks:
        attacks.extend(["IDOR", "Missing Auth", "SQL Injection"])
        reasoning.append("Standard security testing for unknown endpoint type")
    
    return {
        "attacks": attacks,
        "reasoning": " | ".join(reasoning)
    }


async def plan_attacks_llm(
    endpoint_type: str,
    sensitivity: str,
    method: str,
    path: str
) -> Optional[Dict[str, Any]]:
    """
    Plan attacks using LLM (OpenAI/Claude/Groq).
    
    Args:
        endpoint_type: Type of endpoint
        sensitivity: Sensitivity level
        method: HTTP method
        path: Endpoint path
        
    Returns:
        Dict with attacks and reasoning or None if LLM unavailable
    """
    # Load AI config
    config = load_ai_config()
    provider = config.get("provider")
    
    if not provider:
        return None
    
    try:
        # Format prompt
        prompt = ATTACK_PLANNER_PROMPT.format(
            method=method,
            path=path,
            endpoint_type=endpoint_type,
            sensitivity=sensitivity
        )
        
        # Try Groq first (priority)
        if provider == "groq" and config.get("groq_key"):
            from groq import Groq
            client = Groq(api_key=config["groq_key"])
            
            response = client.chat.completions.create(
                model=config.get("model", "llama-3.1-8b-instant"),
                messages=[
                    {"role": "system", "content": "You are a security expert planning API security tests. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=300
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
                    {"role": "system", "content": "You are a security expert planning API security tests."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=300
            )
            
            result = json.loads(response.choices[0].message.content)
            return result
        
        # Try Anthropic Claude
        elif provider == "anthropic" and config.get("anthropic_key"):
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=config["anthropic_key"])
            
            response = await client.messages.create(
                model=config.get("model", "claude-3-haiku-20240307"),
                max_tokens=300,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            result = json.loads(response.content[0].text)
            return result
            
    except Exception:
        return None
    
    return None


async def plan_attacks(
    endpoint_type: str,
    sensitivity: str,
    method: str,
    path: str
) -> Dict[str, Any]:
    """
    Plan which security attacks to run on an endpoint.
    
    Args:
        endpoint_type: Type of endpoint (auth/resource/admin/public)
        sensitivity: Sensitivity level (low/medium/high)
        method: HTTP method
        path: Endpoint path
        
    Returns:
        Dict with:
        - attacks: List of attack names to run
        - reasoning: Explanation for attack selection
    """
    # Try LLM planning first
    llm_result = await plan_attacks_llm(endpoint_type, sensitivity, method, path)
    if llm_result:
        return llm_result
    
    # Fallback to heuristic rules
    return plan_attacks_heuristic(endpoint_type, sensitivity, method)
