"""AI-powered attack explanation module."""

from typing import Optional
from rico.brain.ai_agent.prompts import EXPLANATION_PROMPT
from rico.brain.ai_agent.config import load_ai_config


def explain_attack_template(attack_type: str, endpoint_type: str, method: str, path: str) -> str:
    """
    Generate explanation using templates (fallback when LLM unavailable).
    
    Args:
        attack_type: Type of attack
        endpoint_type: Type of endpoint
        method: HTTP method
        path: Endpoint path
        
    Returns:
        Explanation string
    """
    explanations = {
        "IDOR": {
            "resource": f"Testing {path} for IDOR - resource IDs may be accessible without proper authorization",
            "admin": f"Admin endpoint {path} may expose resources without ownership validation",
            "auth": f"Auth endpoint {path} tested for IDOR in session/token handling",
            "public": f"Public endpoint {path} checked for unauthorized resource access"
        },
        "Missing Auth": {
            "resource": f"Verifying {path} requires authentication - {method} operations should be protected",
            "admin": f"Critical: Admin endpoint {path} must enforce authentication",
            "auth": f"Auth endpoint {path} tested for bypass vulnerabilities",
            "public": f"Confirming {path} is intentionally public"
        },
        "SQL Injection": {
            "auth": f"Auth endpoint {path} likely queries database - testing for SQLi in credentials",
            "resource": f"Testing {path} for SQL injection in query parameters",
            "admin": f"Admin endpoint {path} may have database queries vulnerable to SQLi",
            "public": f"Public endpoint {path} checked for SQL injection vulnerabilities"
        }
    }
    
    if attack_type in explanations and endpoint_type in explanations[attack_type]:
        return explanations[attack_type][endpoint_type]
    
    return f"Testing {path} for {attack_type} vulnerability"


async def explain_attack_llm(
    attack_type: str,
    endpoint_type: str,
    method: str,
    path: str
) -> Optional[str]:
    """
    Generate explanation using LLM (OpenAI/Claude/Groq).
    
    Args:
        attack_type: Type of attack
        endpoint_type: Type of endpoint
        method: HTTP method
        path: Endpoint path
        
    Returns:
        Explanation string or None if LLM unavailable
    """
    # Load AI config
    config = load_ai_config()
    provider = config.get("provider")
    
    if not provider:
        return None
    
    try:
        # Format prompt
        prompt = EXPLANATION_PROMPT.format(
            method=method,
            path=path,
            attack_type=attack_type,
            classification=endpoint_type
        )
        
        # Try Groq first (priority)
        if provider == "groq" and config.get("groq_key"):
            from groq import Groq
            client = Groq(api_key=config["groq_key"])
            
            response = client.chat.completions.create(
                model=config.get("model", "llama-3.1-8b-instant"),
                messages=[
                    {"role": "system", "content": "You are a security expert explaining vulnerabilities. Be concise."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=150
            )
            
            return response.choices[0].message.content.strip()
        
        # Try OpenAI
        elif provider == "openai" and config.get("openai_key"):
            import openai
            openai.api_key = config["openai_key"]
            
            response = await openai.ChatCompletion.acreate(
                model=config.get("model", "gpt-3.5-turbo"),
                messages=[
                    {"role": "system", "content": "You are a security expert explaining vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=150
            )
            
            return response.choices[0].message.content.strip()
        
        # Try Anthropic Claude
        elif provider == "anthropic" and config.get("anthropic_key"):
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=config["anthropic_key"])
            
            response = await client.messages.create(
                model=config.get("model", "claude-3-haiku-20240307"),
                max_tokens=150,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            return response.content[0].text.strip()
            
    except Exception:
        return None
    
    return None


async def explain_attack(
    attack_type: str,
    endpoint_type: str,
    method: str,
    path: str
) -> str:
    """
    Explain why a security attack is relevant for an endpoint.
    
    Args:
        attack_type: Type of attack (IDOR, Missing Auth, SQL Injection)
        endpoint_type: Type of endpoint (auth/resource/admin/public)
        method: HTTP method
        path: Endpoint path
        
    Returns:
        Explanation string (1-2 sentences)
    """
    # Try LLM explanation first
    llm_result = await explain_attack_llm(attack_type, endpoint_type, method, path)
    if llm_result:
        return llm_result
    
    # Fallback to template
    return explain_attack_template(attack_type, endpoint_type, method, path)
