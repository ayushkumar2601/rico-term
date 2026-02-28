"""Snowflake Cortex LLM integration for adaptive attack reasoning."""
import logging
from typing import Optional, Dict, Any
from rico.db.snowflake_client import get_connection

# Setup logger
logger = logging.getLogger("rico.cortex")


def cortex_complete(
    prompt: str,
    model: str = "llama3-70b",
    max_tokens: int = 500
) -> Optional[str]:
    """
    Use Snowflake Cortex LLM to generate attack payloads or reasoning.
    
    Snowflake Cortex provides serverless LLM inference directly in the data warehouse,
    enabling AI-powered attack planning without external API calls.
    
    Args:
        prompt: The prompt to send to the LLM
        model: Cortex model to use (llama3-70b, mistral-large, etc.)
        max_tokens: Maximum tokens to generate
        
    Returns:
        str: LLM response text, or None if failed
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Calling Snowflake Cortex ({model}) for attack reasoning")
        logger.debug(f"Prompt: {prompt[:100]}...")
        
        # Use Snowflake Cortex COMPLETE function
        # Note: The $$ syntax is for multi-line string literals in Snowflake SQL
        query = f"""
            SELECT SNOWFLAKE.CORTEX.COMPLETE(
                '{model}',
                $$ {prompt} $$
            ) as response;
        """
        
        cur.execute(query)
        result = cur.fetchone()
        
        if result and result[0]:
            response = result[0]
            logger.info(f"✓ Cortex response received ({len(response)} chars)")
            logger.debug(f"Response: {response[:200]}...")
            return response
        else:
            logger.warning("Cortex returned empty response")
            return None
        
    except Exception as e:
        logger.error(f"✗ Cortex LLM call failed: {str(e)}")
        return None
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass


def cortex_generate_payload(
    vulnerability_type: str,
    endpoint_path: str,
    historical_payloads: list,
    api_framework: str = "Unknown"
) -> Optional[str]:
    """
    Generate an advanced attack payload using Cortex LLM and historical data.
    
    This is the core of the adaptive attack loop - it learns from past successes
    and generates more sophisticated payloads.
    
    Args:
        vulnerability_type: Type of vulnerability (SQLi, IDOR, etc.)
        endpoint_path: Target endpoint path
        historical_payloads: List of previously successful payloads
        api_framework: API framework being tested
        
    Returns:
        str: Generated payload, or None if failed
    """
    # Build context from historical payloads
    if historical_payloads:
        payload_context = "\n".join([f"- {p}" for p in historical_payloads[:5]])
    else:
        payload_context = "No historical data available"
    
    # Construct prompt
    prompt = f"""You are an API security testing expert specializing in {vulnerability_type} attacks.

Target Information:
- Endpoint: {endpoint_path}
- API Framework: {api_framework}
- Vulnerability Type: {vulnerability_type}

Previously Successful Payloads:
{payload_context}

Task: Generate ONE advanced {vulnerability_type} payload that:
1. Builds upon the successful patterns above
2. Is more sophisticated than previous attempts
3. Is specifically crafted for {api_framework} APIs
4. Targets the endpoint structure: {endpoint_path}

Requirements:
- Return ONLY the payload string, no explanation
- Make it production-ready (properly encoded if needed)
- Focus on evasion techniques if previous payloads were basic

Payload:"""
    
    response = cortex_complete(prompt, model="llama3-70b", max_tokens=200)
    
    if response:
        # Extract just the payload (remove any extra text)
        payload = response.strip().split('\n')[0]
        logger.info(f"✓ Generated adaptive payload: {payload[:50]}...")
        return payload
    else:
        return None


def cortex_analyze_response(
    vulnerability_type: str,
    response_text: str,
    response_code: int,
    response_time_ms: float
) -> Dict[str, Any]:
    """
    Use Cortex LLM to analyze API response and determine exploit success.
    
    Args:
        vulnerability_type: Type of vulnerability tested
        response_text: API response body
        response_code: HTTP status code
        response_time_ms: Response time in milliseconds
        
    Returns:
        Dict with analysis results (success, confidence, reasoning)
    """
    # Truncate response for analysis
    response_preview = response_text[:500] if len(response_text) > 500 else response_text
    
    prompt = f"""You are analyzing an API security test response for {vulnerability_type}.

Response Details:
- Status Code: {response_code}
- Response Time: {response_time_ms}ms
- Response Body Preview:
{response_preview}

Task: Determine if this response indicates a successful {vulnerability_type} exploit.

Analyze for:
1. Error messages indicating vulnerability
2. Unexpected data exposure
3. Timing anomalies
4. Status code changes

Respond in this exact format:
SUCCESS: [true/false]
CONFIDENCE: [0-100]
REASONING: [one sentence explanation]"""
    
    response = cortex_complete(prompt, model="llama3-70b", max_tokens=150)
    
    if response:
        # Parse response
        try:
            lines = response.strip().split('\n')
            success = "true" in lines[0].lower()
            confidence = int(''.join(filter(str.isdigit, lines[1])))
            reasoning = lines[2].split(':', 1)[1].strip() if len(lines) > 2 else "Analysis completed"
            
            return {
                "success": success,
                "confidence": min(confidence, 100),
                "reasoning": reasoning
            }
        except Exception as e:
            logger.warning(f"Failed to parse Cortex analysis: {e}")
            return {
                "success": False,
                "confidence": 0,
                "reasoning": "Failed to parse LLM response"
            }
    else:
        return {
            "success": False,
            "confidence": 0,
            "reasoning": "Cortex analysis unavailable"
        }


def cortex_suggest_next_attack(
    vulnerability_type: str,
    failed_payloads: list,
    endpoint_characteristics: Dict[str, Any]
) -> Optional[str]:
    """
    Suggest next attack vector based on failed attempts.
    
    This enables intelligent attack evolution when initial payloads fail.
    
    Args:
        vulnerability_type: Type of vulnerability
        failed_payloads: List of payloads that didn't work
        endpoint_characteristics: Dict with endpoint metadata
        
    Returns:
        str: Suggested next payload or attack approach
    """
    failed_context = "\n".join([f"- {p}" for p in failed_payloads[:3]])
    
    prompt = f"""You are an API penetration testing expert.

Vulnerability Type: {vulnerability_type}
Endpoint: {endpoint_characteristics.get('path', 'unknown')}
Method: {endpoint_characteristics.get('method', 'GET')}

Failed Payloads:
{failed_context}

These payloads did NOT work. Suggest a different attack vector or evasion technique.

Requirements:
- Try a completely different approach
- Consider encoding, obfuscation, or alternative syntax
- Return ONLY the new payload, no explanation

New Payload:"""
    
    response = cortex_complete(prompt, model="llama3-70b", max_tokens=150)
    
    if response:
        payload = response.strip().split('\n')[0]
        logger.info(f"✓ Cortex suggested alternative payload: {payload[:50]}...")
        return payload
    else:
        return None
