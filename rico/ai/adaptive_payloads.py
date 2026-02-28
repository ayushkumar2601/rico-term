"""
Adaptive Payload Generation using Hybrid AI Architecture

Architecture:
- Snowflake: Security Intelligence Warehouse (stores historical exploit data)
- AI Provider: LLM Reasoning Engine (Groq or Cortex)
  - Current: Groq (due to regional Cortex availability)
  - Future: Seamless migration to Snowflake Cortex when available

This module retrieves historical intelligence from Snowflake and uses
an AI reasoning engine to generate adaptive, context-aware payloads.
"""
import logging
from typing import List, Optional, Dict, Any

from rico.db.retrieve import get_top_successful_payloads, get_payload_statistics
from rico.ai.provider import generate_completion, is_ai_enabled, get_provider_info

logger = logging.getLogger("rico.ai.adaptive")


class AdaptivePayloadGenerator:
    """
    Generates adaptive attack payloads using Hybrid AI Architecture.
    
    Architecture:
    1. Retrieve successful payloads from Snowflake (Intelligence Warehouse)
    2. Inject context into AI provider prompt (RAG pattern)
    3. Generate improved payload using AI reasoning engine
    4. Return for execution (storage handled by existing flow)
    
    AI Provider:
    - Current: Groq (llama-3.3-70b-versatile)
    - Future: Snowflake Cortex (when available in region)
    - Abstraction: Seamless switching via provider layer
    """
    
    def __init__(self):
        """
        Initialize adaptive payload generator.
        
        Uses the configured AI provider (Groq or Cortex) via abstraction layer.
        """
        self.provider_info = get_provider_info()
        
        if not is_ai_enabled():
            logger.warning("No AI provider configured. Adaptive payloads disabled.")
            logger.info("Set GROQ_API_KEY or enable Cortex to use adaptive intelligence.")
        else:
            logger.info(f"Adaptive payload generator initialized with {self.provider_info['provider']}")
    
    def is_enabled(self) -> bool:
        """Check if adaptive payload generation is enabled."""
        return is_ai_enabled()
    
    def generate_adaptive_sqli_payload(
        self,
        api_framework: Optional[str] = None,
        endpoint_context: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate adaptive SQL injection payload using historical intelligence.
        
        Args:
            api_framework: Target API framework (FastAPI, Flask, etc.)
            endpoint_context: Additional context about the endpoint
            
        Returns:
            Generated payload string, or None if generation fails
        """
        if not self.is_enabled():
            logger.debug("Adaptive payloads disabled - no Groq API key")
            return None
        
        try:
            # Retrieve historical successful payloads from Snowflake
            historical = get_top_successful_payloads(
                vulnerability_type="SQL Injection",
                limit=5,
                api_framework=api_framework
            )
            
            # Get statistics for context
            stats = get_payload_statistics("SQL Injection")
            
            # Build context
            if historical:
                context = "\n".join([f"- {p}" for p in historical])
                logger.info(f"Retrieved {len(historical)} successful SQL injection payloads from Snowflake")
            else:
                context = "No historical successful payloads found."
                logger.info("No historical SQL injection payloads - generating from scratch")
            
            # Build prompt
            prompt = self._build_sqli_prompt(
                historical_payloads=context,
                api_framework=api_framework,
                endpoint_context=endpoint_context,
                stats=stats
            )
            
            # Generate payload using AI provider (Groq or Cortex)
            logger.info(f"Generating SQL injection payload using {self.provider_info['provider']}")
            payload = generate_completion(
                prompt=prompt,
                temperature=0.3,  # Low temperature for focused generation
                max_tokens=200
            )
            
            # Clean up payload (remove quotes, explanations, etc.)
            payload = self._clean_payload(payload)
            
            logger.info(f"Generated adaptive SQL injection payload: {payload[:50]}...")
            return payload
            
        except Exception as e:
            logger.error(f"Failed to generate adaptive SQL injection payload: {str(e)}")
            return None
    
    def generate_adaptive_idor_payload(
        self,
        api_framework: Optional[str] = None,
        endpoint_context: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate adaptive IDOR attack strategy using historical intelligence.
        
        Args:
            api_framework: Target API framework
            endpoint_context: Additional context about the endpoint
            
        Returns:
            Dictionary with IDOR attack strategy, or None if generation fails
        """
        if not self.is_enabled():
            logger.debug("Adaptive payloads disabled - no Groq API key")
            return None
        
        try:
            # Retrieve historical successful IDOR attacks
            historical = get_top_successful_payloads(
                vulnerability_type="IDOR",
                limit=5,
                api_framework=api_framework
            )
            
            # Get statistics
            stats = get_payload_statistics("IDOR")
            
            # Build context
            if historical:
                context = "\n".join([f"- {p}" for p in historical])
                logger.info(f"Retrieved {len(historical)} successful IDOR patterns from Snowflake")
            else:
                context = "No historical successful IDOR patterns found."
                logger.info("No historical IDOR patterns - generating from scratch")
            
            # Build prompt
            prompt = self._build_idor_prompt(
                historical_patterns=context,
                api_framework=api_framework,
                endpoint_context=endpoint_context,
                stats=stats
            )
            
            # Generate strategy using AI provider (Groq or Cortex)
            logger.info(f"Generating IDOR strategy using {self.provider_info['provider']}")
            strategy_text = generate_completion(
                prompt=prompt,
                temperature=0.3,
                max_tokens=300
            )
            
            # Try to parse as JSON
            import json
            try:
                strategy = json.loads(strategy_text)
                logger.info(f"Generated adaptive IDOR strategy: {strategy.get('strategy', 'N/A')}")
                return strategy
            except json.JSONDecodeError:
                # Fallback: return as text
                logger.warning("Could not parse IDOR strategy as JSON, returning as text")
                return {"strategy": strategy_text, "test_ids": []}
            
        except Exception as e:
            logger.error(f"Failed to generate adaptive IDOR strategy: {str(e)}")
            return None
    
    def _build_sqli_prompt(
        self,
        historical_payloads: str,
        api_framework: Optional[str],
        endpoint_context: Optional[str],
        stats: Dict[str, Any]
    ) -> str:
        """Build prompt for SQL injection payload generation."""
        prompt_parts = [
            "Generate an advanced SQL injection payload based on the following intelligence:",
            "",
            "HISTORICAL SUCCESSFUL PAYLOADS:",
            historical_payloads,
            "",
        ]
        
        if stats and stats.get("total_attempts", 0) > 0:
            prompt_parts.extend([
                "STATISTICS:",
                f"- Total attempts: {stats['total_attempts']}",
                f"- Successful: {stats['successful']}",
                f"- Success rate: {stats['success_rate']}%",
                "",
            ])
        
        if api_framework:
            prompt_parts.extend([
                f"TARGET FRAMEWORK: {api_framework}",
                "",
            ])
        
        if endpoint_context:
            prompt_parts.extend([
                f"ENDPOINT CONTEXT: {endpoint_context}",
                "",
            ])
        
        prompt_parts.extend([
            "REQUIREMENTS:",
            "1. Learn from successful patterns above",
            "2. Generate a more sophisticated variant",
            "3. Consider the target framework if specified",
            "4. Return ONLY the payload string (no quotes, no explanations)",
            "",
            "PAYLOAD:"
        ])
        
        return "\n".join(prompt_parts)
    
    def _build_idor_prompt(
        self,
        historical_patterns: str,
        api_framework: Optional[str],
        endpoint_context: Optional[str],
        stats: Dict[str, Any]
    ) -> str:
        """Build prompt for IDOR strategy generation."""
        prompt_parts = [
            "Generate an advanced IDOR testing strategy based on the following intelligence:",
            "",
            "HISTORICAL SUCCESSFUL PATTERNS:",
            historical_patterns,
            "",
        ]
        
        if stats and stats.get("total_attempts", 0) > 0:
            prompt_parts.extend([
                "STATISTICS:",
                f"- Total attempts: {stats['total_attempts']}",
                f"- Successful: {stats['successful']}",
                f"- Success rate: {stats['success_rate']}%",
                "",
            ])
        
        if api_framework:
            prompt_parts.extend([
                f"TARGET FRAMEWORK: {api_framework}",
                "",
            ])
        
        if endpoint_context:
            prompt_parts.extend([
                f"ENDPOINT CONTEXT: {endpoint_context}",
                "",
            ])
        
        prompt_parts.extend([
            "REQUIREMENTS:",
            "1. Learn from successful patterns above",
            "2. Suggest IDs to test (e.g., sequential, negative, large numbers)",
            "3. Consider the target framework if specified",
            "4. Return JSON: {\"test_ids\": [1, 2, 999, -1], \"strategy\": \"brief description\"}",
            "",
            "STRATEGY:"
        ])
        
        return "\n".join(prompt_parts)
    
    def _clean_payload(self, payload: str) -> str:
        """Clean up generated payload string."""
        # Remove common wrapper patterns
        payload = payload.strip()
        
        # Remove markdown code blocks
        if payload.startswith("```"):
            lines = payload.split("\n")
            payload = "\n".join(lines[1:-1]) if len(lines) > 2 else payload
        
        # Remove quotes if wrapped
        if (payload.startswith('"') and payload.endswith('"')) or \
           (payload.startswith("'") and payload.endswith("'")):
            payload = payload[1:-1]
        
        # Take first line if multi-line
        if "\n" in payload:
            payload = payload.split("\n")[0]
        
        return payload.strip()


# Global instance (lazy initialization)
_generator = None


def get_adaptive_generator() -> AdaptivePayloadGenerator:
    """
    Get global adaptive payload generator instance.
    
    Returns:
        AdaptivePayloadGenerator instance
    """
    global _generator
    if _generator is None:
        _generator = AdaptivePayloadGenerator()
    return _generator


def generate_adaptive_payload(
    vulnerability_type: str,
    api_framework: Optional[str] = None,
    endpoint_context: Optional[str] = None
) -> Optional[Any]:
    """
    Convenience function to generate adaptive payload.
    
    Args:
        vulnerability_type: Type of vulnerability (SQL Injection, IDOR, etc.)
        api_framework: Target API framework
        endpoint_context: Additional context about the endpoint
        
    Returns:
        Generated payload (type depends on vulnerability type)
    """
    generator = get_adaptive_generator()
    
    if vulnerability_type == "SQL Injection":
        return generator.generate_adaptive_sqli_payload(
            api_framework=api_framework,
            endpoint_context=endpoint_context
        )
    elif vulnerability_type == "IDOR":
        return generator.generate_adaptive_idor_payload(
            api_framework=api_framework,
            endpoint_context=endpoint_context
        )
    else:
        logger.warning(f"Adaptive payload generation not implemented for: {vulnerability_type}")
        return None
