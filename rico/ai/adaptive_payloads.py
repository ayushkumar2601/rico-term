"""Adaptive payload generation using Groq AI and Snowflake intelligence."""
import logging
from typing import List, Optional, Dict, Any
from groq import Groq
import os

from rico.db.retrieve import get_top_successful_payloads, get_payload_statistics

logger = logging.getLogger("rico.ai.adaptive")


class AdaptivePayloadGenerator:
    """
    Generates adaptive attack payloads using Groq AI reasoning
    and Snowflake intelligence storage.
    
    Architecture:
    1. Retrieve successful payloads from Snowflake
    2. Inject context into Groq prompt
    3. Generate improved payload
    4. Return for execution (storage handled by existing flow)
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize adaptive payload generator.
        
        Args:
            api_key: Groq API key. If None, reads from GROQ_API_KEY env var.
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        
        if not self.api_key:
            logger.warning("Groq API key not found. Adaptive payloads disabled.")
            self.client = None
        else:
            self.client = Groq(api_key=self.api_key)
            logger.info("Adaptive payload generator initialized with Groq")
    
    def is_enabled(self) -> bool:
        """Check if adaptive payload generation is enabled."""
        return self.client is not None
    
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
            
            # Generate payload using Groq
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",  # Updated model
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert API security researcher specializing in SQL injection. "
                            "Generate advanced SQL injection payloads based on historical success patterns. "
                            "Return ONLY the payload string, no explanations."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,  # Low temperature for focused generation
                max_tokens=200,
            )
            
            payload = response.choices[0].message.content.strip()
            
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
            
            # Generate strategy using Groq
            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",  # Updated model
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert API security researcher specializing in IDOR vulnerabilities. "
                            "Suggest advanced IDOR testing strategies based on historical success patterns. "
                            "Return a JSON object with 'test_ids' (array of IDs to test) and 'strategy' (brief description)."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=300,
            )
            
            strategy_text = response.choices[0].message.content.strip()
            
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
