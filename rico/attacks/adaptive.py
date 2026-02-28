"""Adaptive attack loop using Snowflake intelligence and Cortex LLM."""
import logging
from typing import Dict, Any, List, Optional
from rico.db.snowflake_client import is_snowflake_enabled
from rico.db.retrieve import (
    get_top_successful_payloads,
    get_payload_statistics,
    get_framework_specific_payloads
)
from rico.db.insert import insert_payload_result
from rico.ai.cortex import cortex_generate_payload, cortex_analyze_response

# Setup logger
logger = logging.getLogger("rico.adaptive")


class AdaptiveAttackEngine:
    """
    Adaptive attack engine that learns from historical data.
    
    This engine implements the core adaptive loop:
    1. Retrieve successful payloads from Snowflake
    2. Use Cortex LLM to generate advanced payloads
    3. Execute attacks
    4. Store results back to Snowflake
    5. Repeat with improved intelligence
    """
    
    def __init__(self, scan_id: Optional[str] = None):
        """
        Initialize the adaptive attack engine.
        
        Args:
            scan_id: Current scan ID for tracking
        """
        self.scan_id = scan_id
        self.snowflake_enabled = is_snowflake_enabled()
        
        if self.snowflake_enabled:
            logger.info("[OK] Adaptive attack engine initialized with Snowflake intelligence")
        else:
            logger.info("Adaptive attack engine initialized (Snowflake disabled)")
    
    def get_adaptive_payloads(
        self,
        vulnerability_type: str,
        endpoint_path: str,
        api_framework: str = "Unknown",
        base_payloads: Optional[List[str]] = None
    ) -> List[str]:
        """
        Get adaptive payloads based on historical intelligence.
        
        Args:
            vulnerability_type: Type of vulnerability (SQLi, IDOR, etc.)
            endpoint_path: Target endpoint
            api_framework: API framework
            base_payloads: Fallback payloads if no intelligence available
            
        Returns:
            List of payloads to try (adaptive + base)
        """
        if not self.snowflake_enabled:
            logger.debug("Snowflake disabled, using base payloads only")
            return base_payloads or []
        
        try:
            # Retrieve historical successful payloads
            logger.info(f"Retrieving historical {vulnerability_type} intelligence...")
            
            historical_payloads = get_top_successful_payloads(
                vulnerability_type=vulnerability_type,
                limit=5,
                api_framework=api_framework
            )
            
            if historical_payloads:
                logger.info(f"[OK] Found {len(historical_payloads)} successful historical payloads")
                
                # Get statistics
                stats = get_payload_statistics(vulnerability_type)
                logger.info(
                    f"Intelligence: {stats.get('successful', 0)}/{stats.get('total_attempts', 0)} "
                    f"success rate: {stats.get('success_rate', 0)}%"
                )
                
                # Generate advanced payload using Cortex LLM
                logger.info("Generating adaptive payload with Cortex LLM...")
                adaptive_payload = cortex_generate_payload(
                    vulnerability_type=vulnerability_type,
                    endpoint_path=endpoint_path,
                    historical_payloads=historical_payloads,
                    api_framework=api_framework
                )
                
                if adaptive_payload:
                    logger.info(f"[OK] Cortex generated adaptive payload: {adaptive_payload[:50]}...")
                    
                    # Combine: adaptive payload + historical + base
                    all_payloads = [adaptive_payload] + historical_payloads
                    
                    if base_payloads:
                        # Add base payloads that aren't already in the list
                        for bp in base_payloads:
                            if bp not in all_payloads:
                                all_payloads.append(bp)
                    
                    return all_payloads[:10]  # Limit to top 10
                else:
                    logger.warning("Cortex payload generation failed, using historical only")
                    return historical_payloads + (base_payloads or [])
            else:
                logger.info("No historical intelligence found, using base payloads")
                return base_payloads or []
                
        except Exception as e:
            logger.error(f"Error retrieving adaptive payloads: {e}")
            return base_payloads or []
    
    def log_payload_result(
        self,
        vulnerability_type: str,
        payload: str,
        endpoint_path: str,
        response_code: int,
        response_time_ms: float,
        response_text: str,
        exploit_success: bool,
        api_framework: str = "Unknown",
        auth_type: str = "None"
    ) -> bool:
        """
        Log payload test result to Snowflake for future intelligence.
        
        Args:
            vulnerability_type: Type of vulnerability
            payload: Payload used
            endpoint_path: Endpoint tested
            response_code: HTTP response code
            response_time_ms: Response time
            response_text: Response body
            exploit_success: Whether exploit succeeded
            api_framework: API framework
            auth_type: Authentication type
            
        Returns:
            bool: True if logged successfully
        """
        if not self.snowflake_enabled:
            return False
        
        try:
            # Use Cortex to analyze response if not already determined
            if not exploit_success and response_code == 200:
                logger.debug("Using Cortex to analyze ambiguous response...")
                analysis = cortex_analyze_response(
                    vulnerability_type=vulnerability_type,
                    response_text=response_text,
                    response_code=response_code,
                    response_time_ms=response_time_ms
                )
                
                if analysis.get("success") and analysis.get("confidence", 0) > 70:
                    logger.info(f"Cortex detected exploit success: {analysis.get('reasoning')}")
                    exploit_success = True
            
            # Insert payload result
            payload_id = insert_payload_result({
                "scan_id": self.scan_id or "unknown",
                "vulnerability_type": vulnerability_type,
                "payload": payload,
                "api_framework": api_framework,
                "auth_type": auth_type,
                "endpoint_path": endpoint_path,
                "response_code": response_code,
                "response_time_ms": response_time_ms,
                "exploit_success": exploit_success
            })
            
            if payload_id:
                if exploit_success:
                    logger.info(f"[OK] Successful exploit logged to Snowflake: {payload_id}")
                else:
                    logger.debug(f"Payload result logged: {payload_id}")
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Failed to log payload result: {e}")
            return False
    
    def get_framework_intelligence(
        self,
        vulnerability_type: str,
        api_framework: str
    ) -> Dict[str, Any]:
        """
        Get framework-specific intelligence for targeted attacks.
        
        Args:
            vulnerability_type: Type of vulnerability
            api_framework: API framework
            
        Returns:
            Dict with framework-specific intelligence
        """
        if not self.snowflake_enabled:
            return {}
        
        try:
            payloads = get_framework_specific_payloads(
                vulnerability_type=vulnerability_type,
                api_framework=api_framework,
                limit=10
            )
            
            if payloads:
                logger.info(f"[OK] Retrieved {len(payloads)} {api_framework}-specific payloads")
                
                # Extract patterns
                common_patterns = []
                for p in payloads:
                    if p.get("payload"):
                        common_patterns.append(p["payload"])
                
                return {
                    "framework": api_framework,
                    "payload_count": len(payloads),
                    "common_patterns": common_patterns[:5],
                    "avg_response_time": sum(p.get("response_time_ms", 0) for p in payloads) / len(payloads)
                }
            else:
                return {}
                
        except Exception as e:
            logger.error(f"Failed to get framework intelligence: {e}")
            return {}


def create_adaptive_engine(scan_id: Optional[str] = None) -> AdaptiveAttackEngine:
    """
    Factory function to create an adaptive attack engine.
    
    Args:
        scan_id: Current scan ID
        
    Returns:
        AdaptiveAttackEngine instance
    """
    return AdaptiveAttackEngine(scan_id=scan_id)
