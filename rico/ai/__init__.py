"""
RICO AI Module - Hybrid Adaptive Intelligence Architecture

This module provides AI-powered adaptive payload generation using:
- Snowflake: Security Intelligence Warehouse (storage + retrieval)
- AI Provider: LLM Reasoning Engine (Groq or Cortex)

Architecture:
1. Snowflake stores historical exploit intelligence
2. AI provider generates adaptive payloads based on patterns
3. Results stored back in Snowflake for continuous learning

Components:
- provider.py: AI provider abstraction layer (Groq/Cortex switching)
- groq_client.py: Groq LLM client (current default)
- cortex.py: Snowflake Cortex client (future-ready)
- adaptive_payloads.py: Adaptive payload generation logic
- agent.py: Legacy AI agent (deprecated, use adaptive_payloads)
"""

from rico.ai.provider import (
    generate_completion,
    is_ai_enabled,
    get_provider_info,
    log_provider_status
)

from rico.ai.adaptive_payloads import (
    AdaptivePayloadGenerator,
    get_adaptive_generator,
    generate_adaptive_payload
)

__all__ = [
    "generate_completion",
    "is_ai_enabled",
    "get_provider_info",
    "log_provider_status",
    "AdaptivePayloadGenerator",
    "get_adaptive_generator",
    "generate_adaptive_payload",
]
