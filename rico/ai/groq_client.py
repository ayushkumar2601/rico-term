"""Groq API client for AI-powered security analysis."""
import os
import logging
from typing import Optional
import httpx

logger = logging.getLogger("rico.ai.groq")


class GroqClient:
    """Client for interacting with Groq's Chat Completions API."""
    
    BASE_URL = "https://api.groq.com/openai/v1"
    MODEL = "llama-3.3-70b-versatile"
    TEMPERATURE = 0.2  # Low randomness for deterministic reasoning
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Groq client.
        
        Args:
            api_key: Groq API key. If None, reads from GROQ_API_KEY env var.
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        
        if not self.api_key:
            raise ValueError(
                "Groq API key not found. Set GROQ_API_KEY environment variable "
                "or pass api_key parameter."
            )
        
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    async def analyze(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: float = 60.0
    ) -> str:
        """
        Send analysis request to Groq API.
        
        Args:
            prompt: User prompt with scan results
            system_prompt: Optional system prompt (defaults to security expert)
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
            
        Returns:
            AI-generated analysis as string
            
        Raises:
            httpx.HTTPError: If API request fails
            ValueError: If response is invalid
        """
        if not system_prompt:
            system_prompt = (
                "You are a senior application security expert specializing in "
                "API security, vulnerability analysis, and exploit chain detection. "
                "Provide structured, actionable security analysis."
            )
        
        payload = {
            "model": self.MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": self.TEMPERATURE,
            "max_tokens": max_tokens,
            "top_p": 1,
            "stream": False
        }
        
        logger.info(f"Sending request to Groq API (model: {self.MODEL})")
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers=self.headers,
                    json=payload
                )
                response.raise_for_status()
                
                data = response.json()
                
                # Extract content from response
                if "choices" not in data or len(data["choices"]) == 0:
                    raise ValueError("Invalid response from Groq API: no choices")
                
                content = data["choices"][0]["message"]["content"]
                
                logger.info(f"Received response from Groq API ({len(content)} chars)")
                
                return content
                
            except httpx.HTTPStatusError as e:
                logger.error(f"Groq API error: {e.response.status_code} - {e.response.text}")
                raise
            except httpx.TimeoutException:
                logger.error("Groq API request timed out")
                raise
            except Exception as e:
                logger.error(f"Unexpected error calling Groq API: {str(e)}")
                raise
    
    async def analyze_with_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: float = 60.0
    ) -> dict:
        """
        Send analysis request and parse JSON response.
        
        Args:
            prompt: User prompt with scan results
            system_prompt: Optional system prompt
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
            
        Returns:
            Parsed JSON response as dict
            
        Raises:
            ValueError: If response is not valid JSON
        """
        import json
        
        response = await self.analyze(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            timeout=timeout
        )
        
        # Try to extract JSON from response
        # Sometimes the model wraps JSON in markdown code blocks
        response = response.strip()
        
        # Remove markdown code blocks if present
        if response.startswith("```json"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]
        
        if response.endswith("```"):
            response = response[:-3]
        
        response = response.strip()
        
        try:
            return json.loads(response)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {str(e)}")
            logger.error(f"Response: {response[:500]}")
            raise ValueError(f"Invalid JSON response from AI: {str(e)}")
