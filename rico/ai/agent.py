"""Agentic AI reasoning engine for RICO security analysis."""
import json
import logging
from typing import Dict, List, Any, Optional
from rico.ai.groq_client import GroqClient

logger = logging.getLogger("rico.ai.agent")


class RicoAgent:
    """
    Agentic AI reasoning layer for intelligent security analysis.
    
    This agent analyzes deterministic scan results and provides:
    - Risk prioritization
    - Exploit chain detection
    - Business impact assessment
    - Remediation strategies
    - Executive summaries
    """
    
    def __init__(self, groq_client: GroqClient):
        """
        Initialize RICO agent.
        
        Args:
            groq_client: Configured Groq API client
        """
        self.groq_client = groq_client
    
    def _build_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """
        Build structured prompt for AI analysis.
        
        Args:
            scan_results: Structured scan results from RICO
            
        Returns:
            Formatted prompt string
        """
        # Extract key information
        target_url = scan_results.get("target_url", "Unknown")
        total_endpoints = scan_results.get("total_endpoints", 0)
        vulnerabilities = scan_results.get("vulnerabilities", [])
        security_score = scan_results.get("security_score", 0)
        risk_level = scan_results.get("risk_level", "UNKNOWN")
        
        # Format vulnerabilities
        vuln_summary = []
        for vuln in vulnerabilities:
            vuln_summary.append({
                "endpoint": vuln.get("endpoint", ""),
                "attack_type": vuln.get("attack_type", ""),
                "severity": vuln.get("severity", ""),  # PHASE 4: Severity from deterministic engine
                "confidence": vuln.get("confidence", 0),
                "status": vuln.get("status", ""),
                "details": vuln.get("details", "")
            })
        
        # Build structured JSON for the prompt
        scan_data = {
            "target": target_url,
            "total_endpoints_tested": total_endpoints,
            "security_score": security_score,
            "risk_level": risk_level,
            "vulnerabilities": vuln_summary,
            "endpoints_tested": scan_results.get("endpoints_tested", [])
        }
        
        prompt = f"""You are a senior application security expert analyzing API vulnerability scan results.

Given the following structured vulnerability scan results:

{json.dumps(scan_data, indent=2)}

Perform comprehensive security analysis:

1. **Risk Prioritization**: Rank vulnerabilities by exploitability and business impact
2. **Exploit Chain Detection**: Identify combinations of vulnerabilities that enable attack escalation
3. **Business Risk Assessment**: Evaluate potential business impact (data breach, compliance, reputation)
4. **Attack Escalation Paths**: Map how attackers could chain vulnerabilities
5. **Remediation Strategy**: Provide prioritized, actionable fix recommendations
6. **Executive Summary**: Non-technical summary for leadership

CRITICAL REQUIREMENTS:
- Respond in STRICT JSON format only
- No markdown, no code blocks, no explanations outside JSON
- Base analysis ONLY on provided scan results
- Do NOT hallucinate vulnerabilities not in the scan
- Do NOT invent endpoints not tested
- Focus on REAL exploit chains from ACTUAL findings
- SEVERITY LOCK: You MUST use the provided severity values from the scan
- Do NOT override or reassign severity levels - they are deterministic
- The severity field in each vulnerability is FINAL and cannot be changed
- RISK ALIGNMENT: Your executive summary MUST reflect the provided risk_level ({risk_level})
- If risk_level is CRITICAL or HIGH, your summary must emphasize urgency and severity
- If risk_level is MEDIUM or LOW, your summary should be proportionally measured
- Do NOT contradict the deterministic security_score ({security_score}/100) in your analysis

Response format:
{{
  "priority_matrix": [
    {{
      "rank": 1,
      "endpoint": "...",
      "attack_type": "...",
      "severity": "...",
      "exploitability": "high|medium|low",
      "business_impact": "...",
      "rationale": "..."
    }}
  ],
  "exploit_chains": [
    {{
      "chain_id": 1,
      "name": "...",
      "steps": ["step1", "step2", "step3"],
      "vulnerabilities_used": ["vuln1", "vuln2"],
      "impact": "...",
      "likelihood": "high|medium|low"
    }}
  ],
  "business_risk": {{
    "data_exposure": "...",
    "compliance_impact": "...",
    "reputation_risk": "...",
    "financial_impact": "...",
    "overall_risk_level": "{risk_level}"
  }},
  "remediation_plan": [
    {{
      "priority": "critical|high|medium|low",
      "action": "...",
      "endpoints_affected": ["..."],
      "estimated_effort": "...",
      "dependencies": ["..."]
    }}
  ],
  "executive_summary": "Non-technical summary for leadership (2-3 sentences)",
  "technical_summary": "Technical summary for security team (3-4 sentences)"
}}

Respond with ONLY the JSON object. No additional text."""

        return prompt
    
    async def analyze_scan(
        self,
        scan_results: Dict[str, Any],
        timeout: float = 60.0
    ) -> Dict[str, Any]:
        """
        Analyze scan results using AI reasoning.
        
        Args:
            scan_results: Structured scan results from RICO
            timeout: API request timeout
            
        Returns:
            Structured AI analysis as dict
            
        Raises:
            ValueError: If analysis fails or returns invalid data
        """
        logger.info("Starting agentic AI analysis...")
        
        # Validate input
        if not scan_results:
            raise ValueError("Scan results cannot be empty")
        
        if "vulnerabilities" not in scan_results:
            raise ValueError("Scan results must contain 'vulnerabilities' key")
        
        # Build prompt
        prompt = self._build_analysis_prompt(scan_results)
        
        # Get AI analysis
        try:
            analysis = await self.groq_client.analyze_with_json(
                prompt=prompt,
                timeout=timeout
            )
            
            # Validate response structure
            required_keys = [
                "priority_matrix",
                "exploit_chains",
                "business_risk",
                "remediation_plan",
                "executive_summary"
            ]
            
            missing_keys = [key for key in required_keys if key not in analysis]
            if missing_keys:
                logger.warning(f"AI response missing keys: {missing_keys}")
                # Add empty structures for missing keys
                for key in missing_keys:
                    if key == "priority_matrix":
                        analysis[key] = []
                    elif key == "exploit_chains":
                        analysis[key] = []
                    elif key == "business_risk":
                        analysis[key] = {}
                    elif key == "remediation_plan":
                        analysis[key] = []
                    elif key in ["executive_summary", "technical_summary"]:
                        analysis[key] = ""
            
            logger.info("Agentic AI analysis completed successfully")
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            raise
    
    def format_analysis_for_display(self, analysis: Dict[str, Any]) -> str:
        """
        Format AI analysis for console display.
        
        Args:
            analysis: AI analysis dict
            
        Returns:
            Formatted string for display
        """
        lines = []
        
        lines.append("=" * 80)
        lines.append("AGENTIC AI SECURITY ANALYSIS")
        lines.append("=" * 80)
        lines.append("")
        
        # Executive Summary
        if "executive_summary" in analysis:
            lines.append("📊 EXECUTIVE SUMMARY")
            lines.append("-" * 80)
            lines.append(analysis["executive_summary"])
            lines.append("")
        
        # Technical Summary
        if "technical_summary" in analysis:
            lines.append("🔧 TECHNICAL SUMMARY")
            lines.append("-" * 80)
            lines.append(analysis["technical_summary"])
            lines.append("")
        
        # Priority Matrix
        if "priority_matrix" in analysis and analysis["priority_matrix"]:
            lines.append("🎯 RISK PRIORITIZATION")
            lines.append("-" * 80)
            for item in analysis["priority_matrix"][:5]:  # Top 5
                rank = item.get("rank", "?")
                endpoint = item.get("endpoint", "Unknown")
                attack = item.get("attack_type", "Unknown")
                severity = item.get("severity", "Unknown")
                exploitability = item.get("exploitability", "Unknown")
                
                lines.append(f"  #{rank}. {endpoint}")
                lines.append(f"      Attack: {attack} | Severity: {severity} | Exploitability: {exploitability}")
                
                rationale = item.get("rationale", "")
                if rationale:
                    lines.append(f"      Rationale: {rationale}")
                lines.append("")
        
        # Exploit Chains
        if "exploit_chains" in analysis and analysis["exploit_chains"]:
            lines.append("⛓️  EXPLOIT CHAINS DETECTED")
            lines.append("-" * 80)
            for chain in analysis["exploit_chains"]:
                name = chain.get("name", "Unknown Chain")
                likelihood = chain.get("likelihood", "unknown")
                impact = chain.get("impact", "")
                
                lines.append(f"  • {name} (Likelihood: {likelihood})")
                
                steps = chain.get("steps", [])
                if steps:
                    lines.append("    Steps:")
                    for i, step in enumerate(steps, 1):
                        lines.append(f"      {i}. {step}")
                
                if impact:
                    lines.append(f"    Impact: {impact}")
                lines.append("")
        
        # Business Risk
        if "business_risk" in analysis and analysis["business_risk"]:
            lines.append("💼 BUSINESS RISK ASSESSMENT")
            lines.append("-" * 80)
            risk = analysis["business_risk"]
            
            if "data_exposure" in risk:
                lines.append(f"  Data Exposure: {risk['data_exposure']}")
            if "compliance_impact" in risk:
                lines.append(f"  Compliance: {risk['compliance_impact']}")
            if "reputation_risk" in risk:
                lines.append(f"  Reputation: {risk['reputation_risk']}")
            if "financial_impact" in risk:
                lines.append(f"  Financial: {risk['financial_impact']}")
            lines.append("")
        
        # Remediation Plan
        if "remediation_plan" in analysis and analysis["remediation_plan"]:
            lines.append("🔨 REMEDIATION STRATEGY")
            lines.append("-" * 80)
            for item in analysis["remediation_plan"][:5]:  # Top 5
                priority = item.get("priority", "unknown").upper()
                action = item.get("action", "")
                effort = item.get("estimated_effort", "")
                
                lines.append(f"  [{priority}] {action}")
                if effort:
                    lines.append(f"          Effort: {effort}")
                
                endpoints = item.get("endpoints_affected", [])
                if endpoints:
                    lines.append(f"          Affects: {', '.join(endpoints[:3])}")
                lines.append("")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)
