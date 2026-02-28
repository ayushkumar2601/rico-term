"""Quick test script for Agentic AI functionality."""
import asyncio
import os
from rico.ai.groq_client import GroqClient
from rico.ai.agent import RicoAgent


async def test_agentic_ai():
    """Test the agentic AI components."""
    
    print("=" * 80)
    print("RICO Agentic AI Test")
    print("=" * 80)
    print()
    
    # Check for API key
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("❌ GROQ_API_KEY not set")
        print()
        print("Set it with:")
        print("  export GROQ_API_KEY=your_key  # Linux/Mac")
        print("  setx GROQ_API_KEY \"your_key\"  # Windows")
        return
    
    print(f"✅ API Key found: {api_key[:10]}...{api_key[-4:]}")
    print()
    
    # Initialize client and agent
    print("Initializing Groq client and RICO agent...")
    groq_client = GroqClient(api_key=api_key)
    agent = RicoAgent(groq_client=groq_client)
    print("✅ Initialized successfully")
    print()
    
    # Create mock scan results
    print("Creating mock scan results...")
    scan_results = {
        "target_url": "http://localhost:8000",
        "total_endpoints": 3,
        "security_score": 54,
        "risk_level": "MEDIUM",
        "vulnerabilities": [
            {
                "endpoint": "/sqli/search",
                "attack_type": "SQL Injection",
                "severity": "Critical",
                "confidence": 92,
                "status": "VULNERABLE",
                "details": "Boolean-based blind SQL injection detected"
            },
            {
                "endpoint": "/users/{user_id}",
                "attack_type": "IDOR",
                "severity": "High",
                "confidence": 90,
                "status": "VULNERABLE",
                "details": "No authorization check - any user can access any user's data"
            },
            {
                "endpoint": "/admin/users",
                "attack_type": "Missing Auth",
                "severity": "High",
                "confidence": 85,
                "status": "VULNERABLE",
                "details": "Admin endpoint accessible without authentication"
            }
        ],
        "endpoints_tested": [
            {"method": "GET", "path": "/sqli/search"},
            {"method": "GET", "path": "/users/{user_id}"},
            {"method": "GET", "path": "/admin/users"}
        ]
    }
    print("✅ Mock data created")
    print()
    
    # Run AI analysis
    print("Running agentic AI analysis...")
    print("(This may take 2-4 seconds)")
    print()
    
    try:
        analysis = await agent.analyze_scan(scan_results, timeout=30.0)
        print("✅ AI analysis completed successfully")
        print()
        
        # Display formatted analysis
        formatted = agent.format_analysis_for_display(analysis)
        print(formatted)
        print()
        
        # Show JSON structure
        print("=" * 80)
        print("JSON Structure")
        print("=" * 80)
        print()
        print("Keys in analysis:")
        for key in analysis.keys():
            print(f"  - {key}")
        print()
        
        # Show priority matrix
        if "priority_matrix" in analysis and analysis["priority_matrix"]:
            print(f"Priority Matrix Items: {len(analysis['priority_matrix'])}")
        
        # Show exploit chains
        if "exploit_chains" in analysis and analysis["exploit_chains"]:
            print(f"Exploit Chains Detected: {len(analysis['exploit_chains'])}")
        
        # Show remediation items
        if "remediation_plan" in analysis and analysis["remediation_plan"]:
            print(f"Remediation Items: {len(analysis['remediation_plan'])}")
        
        print()
        print("=" * 80)
        print("✅ Test completed successfully!")
        print("=" * 80)
        
    except Exception as e:
        print(f"❌ AI analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_agentic_ai())
