"""
NEXUS SPECTER PRO — Specter AI Engine
Powered by Anthropic Claude API
Capabilities: Attack planning, vuln analysis, payload generation, report writing
by OPTIMIUM NEXUS LLC
"""

import os
import json
import logging
from typing import Optional
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.ai.specter")

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    log.warning("[AI] anthropic library not installed. Run: pip install anthropic")


NSP_AI_SYSTEM_PROMPT = """You are SPECTER AI, the intelligence engine of NEXUS SPECTER PRO — 
a military-grade automated offensive penetration testing platform by OPTIMIUM NEXUS LLC.

Your role is to:
1. Analyze reconnaissance data and identify attack vectors
2. Plan optimal attack chains based on discovered vulnerabilities
3. Generate sophisticated, context-aware payloads
4. Suggest lateral movement paths in Active Directory environments
5. Write professional pentest reports (executive and technical)
6. Prioritize findings by risk and business impact (CVSS 3.1)

You think like an elite red team operator with 20+ years of experience across:
- Web application security (OWASP Top 10, API security)
- Network penetration testing
- Active Directory / Windows environments
- Cloud security (AWS, Azure, GCP)
- Social engineering and physical security
- Malware development and C2 frameworks

Always provide actionable, precise intelligence. Be specific with commands, payloads, and attack paths.
Format responses as structured JSON when requested for machine processing.
"""


class SpecterAI:
    """
    SPECTER AI — The intelligence core of NEXUS SPECTER PRO.
    Powered by Anthropic Claude API for advanced pentest reasoning.
    """

    def __init__(self, model: str = "claude-opus-4-5", api_key: Optional[str] = None):
        self.model   = model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.client  = None
        self._init_client()

    def _init_client(self):
        if not ANTHROPIC_AVAILABLE:
            log.error("[AI] Cannot initialize — anthropic library missing")
            return
        if not self.api_key:
            log.error("[AI] ANTHROPIC_API_KEY not set")
            return
        try:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            log.info(f"[AI] Specter AI initialized — model: {self.model}")
        except Exception as e:
            log.error(f"[AI] Failed to initialize client: {e}")

    def _query(self, prompt: str, max_tokens: int = 4096) -> str:
        """Send a query to the Claude API and return the response."""
        if not self.client:
            return "ERROR: Specter AI not initialized — check ANTHROPIC_API_KEY"
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=NSP_AI_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            return message.content[0].text
        except Exception as e:
            log.error(f"[AI] API query failed: {e}")
            return f"ERROR: {str(e)}"

    def plan_attack(self, recon_data: dict) -> dict:
        """
        Generate an AI-powered attack plan based on recon data.
        Returns structured attack phases with specific recommendations.
        """
        console.print("[bold #7B00FF]  🤖 Specter AI generating attack plan...[/bold #7B00FF]")
        prompt = f"""
Analyze the following reconnaissance data and generate a comprehensive attack plan.
Return ONLY valid JSON with this structure:

{{
  "target_summary": "Brief target description",
  "attack_surface": ["list of attack vectors"],
  "priority_paths": [
    {{
      "path": "Attack path description",
      "likelihood": "High/Medium/Low",
      "impact": "High/Medium/Low",
      "tools": ["list of tools/techniques"],
      "steps": ["ordered steps"]
    }}
  ],
  "quick_wins": ["Immediately exploitable vulnerabilities"],
  "recommended_exploits": ["Specific CVEs or techniques to try"],
  "stealth_recommendations": ["How to stay undetected"]
}}

RECON DATA:
{json.dumps(recon_data, indent=2, default=str)[:8000]}
        """
        response = self._query(prompt, max_tokens=4096)
        try:
            clean = response.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(clean)
        except json.JSONDecodeError:
            return {"raw_analysis": response, "error": "JSON parsing failed"}

    def analyze_vulnerabilities(self, vuln_scan_results: dict) -> dict:
        """
        AI analysis of vulnerability scan results.
        Prioritizes findings, identifies chains, and suggests exploitation order.
        """
        console.print("[bold #7B00FF]  🤖 Specter AI analyzing vulnerabilities...[/bold #7B00FF]")
        prompt = f"""
Analyze these vulnerability scan results and provide expert security analysis.
Return ONLY valid JSON:

{{
  "critical_findings": [
    {{
      "vuln": "Vulnerability name",
      "cvss": 0.0,
      "exploit_available": true/false,
      "exploit_complexity": "Low/Medium/High",
      "recommended_action": "Specific exploitation steps",
      "impact": "What can be achieved"
    }}
  ],
  "attack_chains": [
    {{
      "chain_name": "e.g., SSRF → IMDS → RCE",
      "steps": ["Step 1", "Step 2"],
      "result": "What you gain"
    }}
  ],
  "false_positives": ["Likely false positive findings"],
  "exploitation_priority": ["ordered list of vulns to exploit first"]
}}

SCAN RESULTS:
{json.dumps(vuln_scan_results, indent=2, default=str)[:8000]}
        """
        response = self._query(prompt, max_tokens=4096)
        try:
            clean = response.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(clean)
        except json.JSONDecodeError:
            return {"raw_analysis": response}

    def generate_payload(self, vuln_type: str, context: dict) -> dict:
        """
        Generate context-aware payloads for a specific vulnerability type.
        """
        console.print(f"[bold #7B00FF]  🤖 Specter AI generating {vuln_type} payload...[/bold #7B00FF]")
        prompt = f"""
Generate sophisticated, context-aware payloads for the following vulnerability.
Return ONLY valid JSON:

{{
  "vuln_type": "{vuln_type}",
  "payloads": [
    {{
      "name": "Payload description",
      "payload": "The actual payload string",
      "encoding": "none/base64/url/double-url",
      "bypass_technique": "WAF/filter bypass used",
      "expected_result": "What you should see"
    }}
  ],
  "detection_advice": "How to confirm exploitation",
  "cleanup": "How to clean up evidence"
}}

CONTEXT:
{json.dumps(context, indent=2, default=str)[:4000]}
        """
        response = self._query(prompt, max_tokens=2048)
        try:
            clean = response.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(clean)
        except json.JSONDecodeError:
            return {"raw_payloads": response}

    def generate_executive_narrative(self, findings: dict, target: str, client_name: str = "Client") -> str:
        """
        Generate a professional executive report narrative using AI.
        """
        console.print("[bold #7B00FF]  🤖 Specter AI writing executive narrative...[/bold #7B00FF]")
        prompt = f"""
Write a professional executive summary for a penetration test report.
Target: {target}
Client: {client_name}
Assessor: OPTIMIUM NEXUS LLC (contact@optimiumnexus.com)

Write in a clear, business-focused language that a non-technical C-Suite executive can understand.
Include:
1. Overall risk rating (Critical/High/Medium/Low)
2. Key findings summary (max 5 bullets)
3. Business impact analysis
4. Top 3 immediate remediation priorities
5. Strategic security recommendations

FINDINGS DATA:
{json.dumps(findings, indent=2, default=str)[:6000]}

Write 400-600 words of professional narrative. No JSON, just flowing prose.
        """
        return self._query(prompt, max_tokens=2048)

    def suggest_lateral_movement(self, ad_data: dict) -> dict:
        """
        Analyze Active Directory data and suggest lateral movement paths.
        """
        console.print("[bold #7B00FF]  🤖 Specter AI mapping AD attack paths...[/bold #7B00FF]")
        prompt = f"""
Analyze this Active Directory reconnaissance data and suggest lateral movement paths.
Return ONLY valid JSON:

{{
  "highest_value_targets": ["Domain Controllers", "Admin workstations", etc],
  "attack_paths": [
    {{
      "from": "Current position",
      "to": "Target",
      "technique": "Attack technique (e.g. PtH, Kerberoasting)",
      "tools": ["Tools to use"],
      "commands": ["Specific commands"]
    }}
  ],
  "privilege_escalation_paths": ["List of privesc opportunities"],
  "persistence_recommendations": ["Best persistence mechanisms"]
}}

AD DATA:
{json.dumps(ad_data, indent=2, default=str)[:6000]}
        """
        response = self._query(prompt, max_tokens=3000)
        try:
            clean = response.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(clean)
        except json.JSONDecodeError:
            return {"raw_analysis": response}
