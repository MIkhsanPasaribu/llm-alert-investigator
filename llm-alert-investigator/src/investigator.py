"""Alert investigator using LLM with RAG for MITRE ATT&CK mapping."""

import json
from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from src.kb_builder import MITREKnowledgeBaseBuilder
from src.preprocessor import AlertPreprocessor


class AlertInvestigator:
    """Investigates security alerts using LLM with RAG for MITRE ATT&CK mapping."""

    def __init__(
        self,
        model: str = "gpt-4o",
        temperature: float = 0.0,
        retrieval_k: int = 5,
        mitre_kb_path: str = "data/mitre_attack_kb",
        prompt_path: str | None = None,
    ):
        self.model = model
        self.temperature = temperature
        self.retrieval_k = retrieval_k
        self.mitre_kb_path = mitre_kb_path

        self.llm = ChatOpenAI(model=model, temperature=temperature)
        self.preprocessor = AlertPreprocessor()

        kb_builder = MITREKnowledgeBaseBuilder()
        if Path(mitre_kb_path).exists():
            self.mitre_kb = kb_builder.load(mitre_kb_path)
        else:
            self.mitre_kb = kb_builder.build_from_mitre()
            kb_builder.save(mitre_kb_path)

        self.prompt_template = self._load_prompt_template(prompt_path)

    def investigate(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Investigate a security alert and return analysis results.

        Args:
            alert: Raw alert dictionary from SIEM

        Returns:
            Dictionary containing MITRE mapping, narrative, next steps, and severity
        """
        normalized_alert = self.preprocessor.normalize(alert)
        enriched_alert = self.preprocessor.enrich(normalized_alert)

        alert_text = self._format_alert(enriched_alert)
        relevant_techniques = self.mitre_kb.similarity_search(alert_text, k=self.retrieval_k)

        mitre_context = self._format_techniques(relevant_techniques)

        prompt = ChatPromptTemplate.from_template(self.prompt_template)

        chain = prompt | self.llm

        response = chain.invoke(
            {
                "alert": alert_text,
                "mitre_context": mitre_context,
            }
        )

        try:
            result = json.loads(response.content)
        except json.JSONDecodeError:
            result = self._parse_fallback(response.content)

        result["raw_alert"] = alert
        result["normalized_alert"] = normalized_alert
        result["enriched_alert"] = enriched_alert
        result["retrieved_techniques"] = [
            {
                "technique_id": doc.metadata.get("technique_id"),
                "technique_name": doc.metadata.get("technique_name"),
                "tactics": doc.metadata.get("tactics"),
            }
            for doc in relevant_techniques
        ]

        return result

    def investigate_batch(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Investigate multiple alerts in batch.

        Args:
            alerts: List of raw alert dictionaries

        Returns:
            List of investigation results
        """
        results = []
        for alert in alerts:
            try:
                result = self.investigate(alert)
                results.append(result)
            except Exception as e:
                results.append(
                    {
                        "error": str(e),
                        "raw_alert": alert,
                        "mitre_mapping": [],
                        "narrative": f"Error during investigation: {e}",
                        "next_steps": [],
                        "severity": "unknown",
                    }
                )
        return results

    def _format_alert(self, alert: dict[str, Any]) -> str:
        """Format alert for LLM prompt."""
        parts = []

        if alert.get("timestamp"):
            parts.append(f"Timestamp: {alert['timestamp']}")

        if alert.get("event_type"):
            parts.append(f"Event Type: {alert['event_type']}")

        if alert.get("src_ip") and alert.get("dst_ip"):
            parts.append(
                f"Network: {alert['src_ip']}:{alert.get('src_port', 'N/A')} -> {alert['dst_ip']}:{alert.get('dst_port', 'N/A')}"
            )
        elif alert.get("src_ip"):
            parts.append(f"Source IP: {alert['src_ip']}")

        if alert.get("process"):
            parts.append(f"Process: {alert['process']}")

        if alert.get("command_line"):
            parts.append(f"Command Line: {alert['command_line']}")

        if alert.get("file_hash"):
            parts.append(f"File Hash: {alert['file_hash']}")

        if alert.get("severity"):
            parts.append(f"Severity: {alert['severity']}")

        if alert.get("ioc_hints"):
            ioc_parts = []
            if alert["ioc_hints"].get("urls"):
                ioc_parts.append(f"URLs: {', '.join(alert['ioc_hints']['urls'])}")
            if alert["ioc_hints"].get("domains"):
                ioc_parts.append(f"Domains: {', '.join(alert['ioc_hints']['domains'])}")
            if alert["ioc_hints"].get("ips"):
                ioc_parts.append(f"IPs: {', '.join(alert['ioc_hints']['ips'])}")
            if ioc_parts:
                parts.append(f"IOCs: {' | '.join(ioc_parts)}")

        if alert.get("attack_indicators"):
            indicators = []
            for key, value in alert["attack_indicators"].items():
                if value:
                    indicators.append(key.replace("has_", "").replace("_", " "))
            if indicators:
                parts.append(f"Attack Indicators: {', '.join(indicators)}")

        return "\n".join(parts)

    def _format_techniques(self, techniques: list[Document]) -> str:
        """Format retrieved MITRE techniques for LLM prompt."""
        if not techniques:
            return "No relevant MITRE techniques found."

        formatted = []
        for i, doc in enumerate(techniques, 1):
            technique_id = doc.metadata.get("technique_id", "Unknown")
            technique_name = doc.metadata.get("technique_name", "Unknown")
            tactics = doc.metadata.get("tactics", "Unknown")

            formatted.append(
                f"{i}. {technique_id} - {technique_name}\n"
                f"   Tactics: {tactics}\n"
                f"   Details: {doc.page_content[:300]}..."
            )

        return "\n\n".join(formatted)

    def _load_prompt_template(self, prompt_path: str | None) -> str:
        """Load investigation prompt template from file or use default."""
        if prompt_path and Path(prompt_path).exists():
            with open(prompt_path, "r", encoding="utf-8") as f:
                return f.read()

        return """You are a SOC Level 2 analyst with expertise in threat hunting and incident response. Analyze this security alert and provide:

1. MITRE ATT&CK mapping (tactic + technique ID + technique name + confidence 0-1)
2. Investigation narrative explaining what likely happened
3. Recommended next steps for the analyst
4. Severity assessment (low|medium|high|critical)

ALERT:
{alert}

RELEVANT MITRE TECHNIQUES (from knowledge base):
{mitre_context}

Respond in valid JSON format:
{{
  "mitre_mapping": [
    {{
      "tactic": "...",
      "technique_id": "T...",
      "technique_name": "...",
      "confidence": 0.0
    }}
  ],
  "narrative": "...",
  "next_steps": ["...", "..."],
  "severity": "low|medium|high|critical"
}}

Guidelines:
- Confidence should be between 0.0 and 1.0 based on how well the alert matches the technique
- Narrative should be concise but comprehensive, explaining the attack chain
- Next steps should be actionable and specific
- Severity should consider both the technique's impact and the alert's context
- If multiple techniques are relevant, include all with appropriate confidence scores"""

    def _parse_fallback(self, content: str) -> dict[str, Any]:
        """Fallback parsing if JSON parsing fails."""
        return {
            "mitre_mapping": [],
            "narrative": content,
            "next_steps": ["Review the alert manually"],
            "severity": "medium",
        }


def investigate_alert(
    alert: dict[str, Any],
    model: str = "gpt-4o",
    temperature: float = 0.0,
    retrieval_k: int = 5,
    mitre_kb_path: str = "data/mitre_attack_kb",
) -> dict[str, Any]:
    """Convenience function to investigate a single alert."""
    investigator = AlertInvestigator(
        model=model,
        temperature=temperature,
        retrieval_k=retrieval_k,
        mitre_kb_path=mitre_kb_path,
    )
    return investigator.investigate(alert)


def investigate_alerts(
    alerts: list[dict[str, Any]],
    model: str = "gpt-4o",
    temperature: float = 0.0,
    retrieval_k: int = 5,
    mitre_kb_path: str = "data/mitre_attack_kb",
) -> list[dict[str, Any]]:
    """Convenience function to investigate multiple alerts."""
    investigator = AlertInvestigator(
        model=model,
        temperature=temperature,
        retrieval_k=retrieval_k,
        mitre_kb_path=mitre_kb_path,
    )
    return investigator.investigate_batch(alerts)