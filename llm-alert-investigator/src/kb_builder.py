"""MITRE ATT&CK knowledge base builder for vector store."""

import json
from pathlib import Path
from typing import Any

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings


class MITREKnowledgeBaseBuilder:
    """Builds and manages MITRE ATT&CK vector store for RAG."""

    def __init__(self, embedding_model: str = "text-embedding-3-small"):
        self.embedding_model = embedding_model
        self.embeddings = OpenAIEmbeddings(model=embedding_model)
        self.vector_store = None

    def build_from_mitre(self, mitre_data_path: str | None = None) -> FAISS:
        """Build vector store from MITRE ATT&CK data.

        Args:
            mitre_data_path: Path to MITRE ATT&CK JSON data. If None, uses mitreattack-python.

        Returns:
            FAISS vector store
        """
        documents = []

        if mitre_data_path and Path(mitre_data_path).exists():
            documents = self._load_from_file(mitre_data_path)
        else:
            documents = self._load_from_mitre_library()

        if not documents:
            raise ValueError("No MITRE ATT&CK documents loaded")

        self.vector_store = FAISS.from_documents(documents, self.embeddings)
        return self.vector_store

    def _load_from_file(self, filepath: str) -> list[Document]:
        """Load MITRE data from local JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        documents = []
        if isinstance(data, list):
            for item in data:
                doc = self._create_document(item)
                if doc:
                    documents.append(doc)
        elif isinstance(data, dict):
            if "techniques" in data:
                for item in data["techniques"]:
                    doc = self._create_document(item)
                    if doc:
                        documents.append(doc)
            else:
                doc = self._create_document(data)
                if doc:
                    documents.append(doc)

        return documents

    def _load_from_mitre_library(self) -> list[Document]:
        """Load MITRE ATT&CK data using mitreattack-python library."""
        try:
            from mitreattack import attackToExcel
            from mitreattack.attackToExcel import attackToExcel
            from mitreattack.navlayers import LayerGenerator
            from mitreattack.stix20 import MitreAttack

            attack = MitreAttack()
            techniques = attack.get_techniques()

            documents = []
            for technique in techniques:
                doc = self._create_document_from_stix(technique)
                if doc:
                    documents.append(doc)

            return documents
        except ImportError:
            return self._create_synthetic_mitre_data()

    def _create_document_from_stix(self, stix_obj: dict[str, Any]) -> Document | None:
        """Create Document from STIX MITRE ATT&CK object."""
        if stix_obj.get("type") != "attack-pattern":
            return None

        technique_id = stix_obj.get("external_references", [{}])[0].get("external_id", "")
        technique_name = stix_obj.get("name", "")
        description = stix_obj.get("description", "")

        tactics = []
        for kill_chain in stix_obj.get("kill_chain_phases", []):
            if kill_chain.get("kill_chain_name") == "mitre-attack":
                tactics.append(kill_chain.get("phase_name", ""))

        if not technique_id or not technique_name:
            return None

        content = self._format_technique_content(
            technique_id=technique_id,
            technique_name=technique_name,
            tactics=tactics,
            description=description,
            detection=stix_obj.get("x_mitre_detection", ""),
            data_sources=stix_obj.get("x_mitre_data_sources", []),
        )

        metadata = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactics": ", ".join(tactics),
            "description": description[:200],
        }

        return Document(page_content=content, metadata=metadata)

    def _create_document(self, item: dict[str, Any]) -> Document | None:
        """Create Document from MITRE technique dictionary."""
        technique_id = item.get("technique_id") or item.get("id", "")
        technique_name = item.get("technique_name") or item.get("name", "")
        tactic = item.get("tactic") or item.get("tactics", "")
        description = item.get("description", "")
        detection = item.get("detection", "")
        data_sources = item.get("data_sources", [])

        if not technique_id or not technique_name:
            return None

        content = self._format_technique_content(
            technique_id=technique_id,
            technique_name=technique_name,
            tactics=tactic if isinstance(tactic, str) else ", ".join(tactic),
            description=description,
            detection=detection,
            data_sources=data_sources,
        )

        metadata = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactics": tactic if isinstance(tactic, str) else ", ".join(tactic),
            "description": description[:200],
        }

        return Document(page_content=content, metadata=metadata)

    def _format_technique_content(
        self,
        technique_id: str,
        technique_name: str,
        tactics: str,
        description: str,
        detection: str,
        data_sources: list[str] | str,
    ) -> str:
        """Format technique information for embedding."""
        parts = [
            f"Technique ID: {technique_id}",
            f"Technique Name: {technique_name}",
            f"Tactics: {tactics}",
        ]

        if description:
            parts.append(f"Description: {description}")

        if detection:
            parts.append(f"Detection: {detection}")

        if data_sources:
            if isinstance(data_sources, str):
                parts.append(f"Data Sources: {data_sources}")
            else:
                parts.append(f"Data Sources: {', '.join(data_sources)}")

        return " | ".join(parts)

    def _create_synthetic_mitre_data(self) -> list[Document]:
        """Create synthetic MITRE ATT&CK data for testing."""
        synthetic_techniques = [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "Execution",
                "description": "PowerShell is a powerful command-line shell and scripting language. Adversaries may abuse PowerShell to execute commands, perform reconnaissance, and move laterally.",
                "detection": "Monitor for PowerShell execution, especially with encoded commands or suspicious parameters.",
                "data_sources": ["Process monitoring", "Command-line logging"],
            },
            {
                "technique_id": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "tactic": "Initial Access",
                "description": "Adversaries may send spearphishing emails with malicious attachments to gain initial access to victim systems.",
                "detection": "Monitor for suspicious email attachments, especially from unknown senders.",
                "data_sources": ["Email gateway", "File monitoring"],
            },
            {
                "technique_id": "T1078.002",
                "technique_name": "Domain Account",
                "tactic": "Defense Evasion",
                "description": "Adversaries may create domain accounts to maintain access to victim systems.",
                "detection": "Monitor for creation of new domain accounts, especially with privileged rights.",
                "data_sources": ["Active Directory", "Windows event logs"],
            },
            {
                "technique_id": "T1021.001",
                "technique_name": "Remote Desktop Protocol",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use RDP for lateral movement between systems within a network.",
                "detection": "Monitor for RDP connections, especially from unusual source IPs or at unusual times.",
                "data_sources": ["Network traffic", "Windows event logs"],
            },
            {
                "technique_id": "T1047",
                "technique_name": "Windows Management Instrumentation",
                "tactic": "Execution",
                "description": "Adversaries may abuse WMI to execute commands, perform reconnaissance, and move laterally.",
                "detection": "Monitor for WMI execution, especially with suspicious parameters or from unusual processes.",
                "data_sources": ["Process monitoring", "WMI repository"],
            },
            {
                "technique_id": "T1055.001",
                "technique_name": "Dynamic-link Library Injection",
                "tactic": "Defense Evasion",
                "description": "Adversaries may inject malicious code into processes via DLL injection to evade detection.",
                "detection": "Monitor for suspicious process injection, especially from unusual parent processes.",
                "data_sources": ["Process monitoring", "API monitoring"],
            },
            {
                "technique_id": "T1567.002",
                "technique_name": "Exfiltration Over Web Service",
                "tactic": "Exfiltration",
                "description": "Adversaries may exfiltrate data over web services to avoid detection.",
                "detection": "Monitor for large data transfers to external web services, especially to unknown domains.",
                "data_sources": ["Network traffic", "Proxy logs"],
            },
            {
                "technique_id": "T1070.004",
                "technique_name": "File Deletion",
                "tactic": "Defense Evasion",
                "description": "Adversaries may delete files to hide evidence of their activity.",
                "detection": "Monitor for file deletion, especially of security-related files or logs.",
                "data_sources": ["File system", "Windows event logs"],
            },
            {
                "technique_id": "T1543.003",
                "technique_name": "Windows Service",
                "tactic": "Persistence",
                "description": "Adversaries may create or modify Windows services to maintain persistence.",
                "detection": "Monitor for creation or modification of Windows services, especially with suspicious commands.",
                "data_sources": ["Service configuration", "Process monitoring"],
            },
            {
                "technique_id": "T1136.002",
                "technique_name": "Domain Account",
                "tactic": "Persistence",
                "description": "Adversaries may create domain accounts to maintain access to victim systems.",
                "detection": "Monitor for creation of new domain accounts, especially with privileged rights.",
                "data_sources": ["Active Directory", "Windows event logs"],
            },
        ]

        documents = []
        for technique in synthetic_techniques:
            doc = self._create_document(technique)
            if doc:
                documents.append(doc)

        return documents

    def save(self, path: str) -> None:
        """Save vector store to disk."""
        if self.vector_store is None:
            raise ValueError("No vector store to save. Build one first.")

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.vector_store.save_local(path)

    def load(self, path: str) -> FAISS:
        """Load vector store from disk."""
        self.vector_store = FAISS.load_local(path, self.embeddings, allow_dangerous_deserialization=True)
        return self.vector_store

    def search(self, query: str, k: int = 5) -> list[Document]:
        """Search vector store for relevant documents."""
        if self.vector_store is None:
            raise ValueError("No vector store loaded. Build or load one first.")

        return self.vector_store.similarity_search(query, k=k)

    def search_with_scores(self, query: str, k: int = 5) -> list[tuple[Document, float]]:
        """Search vector store with relevance scores."""
        if self.vector_store is None:
            raise ValueError("No vector store loaded. Build or load one first.")

        return self.vector_store.similarity_search_with_score(query, k=k)


def build_mitre_kb(output_path: str = "data/mitre_attack_kb", mitre_data_path: str | None = None) -> FAISS:
    """Convenience function to build and save MITRE knowledge base."""
    builder = MITREKnowledgeBaseBuilder()
    kb = builder.build_from_mitre(mitre_data_path)
    builder.save(output_path)
    return kb


def load_mitre_kb(path: str = "data/mitre_attack_kb") -> FAISS:
    """Convenience function to load MITRE knowledge base."""
    builder = MITREKnowledgeBaseBuilder()
    return builder.load(path)