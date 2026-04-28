# LLM Alert Investigator

AI-powered SOC alert investigation tool that uses RAG-augmented LLM to automatically map security alerts to MITRE ATT&CK framework, generate investigation narratives, and recommend next steps for SOC analysts.

## Features

- **MITRE ATT&CK Mapping**: Automatically maps alerts to MITRE techniques with confidence scores
- **Investigation Narratives**: Generates comprehensive narratives explaining what likely happened
- **Next Steps Recommendations**: Provides actionable next steps for SOC analysts
- **RAG-Powered**: Uses retrieval-augmented generation with MITRE ATT&CK knowledge base
- **Batch Processing**: Process multiple alerts efficiently
- **Evaluation Metrics**: Built-in evaluation framework for measuring performance
- **Streamlit UI**: User-friendly web interface for investigation and evaluation

## Architecture

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

## Tech Stack

- **Language**: Python 3.11
- **LLM Framework**: LangChain >= 0.2
- **Vector Store**: FAISS (CPU)
- **LLM Provider**: OpenAI GPT-4o
- **Embeddings**: OpenAI text-embedding-3-small
- **MITRE Data**: mitreattack-python
- **UI**: Streamlit
- **Evaluation**: scikit-learn, pandas, matplotlib

## Installation

### Prerequisites

- Python 3.11 or higher
- OpenAI API key

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd llm-alert-investigator
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

5. Build the MITRE knowledge base:
```bash
python -c "from src.kb_builder import build_mitre_kb; build_mitre_kb()"
```

## Usage

### Streamlit UI

Launch the web interface:

```bash
streamlit run src/app.py
```

The UI provides three modes:
- **Single Alert**: Investigate individual alerts
- **Batch Processing**: Process multiple alerts from JSON file
- **Evaluation**: Evaluate predictions against ground truth

### Python API

#### Investigate a Single Alert

```python
from src.investigator import investigate_alert

alert = {
    "timestamp": "2024-01-15T10:30:00Z",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.50",
    "event_type": "network_connection",
    "process": "powershell.exe",
    "command_line": "powershell.exe -EncodedCommand ...",
    "severity": "high"
}

result = investigate_alert(alert)

print(f"MITRE Mapping: {result['mitre_mapping']}")
print(f"Narrative: {result['narrative']}")
print(f"Next Steps: {result['next_steps']}")
print(f"Severity: {result['severity']}")
```

#### Batch Processing

```python
from src.investigator import investigate_alerts
from src.preprocessor import load_alerts_from_file

alerts = load_alerts_from_file("data/sample_alerts/attack_samples.json")
results = investigate_alerts(alerts)

for result in results:
    print(f"Alert: {result['normalized_alert']['event_type']}")
    print(f"Technique: {result['mitre_mapping'][0]['technique_id']}")
    print()
```

#### Evaluation

```python
from src.evaluator import generate_evaluation_report
from src.preprocessor import load_alerts_from_file

predictions = load_alerts_from_file("investigation_results.json")
ground_truth = load_alerts_from_file("ground_truth_labels.json")

report = generate_evaluation_report(predictions, ground_truth)

print(f"Top-1 Accuracy: {report['mitre_mapping']['top1_accuracy']:.2%}")
print(f"Top-3 Accuracy: {report['mitre_mapping']['top3_accuracy']:.2%}")
print(f"Avg Quality: {report['narrative_quality']['avg_quality']:.2f}/5")
```

## Project Structure

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
├── SPEC.md
└── README.md
```

## Design Decisions

### Temperature=0
Ensures deterministic, reproducible results for paper evaluation and consistent behavior across multiple runs.

### Retrieval K=5
Balances context window usage with relevance. This parameter can be adjusted for ablation studies.

### RAG vs No-RAG
The system supports both RAG-augmented and LLM-only modes for comparative evaluation.

### LLM-as-Judge
Uses GPT-4 to evaluate narrative quality based on accuracy, completeness, and actionability dimensions.

## Evaluation Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Top-1 Accuracy | Correct technique as top prediction | > 80% |
| Top-3 Accuracy | Correct technique in top 3 predictions | > 95% |
| Avg Confidence | Mean confidence of correct predictions | > 0.75 |
| Narrative Quality | LLM-as-judge score (1-5) | > 4.0 |

## Dataset Options

### Primary: Synthetic Alerts
Generated using GPT-4o with controlled MITRE technique coverage. See `data/sample_alerts/` for examples.

### Secondary: CICIDS2017/2018
Network intrusion dataset requiring feature-to-alert conversion.

### Ground Truth
Minimum 100-200 manually labeled alerts for meaningful metrics. See `data/ground_truth_labels.csv` for format.

## Limitations

- **Hallucination Risk**: LLM may generate incorrect narratives
- **Latency**: Dependent on LLM API response time
- **Cost**: Per-alert cost based on token usage
- **MITRE KB Coverage**: Limited to techniques in knowledge base

## Future Work

- Multi-level SOC escalation (L1 → L2 → L3)
- Integration with real SIEM platforms (Splunk, Elastic)
- Custom fine-tuned model for security domain
- Feedback loop for continuous improvement
- Support for additional MITRE matrices (ICS, Mobile)

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Citation

If you use this tool in your research, please cite:

```bibtex
@software{llm_alert_investigator,
  title = {LLM Alert Investigator: AI-Powered SOC Alert Investigation},
  author = {Your Name},
  year = {2024},
  url = {https://github.com/yourusername/llm-alert-investigator}
}
```

## Acknowledgments

- MITRE ATT&CK framework
- LangChain community
- OpenAI for GPT-4o
- Streamlit team

## Contact

For questions or support, please open an issue on GitHub or contact [your-email@example.com].

---

**Built with**: LangChain, OpenAI GPT-4o, FAISS, MITRE ATT&CK