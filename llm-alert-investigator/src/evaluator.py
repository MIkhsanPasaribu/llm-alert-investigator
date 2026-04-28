"""Evaluation metrics for LLM alert investigator."""

import json
from typing import Any

import numpy as np
from langchain_openai import ChatOpenAI
from sklearn.metrics import precision_score, recall_score, f1_score


class AlertInvestigatorEvaluator:
    """Evaluates the performance of the alert investigator."""

    def __init__(self, judge_llm: ChatOpenAI | None = None):
        self.judge_llm = judge_llm or ChatOpenAI(model="gpt-4o", temperature=0.0)

    def evaluate_mitre_mapping(
        self, predictions: list[dict[str, Any]], ground_truth: list[str]
    ) -> dict[str, float]:
        """Evaluate MITRE ATT&CK mapping accuracy.

        Args:
            predictions: List of investigation results with mitre_mapping
            ground_truth: List of correct technique IDs

        Returns:
            Dictionary with accuracy metrics
        """
        if len(predictions) != len(ground_truth):
            raise ValueError("Predictions and ground truth must have same length")

        correct = 0
        top1_correct = 0
        top3_correct = 0
        confidences = []

        for pred, gt in zip(predictions, ground_truth):
            mitre_mapping = pred.get("mitre_mapping", [])

            if not mitre_mapping:
                continue

            predicted_ids = [m["technique_id"] for m in mitre_mapping]

            if gt in predicted_ids:
                correct += 1

            if predicted_ids[0] == gt:
                top1_correct += 1

            if gt in predicted_ids[:3]:
                top3_correct += 1

            confidences.append(mitre_mapping[0].get("confidence", 0.0))

        total = len(ground_truth)

        return {
            "technique_accuracy": correct / total if total > 0 else 0.0,
            "top1_accuracy": top1_correct / total if total > 0 else 0.0,
            "top3_accuracy": top3_correct / total if total > 0 else 0.0,
            "avg_confidence": np.mean(confidences) if confidences else 0.0,
            "std_confidence": np.std(confidences) if confidences else 0.0,
        }

    def evaluate_narrative_quality(
        self, narratives: list[str], ground_truth_labels: list[dict[str, Any]]
    ) -> dict[str, float]:
        """Evaluate narrative quality using LLM-as-judge.

        Args:
            narratives: List of generated narratives
            ground_truth_labels: List of ground truth labels with technique info

        Returns:
            Dictionary with quality metrics
        """
        if len(narratives) != len(ground_truth_labels):
            raise ValueError("Narratives and ground truth must have same length")

        scores = []
        accuracy_scores = []
        completeness_scores = []
        actionability_scores = []

        for narrative, gt in zip(narratives, ground_truth_labels):
            score = self._judge_narrative(narrative, gt)
            scores.append(score["overall"])
            accuracy_scores.append(score["accuracy"])
            completeness_scores.append(score["completeness"])
            actionability_scores.append(score["actionability"])

        return {
            "avg_quality": np.mean(scores) if scores else 0.0,
            "avg_accuracy": np.mean(accuracy_scores) if accuracy_scores else 0.0,
            "avg_completeness": np.mean(completeness_scores) if completeness_scores else 0.0,
            "avg_actionability": np.mean(actionability_scores) if actionability_scores else 0.0,
            "std_quality": np.std(scores) if scores else 0.0,
        }

    def _judge_narrative(
        self, narrative: str, ground_truth: dict[str, Any]
    ) -> dict[str, float]:
        """Use LLM to judge narrative quality."""
        technique_id = ground_truth.get("technique_id", "Unknown")
        technique_name = ground_truth.get("technique_name", "Unknown")
        expected_content = ground_truth.get("expected_content", "")

        prompt = f"""You are an expert security analyst evaluating the quality of an investigation narrative.

Ground Truth:
- Technique ID: {technique_id}
- Technique Name: {technique_name}
- Expected Content: {expected_content}

Generated Narrative:
{narrative}

Evaluate the narrative on a scale of 1-5 for each dimension:
1. Accuracy: How accurately does the narrative describe the attack?
2. Completeness: Does it cover all important aspects of the attack?
3. Actionability: Are the next steps specific and actionable?

Respond in JSON format:
{{
  "accuracy": 1-5,
  "completeness": 1-5,
  "actionability": 1-5,
  "overall": 1-5,
  "feedback": "Brief explanation of your evaluation"
}}"""

        try:
            response = self.judge_llm.invoke(prompt)
            result = json.loads(response.content)
            return {
                "accuracy": result.get("accuracy", 3.0),
                "completeness": result.get("completeness", 3.0),
                "actionability": result.get("actionability", 3.0),
                "overall": result.get("overall", 3.0),
                "feedback": result.get("feedback", ""),
            }
        except (json.JSONDecodeError, Exception):
            return {
                "accuracy": 3.0,
                "completeness": 3.0,
                "actionability": 3.0,
                "overall": 3.0,
                "feedback": "Failed to evaluate",
            }

    def evaluate_severity_classification(
        self, predictions: list[dict[str, Any]], ground_truth: list[str]
    ) -> dict[str, float]:
        """Evaluate severity classification accuracy.

        Args:
            predictions: List of investigation results
            ground_truth: List of correct severity levels

        Returns:
            Dictionary with classification metrics
        """
        if len(predictions) != len(ground_truth):
            raise ValueError("Predictions and ground truth must have same length")

        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        y_true = [severity_order.get(gt, 1) for gt in ground_truth]
        y_pred = [severity_order.get(p.get("severity", "medium"), 1) for p in predictions]

        return {
            "accuracy": sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true),
            "precision": precision_score(y_true, y_pred, average="weighted", zero_division=0),
            "recall": recall_score(y_true, y_pred, average="weighted", zero_division=0),
            "f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        }

    def generate_evaluation_report(
        self,
        predictions: list[dict[str, Any]],
        ground_truth: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate comprehensive evaluation report.

        Args:
            predictions: List of investigation results
            ground_truth: List of ground truth labels

        Returns:
            Comprehensive evaluation report
        """
        gt_techniques = [gt.get("technique_id", "") for gt in ground_truth]
        gt_severity = [gt.get("severity", "medium") for gt in ground_truth]
        narratives = [p.get("narrative", "") for p in predictions]

        mitre_metrics = self.evaluate_mitre_mapping(predictions, gt_techniques)
        narrative_metrics = self.evaluate_narrative_quality(narratives, ground_truth)
        severity_metrics = self.evaluate_severity_classification(predictions, gt_severity)

        return {
            "mitre_mapping": mitre_metrics,
            "narrative_quality": narrative_metrics,
            "severity_classification": severity_metrics,
            "total_alerts": len(predictions),
            "successful_investigations": sum(
                1 for p in predictions if "error" not in p and p.get("mitre_mapping")
            ),
        }

    def analyze_error_cases(
        self, predictions: list[dict[str, Any]], ground_truth: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Analyze cases where predictions were incorrect.

        Args:
            predictions: List of investigation results
            ground_truth: List of ground truth labels

        Returns:
            List of error cases with analysis
        """
        error_cases = []

        for pred, gt in zip(predictions, ground_truth):
            gt_technique = gt.get("technique_id", "")
            predicted_techniques = [m["technique_id"] for m in pred.get("mitre_mapping", [])]

            if gt_technique not in predicted_techniques:
                error_cases.append(
                    {
                        "ground_truth": gt,
                        "prediction": pred,
                        "ground_truth_technique": gt_technique,
                        "predicted_techniques": predicted_techniques,
                        "error_type": "incorrect_technique",
                    }
                )

        return error_cases

    def compare_baselines(
        self,
        predictions_rag: list[dict[str, Any]],
        predictions_no_rag: list[dict[str, Any]],
        ground_truth: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Compare RAG vs No-RAG baseline performance.

        Args:
            predictions_rag: Predictions with RAG
            predictions_no_rag: Predictions without RAG
            ground_truth: Ground truth labels

        Returns:
            Comparison metrics
        """
        gt_techniques = [gt.get("technique_id", "") for gt in ground_truth]

        metrics_rag = self.evaluate_mitre_mapping(predictions_rag, gt_techniques)
        metrics_no_rag = self.evaluate_mitre_mapping(predictions_no_rag, gt_techniques)

        return {
            "with_rag": metrics_rag,
            "without_rag": metrics_no_rag,
            "improvement": {
                "technique_accuracy": metrics_rag["technique_accuracy"]
                - metrics_no_rag["technique_accuracy"],
                "top1_accuracy": metrics_rag["top1_accuracy"] - metrics_no_rag["top1_accuracy"],
                "top3_accuracy": metrics_rag["top3_accuracy"] - metrics_no_rag["top3_accuracy"],
            },
        }


def evaluate_mitre_mapping(
    predictions: list[dict[str, Any]], ground_truth: list[str]
) -> dict[str, float]:
    """Convenience function to evaluate MITRE mapping."""
    evaluator = AlertInvestigatorEvaluator()
    return evaluator.evaluate_mitre_mapping(predictions, ground_truth)


def evaluate_narrative_quality(
    narratives: list[str], ground_truth_labels: list[dict[str, Any]]
) -> dict[str, float]:
    """Convenience function to evaluate narrative quality."""
    evaluator = AlertInvestigatorEvaluator()
    return evaluator.evaluate_narrative_quality(narratives, ground_truth_labels)


def generate_evaluation_report(
    predictions: list[dict[str, Any]], ground_truth: list[dict[str, Any]]
) -> dict[str, Any]:
    """Convenience function to generate evaluation report."""
    evaluator = AlertInvestigatorEvaluator()
    return evaluator.generate_evaluation_report(predictions, ground_truth)