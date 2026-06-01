"""
RAGAS evaluation pipeline — measures retrieval quality, answer correctness,
and reachability accuracy of the FPM system against ground truth.

Run standalone: python -m evaluation.evaluate
"""
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def build_evaluation_dataset(
    openai_client,
    retriever,
    reachability_analyzer,
    ground_truth: list[dict],
) -> list[dict]:
    """
    Run the FPM pipeline on each ground-truth alert and collect results
    for RAGAS evaluation.
    """
    from fpm.agents.orchestrator import analyse_alert
    from fpm.retrieval.query_rewriter import rewrite_query
    from mock_server.alert_templates import TEMPLATES

    # Build a lookup from template_id to full alert template
    template_lookup = {t["template_id"]: t for t in TEMPLATES}

    dataset = []
    for gt in ground_truth:
        template_id = gt["template_id"]
        template = template_lookup.get(template_id)
        if not template:
            logger.warning("Template %s not found, skipping", template_id)
            continue

        # Build a mock alert dict
        alert = {
            "alert_id": f"eval-{template_id}",
            "attack_type": template["attack_type"],
            "target_endpoint": template["target_endpoint"],
            "http_method": template["http_method"],
            "severity": template["severity"],
            "traceable_reason": template["traceable_reason"],
            "payload_snippet": template["payload_snippet"],
            "source_ip": template["source_ip"],
            "http_request": template["http_request"],
            "http_response": template["http_response"],
        }

        # Get retrieval context
        rewritten_query = rewrite_query(alert, openai_client)
        retrieval_results = retriever.retrieve(rewritten_query, top_k=10)
        contexts = [r["text"][:500] for r in retrieval_results]

        # Get reachability analysis
        reachability_result = None
        if reachability_analyzer:
            try:
                reachability_result = reachability_analyzer.analyse_endpoint(
                    target_endpoint=template["target_endpoint"],
                    source_ip=template.get("source_ip"),
                )
            except Exception as e:
                logger.error("Reachability analysis failed for %s: %s", template_id, e)

        # Get verdict
        start_time = time.time()
        try:
            verdict = analyse_alert(
                alert, openai_client, retriever,
                reachability_analyzer=reachability_analyzer,
            )
        except Exception as e:
            logger.error("Failed to analyse %s: %s", template_id, e)
            verdict = {"verdict": "ERROR", "reasoning": str(e)}
        latency_ms = int((time.time() - start_time) * 1000)

        entry = {
            "question": f"Is alert {template_id} ({template['attack_type']} on {template['target_endpoint']}) a false positive?",
            "answer": verdict.get("reasoning", ""),
            "contexts": contexts,
            "ground_truth": gt["reasoning"],
            "template_id": template_id,
            "expected_verdict": gt["expected_verdict"],
            "actual_verdict": verdict.get("verdict", "UNKNOWN"),
            "confidence": verdict.get("confidence", 0.0),
            "controls_found": verdict.get("controls_found", []),
            "latency_ms": latency_ms,
            "tokens_used": verdict.get("tokens_used", 0),
        }

        # Add reachability data if available
        if reachability_result:
            entry["reachability"] = {
                "is_internet_reachable": reachability_result.is_internet_reachable,
                "risk_level": reachability_result.risk_level,
                "target_sg": reachability_result.target_sg,
                "waf_in_path": reachability_result.waf_in_path,
                "gateway_in_path": reachability_result.gateway_in_path,
                "paths": [
                    {
                        "layers_traversed": p.layers_traversed,
                        "layers_bypassed": p.layers_bypassed,
                    }
                    for p in reachability_result.paths
                ],
            }
        if gt.get("expected_reachability"):
            entry["expected_reachability"] = gt["expected_reachability"]

        dataset.append(entry)
        logger.info(
            "Evaluated %s: expected=%s, got=%s (conf=%.2f, %dms)",
            template_id, gt["expected_verdict"],
            verdict.get("verdict", "?"), verdict.get("confidence", 0),
            latency_ms,
        )

    return dataset


def compute_metrics(dataset: list[dict]) -> dict:
    """
    Compute evaluation metrics including verdict accuracy, retrieval quality,
    reachability accuracy, and RAGAS metrics.
    """
    metrics = {}

    # ── 1. Verdict Accuracy ──
    correct = sum(1 for d in dataset if d["expected_verdict"] == d["actual_verdict"])
    total = len(dataset)
    metrics["verdict_accuracy"] = correct / total if total > 0 else 0.0
    metrics["correct_verdicts"] = correct
    metrics["total_alerts"] = total

    # ── 2. Per-verdict-type breakdown ──
    fp_correct = sum(
        1 for d in dataset
        if d["expected_verdict"] == "FALSE_POSITIVE" and d["actual_verdict"] == "FALSE_POSITIVE"
    )
    fp_total = sum(1 for d in dataset if d["expected_verdict"] == "FALSE_POSITIVE")
    metrics["false_positive_accuracy"] = fp_correct / fp_total if fp_total > 0 else 0.0
    metrics["fp_correct"] = fp_correct
    metrics["fp_total"] = fp_total

    tp_correct = sum(
        1 for d in dataset
        if d["expected_verdict"] == "TRUE_POSITIVE" and d["actual_verdict"] == "TRUE_POSITIVE"
    )
    tp_total = sum(1 for d in dataset if d["expected_verdict"] == "TRUE_POSITIVE")
    metrics["true_positive_accuracy"] = tp_correct / tp_total if tp_total > 0 else 0.0
    metrics["tp_correct"] = tp_correct
    metrics["tp_total"] = tp_total

    # ── 3. TP Recall (most critical metric — missing a TP is catastrophic) ──
    predicted_tp = sum(1 for d in dataset if d["actual_verdict"] == "TRUE_POSITIVE")
    metrics["tp_recall"] = tp_correct / tp_total if tp_total > 0 else 0.0
    metrics["tp_precision"] = tp_correct / predicted_tp if predicted_tp > 0 else 0.0

    # ── 4. FP Precision (are FPs actually false positives?) ──
    predicted_fp = sum(1 for d in dataset if d["actual_verdict"] == "FALSE_POSITIVE")
    actual_fp_in_predicted = sum(
        1 for d in dataset
        if d["actual_verdict"] == "FALSE_POSITIVE" and d["expected_verdict"] == "FALSE_POSITIVE"
    )
    metrics["fp_precision"] = actual_fp_in_predicted / predicted_fp if predicted_fp > 0 else 0.0

    # ── 5. Confidence Metrics ──
    confidences = [d["confidence"] for d in dataset if d["confidence"] > 0]
    metrics["avg_confidence"] = sum(confidences) / len(confidences) if confidences else 0.0

    correct_confidences = [
        d["confidence"] for d in dataset
        if d["expected_verdict"] == d["actual_verdict"] and d["confidence"] > 0
    ]
    incorrect_confidences = [
        d["confidence"] for d in dataset
        if d["expected_verdict"] != d["actual_verdict"] and d["confidence"] > 0
    ]
    metrics["avg_confidence_correct"] = (
        sum(correct_confidences) / len(correct_confidences) if correct_confidences else 0.0
    )
    metrics["avg_confidence_incorrect"] = (
        sum(incorrect_confidences) / len(incorrect_confidences) if incorrect_confidences else 0.0
    )

    # ── 6. Latency Metrics ──
    latencies = [d.get("latency_ms", 0) for d in dataset if d.get("latency_ms", 0) > 0]
    metrics["avg_latency_ms"] = sum(latencies) / len(latencies) if latencies else 0
    metrics["max_latency_ms"] = max(latencies) if latencies else 0
    metrics["min_latency_ms"] = min(latencies) if latencies else 0

    # ── 7. Token Usage ──
    tokens = [d.get("tokens_used", 0) for d in dataset if d.get("tokens_used", 0) > 0]
    metrics["avg_tokens_per_alert"] = sum(tokens) / len(tokens) if tokens else 0
    metrics["total_tokens"] = sum(tokens)

    # ── 8. Context Recall (retrieval quality) ──
    from evaluation.ground_truth import GROUND_TRUTH
    gt_lookup = {g["template_id"]: g for g in GROUND_TRUTH}

    context_hits = 0
    context_total = 0
    for d in dataset:
        gt = gt_lookup.get(d["template_id"], {})
        expected_controls = gt.get("expected_controls", [])
        for ctrl in expected_controls:
            context_total += 1
            if any(ctrl.lower() in ctx.lower() for ctx in d["contexts"]):
                context_hits += 1

    metrics["context_recall"] = context_hits / context_total if context_total > 0 else 0.0

    # ── 9. Reachability Metrics ──
    metrics["reachability"] = _compute_reachability_metrics(dataset)

    # ── 10. RAGAS Metrics (if available) ──
    metrics["ragas"] = _compute_ragas_metrics(dataset)

    return metrics


def _compute_reachability_metrics(dataset: list[dict]) -> dict:
    """Compute reachability-specific metrics."""
    reachability_metrics = {}

    entries_with_reachability = [
        d for d in dataset
        if d.get("reachability") and d.get("expected_reachability")
    ]

    if not entries_with_reachability:
        return {"note": "No reachability data available"}

    total = len(entries_with_reachability)

    # Internet reachability accuracy
    reach_correct = sum(
        1 for d in entries_with_reachability
        if d["reachability"]["is_internet_reachable"] == d["expected_reachability"]["internet_reachable"]
    )
    reachability_metrics["internet_reachability_accuracy"] = reach_correct / total
    reachability_metrics["internet_reachability_correct"] = reach_correct
    reachability_metrics["internet_reachability_total"] = total

    # Risk level accuracy
    risk_correct = sum(
        1 for d in entries_with_reachability
        if d["reachability"]["risk_level"] == d["expected_reachability"]["risk_level"]
    )
    reachability_metrics["risk_level_accuracy"] = risk_correct / total
    reachability_metrics["risk_level_correct"] = risk_correct

    # Bypass detection — check if expected bypassed layers were detected
    bypass_entries = [
        d for d in entries_with_reachability
        if d["expected_reachability"].get("expected_bypassed")
    ]
    if bypass_entries:
        bypass_correct = 0
        for d in bypass_entries:
            expected_bypassed = set(d["expected_reachability"]["expected_bypassed"])
            actual_bypassed = set()
            for path in d["reachability"].get("paths", []):
                actual_bypassed.update(path.get("layers_bypassed", []))
            if expected_bypassed.issubset(actual_bypassed):
                bypass_correct += 1
        reachability_metrics["bypass_detection_rate"] = bypass_correct / len(bypass_entries)
        reachability_metrics["bypass_detection_correct"] = bypass_correct
        reachability_metrics["bypass_detection_total"] = len(bypass_entries)
    else:
        reachability_metrics["bypass_detection_rate"] = 1.0  # No bypasses expected, none to detect
        reachability_metrics["bypass_detection_correct"] = 0
        reachability_metrics["bypass_detection_total"] = 0

    # Path completeness — check if expected layers appear in traversed path
    path_correct = 0
    for d in entries_with_reachability:
        expected_path = set(d["expected_reachability"].get("expected_path_contains", []))
        actual_path = set()
        for path in d["reachability"].get("paths", []):
            actual_path.update(path.get("layers_traversed", []))
        if expected_path.issubset(actual_path):
            path_correct += 1
    reachability_metrics["path_completeness"] = path_correct / total
    reachability_metrics["path_completeness_correct"] = path_correct

    # Critical bypass detection (specifically for TP #38)
    critical_entries = [
        d for d in entries_with_reachability
        if d["expected_reachability"].get("risk_level") == "CRITICAL"
    ]
    if critical_entries:
        critical_detected = sum(
            1 for d in critical_entries
            if d["reachability"]["risk_level"] == "CRITICAL"
        )
        reachability_metrics["critical_bypass_detection"] = critical_detected / len(critical_entries)
    else:
        reachability_metrics["critical_bypass_detection"] = 1.0

    return reachability_metrics


def _compute_ragas_metrics(dataset: list[dict]) -> dict:
    """Try to compute RAGAS metrics if the library is available."""
    try:
        from ragas import evaluate as ragas_evaluate
        from ragas.metrics import faithfulness, answer_relevancy, context_recall, context_precision
        from datasets import Dataset

        ragas_data = {
            "question": [d["question"] for d in dataset],
            "answer": [d["answer"] for d in dataset],
            "contexts": [d["contexts"] for d in dataset],
            "ground_truth": [d["ground_truth"] for d in dataset],
        }

        ragas_dataset = Dataset.from_dict(ragas_data)
        ragas_result = ragas_evaluate(
            ragas_dataset,
            metrics=[faithfulness, answer_relevancy, context_recall, context_precision],
        )
        result = {k: float(v) for k, v in ragas_result.items() if isinstance(v, (int, float))}
        logger.info("RAGAS metrics computed successfully")
        return result
    except ImportError:
        logger.warning("RAGAS not available; skipping RAGAS-specific metrics")
        return {"note": "RAGAS library not installed or incompatible"}
    except Exception as e:
        logger.error("RAGAS evaluation failed: %s", e)
        return {"error": str(e)}


def print_report(metrics: dict, dataset: list[dict]) -> None:
    """Print a formatted evaluation report."""
    print("\n" + "=" * 74)
    print("FPM EVALUATION REPORT")
    print("=" * 74)

    # Verdict Accuracy
    print(f"\n{'Verdict Accuracy:':<30} {metrics['verdict_accuracy']:.1%} ({metrics['correct_verdicts']}/{metrics['total_alerts']})")
    print(f"{'False Positive Accuracy:':<30} {metrics['false_positive_accuracy']:.1%} ({metrics['fp_correct']}/{metrics['fp_total']})")
    print(f"{'True Positive Accuracy:':<30} {metrics['true_positive_accuracy']:.1%} ({metrics['tp_correct']}/{metrics['tp_total']})")
    print(f"{'TP Recall (CRITICAL):':<30} {metrics['tp_recall']:.1%}")
    print(f"{'TP Precision:':<30} {metrics['tp_precision']:.1%}")
    print(f"{'FP Precision:':<30} {metrics['fp_precision']:.1%}")

    # Confidence
    print(f"\n{'Avg Confidence:':<30} {metrics['avg_confidence']:.2f}")
    print(f"{'Avg Confidence (correct):':<30} {metrics['avg_confidence_correct']:.2f}")
    if metrics['avg_confidence_incorrect'] > 0:
        print(f"{'Avg Confidence (incorrect):':<30} {metrics['avg_confidence_incorrect']:.2f}")

    # Context Recall
    print(f"\n{'Context Recall:':<30} {metrics['context_recall']:.1%}")

    # Latency
    print(f"\n{'Avg Latency:':<30} {metrics['avg_latency_ms']:,.0f} ms")
    print(f"{'Min Latency:':<30} {metrics['min_latency_ms']:,.0f} ms")
    print(f"{'Max Latency:':<30} {metrics['max_latency_ms']:,.0f} ms")

    # Token Usage
    print(f"\n{'Avg Tokens/Alert:':<30} {metrics['avg_tokens_per_alert']:,.0f}")
    print(f"{'Total Tokens:':<30} {metrics['total_tokens']:,.0f}")

    # Reachability Metrics
    reach = metrics.get("reachability", {})
    if "note" not in reach:
        print("\n" + "-" * 74)
        print("REACHABILITY METRICS")
        print("-" * 74)
        print(f"{'Reachability Accuracy:':<30} {reach.get('internet_reachability_accuracy', 0):.1%} ({reach.get('internet_reachability_correct', 0)}/{reach.get('internet_reachability_total', 0)})")
        print(f"{'Risk Level Accuracy:':<30} {reach.get('risk_level_accuracy', 0):.1%} ({reach.get('risk_level_correct', 0)}/{reach.get('internet_reachability_total', 0)})")
        print(f"{'Bypass Detection Rate:':<30} {reach.get('bypass_detection_rate', 0):.1%} ({reach.get('bypass_detection_correct', 0)}/{reach.get('bypass_detection_total', 0)})")
        print(f"{'Path Completeness:':<30} {reach.get('path_completeness', 0):.1%} ({reach.get('path_completeness_correct', 0)}/{reach.get('internet_reachability_total', 0)})")
        print(f"{'Critical Bypass Detection:':<30} {reach.get('critical_bypass_detection', 0):.1%}")

    # RAGAS
    ragas = metrics.get("ragas", {})
    if isinstance(ragas, dict) and "note" not in ragas and "error" not in ragas:
        print("\n" + "-" * 74)
        print("RAGAS METRICS")
        print("-" * 74)
        for k, v in ragas.items():
            print(f"  {k:<28} {v:.3f}")
    elif isinstance(ragas, dict) and "note" in ragas:
        print(f"\nRAGAS: {ragas['note']}")

    # Per-Alert Results
    print("\n" + "-" * 74)
    print("PER-ALERT RESULTS")
    print("-" * 74)

    for d in dataset:
        match = "PASS" if d["expected_verdict"] == d["actual_verdict"] else "FAIL"
        marker = " " if match == "PASS" else "!"
        reach_info = ""
        if d.get("reachability"):
            r = d["reachability"]
            risk = r.get("risk_level", "?")
            reach_info = f" [risk={risk}]"
        print(f"  [{match}]{marker} {d['template_id']}: "
              f"expected={d['expected_verdict']}, got={d['actual_verdict']} "
              f"(conf={d['confidence']:.2f}, {d.get('latency_ms', 0)}ms){reach_info}")

    # Pass/Fail Summary
    print("\n" + "=" * 74)
    print("PASS/FAIL CRITERIA")
    print("=" * 74)

    checks = [
        ("All FP → FALSE_POSITIVE", metrics["fp_correct"] == metrics["fp_total"]),
        ("All TP → TRUE_POSITIVE (TP Recall=100%)", metrics["tp_recall"] == 1.0),
        ("Verdict accuracy >= 95%", metrics["verdict_accuracy"] >= 0.95),
        ("Avg confidence >= 0.75", metrics["avg_confidence"] >= 0.75),
    ]
    if "note" not in reach:
        checks.extend([
            ("Reachability accuracy = 100%", reach.get("internet_reachability_accuracy", 0) == 1.0),
            ("Critical bypass detected", reach.get("critical_bypass_detection", 0) == 1.0),
        ])

    all_pass = True
    for label, passed in checks:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  [{status}] {label}")

    print(f"\nOverall: {'ALL CHECKS PASSED' if all_pass else 'SOME CHECKS FAILED'}")


def main() -> None:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("OPENAI_API_KEY not set")
        sys.exit(1)

    from openai import OpenAI

    openai_client = OpenAI(api_key=api_key)

    # Build knowledge base
    logger.info("Building knowledge base for evaluation...")
    from fpm.knowledge.builder import build_knowledge_base

    store = build_knowledge_base(openai_client)

    # Build retriever
    from fpm.retrieval.hybrid_search import HybridRetriever

    retriever = HybridRetriever(store)

    # Build reachability analyzer
    logger.info("Building reachability analyzer...")
    from fpm.parsers.terraform_parser import parse_terraform
    from fpm.analysis.reachability import ReachabilityAnalyzer

    infra_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "infrastructure")
    tf_dir = os.path.join(infra_dir, "terraform")
    tf_controls = []
    if os.path.isdir(tf_dir):
        for fname in sorted(os.listdir(tf_dir)):
            if fname.endswith(".tf"):
                tf_controls.extend(parse_terraform(os.path.join(tf_dir, fname)))
    reachability_analyzer = ReachabilityAnalyzer(tf_controls)
    logger.info("Reachability analyzer built with %d Terraform controls", len(tf_controls))

    # Load ground truth
    from evaluation.ground_truth import GROUND_TRUTH

    logger.info("Running evaluation on %d ground-truth alerts...", len(GROUND_TRUTH))
    dataset = build_evaluation_dataset(
        openai_client, retriever, reachability_analyzer, GROUND_TRUTH,
    )

    # Compute metrics
    metrics = compute_metrics(dataset)

    # Print report
    print_report(metrics, dataset)

    # Save full report to file
    report_path = os.path.join(os.path.dirname(__file__), "report.json")
    with open(report_path, "w") as f:
        json.dump({"metrics": metrics, "results": dataset}, f, indent=2, default=str)
    print(f"\nFull report saved to: {report_path}")


if __name__ == "__main__":
    main()
