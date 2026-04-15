"""
RAGAS evaluation pipeline — measures retrieval quality and answer correctness
of the FPM system against ground truth.

Run standalone: python -m evaluation.evaluate
"""
import json
import logging
import os
import sys

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

        # Get verdict
        try:
            verdict = analyse_alert(alert, openai_client, retriever)
        except Exception as e:
            logger.error("Failed to analyse %s: %s", template_id, e)
            verdict = {"verdict": "ERROR", "reasoning": str(e)}

        dataset.append({
            "question": f"Is alert {template_id} ({template['attack_type']} on {template['target_endpoint']}) a false positive?",
            "answer": verdict.get("reasoning", ""),
            "contexts": contexts,
            "ground_truth": gt["reasoning"],
            "template_id": template_id,
            "expected_verdict": gt["expected_verdict"],
            "actual_verdict": verdict.get("verdict", "UNKNOWN"),
            "confidence": verdict.get("confidence", 0.0),
            "controls_found": verdict.get("controls_found", []),
        })

    return dataset


def compute_metrics(dataset: list[dict]) -> dict:
    """
    Compute evaluation metrics.

    Attempts to use RAGAS if available, otherwise falls back to
    simple accuracy metrics.
    """
    metrics = {}

    # ── Verdict accuracy ──
    correct = sum(1 for d in dataset if d["expected_verdict"] == d["actual_verdict"])
    total = len(dataset)
    metrics["verdict_accuracy"] = correct / total if total > 0 else 0.0
    metrics["correct_verdicts"] = correct
    metrics["total_alerts"] = total

    # ── Per-verdict-type breakdown ──
    fp_correct = sum(
        1 for d in dataset
        if d["expected_verdict"] == "FALSE_POSITIVE" and d["actual_verdict"] == "FALSE_POSITIVE"
    )
    fp_total = sum(1 for d in dataset if d["expected_verdict"] == "FALSE_POSITIVE")
    metrics["false_positive_accuracy"] = fp_correct / fp_total if fp_total > 0 else 0.0

    tp_correct = sum(
        1 for d in dataset
        if d["expected_verdict"] == "TRUE_POSITIVE" and d["actual_verdict"] == "TRUE_POSITIVE"
    )
    tp_total = sum(1 for d in dataset if d["expected_verdict"] == "TRUE_POSITIVE")
    metrics["true_positive_accuracy"] = tp_correct / tp_total if tp_total > 0 else 0.0

    # ── Average confidence ──
    confidences = [d["confidence"] for d in dataset if d["confidence"] > 0]
    metrics["avg_confidence"] = sum(confidences) / len(confidences) if confidences else 0.0

    # ── Retrieval quality: check if expected controls appear in retrieved contexts ──
    # (rough proxy for context relevance)
    from evaluation.ground_truth import GROUND_TRUTH
    gt_lookup = {g["template_id"]: g for g in GROUND_TRUTH}

    context_hits = 0
    context_total = 0
    for d in dataset:
        gt = gt_lookup.get(d["template_id"], {})
        expected_controls = gt.get("expected_controls", [])
        for ctrl in expected_controls:
            context_total += 1
            # Check if the control ID appears in any of the retrieved contexts
            if any(ctrl.lower() in ctx.lower() for ctx in d["contexts"]):
                context_hits += 1

    metrics["context_recall"] = context_hits / context_total if context_total > 0 else 0.0

    # ── Try RAGAS metrics if available ──
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
        metrics["ragas"] = {k: float(v) for k, v in ragas_result.items() if isinstance(v, (int, float))}
        logger.info("RAGAS metrics computed successfully")
    except ImportError:
        logger.warning("RAGAS not available; skipping RAGAS-specific metrics")
        metrics["ragas"] = {"note": "RAGAS library not installed or incompatible"}
    except Exception as e:
        logger.error("RAGAS evaluation failed: %s", e)
        metrics["ragas"] = {"error": str(e)}

    return metrics


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

    # Load ground truth
    from evaluation.ground_truth import GROUND_TRUTH

    logger.info("Running evaluation on %d ground-truth alerts...", len(GROUND_TRUTH))
    dataset = build_evaluation_dataset(openai_client, retriever, GROUND_TRUTH)

    # Compute metrics
    metrics = compute_metrics(dataset)

    # Print report
    print("\n" + "=" * 70)
    print("FPM EVALUATION REPORT")
    print("=" * 70)
    print(f"\nVerdict Accuracy:        {metrics['verdict_accuracy']:.1%} ({metrics['correct_verdicts']}/{metrics['total_alerts']})")
    print(f"False Positive Accuracy: {metrics['false_positive_accuracy']:.1%}")
    print(f"True Positive Accuracy:  {metrics['true_positive_accuracy']:.1%}")
    print(f"Average Confidence:      {metrics['avg_confidence']:.2f}")
    print(f"Context Recall:          {metrics['context_recall']:.1%}")

    if isinstance(metrics.get("ragas"), dict) and "note" not in metrics["ragas"] and "error" not in metrics["ragas"]:
        print("\nRAGAS Metrics:")
        for k, v in metrics["ragas"].items():
            print(f"  {k}: {v:.3f}")

    print("\n" + "-" * 70)
    print("Per-Alert Results:")
    print("-" * 70)
    for d in dataset:
        match = "PASS" if d["expected_verdict"] == d["actual_verdict"] else "FAIL"
        print(f"  [{match}] {d['template_id']}: expected={d['expected_verdict']}, got={d['actual_verdict']} (conf={d['confidence']:.2f})")

    # Save full report to file
    report_path = os.path.join(os.path.dirname(__file__), "report.json")
    with open(report_path, "w") as f:
        json.dump({"metrics": metrics, "results": dataset}, f, indent=2, default=str)
    print(f"\nFull report saved to: {report_path}")


if __name__ == "__main__":
    main()
