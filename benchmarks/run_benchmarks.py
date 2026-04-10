"""
External benchmark evaluation for StegOFF.

Runs the detection stack against published prompt injection datasets
that were NOT used during training. Reports precision, recall, F1,
and AUC-ROC per layer and per dataset.

Datasets:
  1. xTRam1/safe-guard-prompt-injection (test split, 2060 samples)
     Binary: injection (1) vs clean (0). 4.4% overlap with training data.
  2. TensorTrust extraction attacks (570 attack prompts)
     Recall-only: all samples are attacks.
  3. TensorTrust prompt extraction detection (230 samples)
     Binary: LLM output that leaked vs didn't leak the prompt.
  4. Lakera/gandalf_ignore_instructions (777 attack prompts)
     Recall-only: all samples are "ignore instructions" attacks.

Usage:
    python benchmarks/run_benchmarks.py
    python benchmarks/run_benchmarks.py --dataset safeguard
    python benchmarks/run_benchmarks.py --layer l2  # transformer only
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    classification_report,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from stegoff.orchestrator import scan_text
from stegoff.ml.transformer_classifier import TransformerDetector

logger = logging.getLogger(__name__)


def load_safeguard() -> tuple[list[str], list[int], str]:
    """xTRam1/safe-guard-prompt-injection test split."""
    from datasets import load_dataset
    ds = load_dataset("xTRam1/safe-guard-prompt-injection", trust_remote_code=True)
    texts = ds["test"]["text"]
    labels = ds["test"]["label"]
    return texts, labels, "SafeGuard (xTRam1)"


def load_tensortrust_attacks() -> tuple[list[str], list[int], str]:
    """TensorTrust extraction robustness attacks (all positive)."""
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(
        "qxcv/tensor-trust",
        "benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl",
        repo_type="dataset",
    )
    with open(path, "r", encoding="utf-8") as f:
        rows = [json.loads(l) for l in f]
    texts = [r["attack"] for r in rows if len(r.get("attack", "")) >= 10]
    labels = [1] * len(texts)
    return texts, labels, "TensorTrust Extraction Attacks"


def load_tensortrust_detection() -> tuple[list[str], list[int], str]:
    """TensorTrust prompt extraction detection (binary)."""
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(
        "qxcv/tensor-trust",
        "detecting-extractions/v1/prompt_extraction_detection.jsonl",
        repo_type="dataset",
    )
    with open(path, "r", encoding="utf-8") as f:
        rows = [json.loads(l) for l in f]
    texts = [r["llm_output"] for r in rows]
    labels = [1 if r["is_prompt_extraction"] else 0 for r in rows]
    return texts, labels, "TensorTrust Detection"


def load_gandalf() -> tuple[list[str], list[int], str]:
    """Lakera gandalf ignore-instructions attacks (all positive)."""
    from datasets import load_dataset
    ds = load_dataset("Lakera/gandalf_ignore_instructions", trust_remote_code=True)
    split = list(ds.keys())[0]
    texts = [r["text"] for r in ds[split] if len(r.get("text", "")) >= 10]
    labels = [1] * len(texts)
    return texts, labels, "Gandalf (Lakera)"


LOADERS = {
    "safeguard": load_safeguard,
    "tensortrust_attacks": load_tensortrust_attacks,
    "tensortrust_detection": load_tensortrust_detection,
    "gandalf": load_gandalf,
}


def eval_l1(texts: list[str], labels: list[int]) -> dict:
    """Evaluate L1 (regex + pattern matching, no LLM/transformer)."""
    preds = []
    for text in texts:
        report = scan_text(text, use_llm=False)
        preds.append(0 if report.clean else 1)
    return _compute_metrics(labels, preds, "L1 (regex)")


def eval_l2_transformer(texts: list[str], labels: list[int]) -> dict:
    """Evaluate transformer L2 in isolation."""
    detector = TransformerDetector.load()
    if detector is None:
        return {"layer": "L2 transformer", "error": "model not found"}
    preds = []
    scores = []
    for text in texts:
        pred = detector.predict(text)
        preds.append(1 if pred.is_trap else 0)
        scores.append(pred.raw_score)
    return _compute_metrics(labels, preds, "L2 (transformer)", scores)


def eval_full_pipeline(texts: list[str], labels: list[int]) -> dict:
    """Evaluate full L1 + L2 pipeline."""
    preds = []
    for text in texts:
        report = scan_text(text, use_llm=True)
        preds.append(0 if report.clean else 1)
    return _compute_metrics(labels, preds, "L1+L2 (full)")


def _compute_metrics(
    labels: list[int],
    preds: list[int],
    layer_name: str,
    scores: list[float] | None = None,
) -> dict:
    y_true = np.array(labels)
    y_pred = np.array(preds)

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0,
    )
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

    result = {
        "layer": layer_name,
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "total": len(labels),
    }

    if scores is not None and len(set(labels)) > 1:
        try:
            result["auc_roc"] = float(roc_auc_score(y_true, np.array(scores)))
        except ValueError:
            pass

    return result


def run_benchmark(dataset_name: str, layers: list[str]) -> list[dict]:
    """Run benchmark for a single dataset across specified layers."""
    loader = LOADERS[dataset_name]
    texts, labels, display_name = loader()

    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    print(f"\n{'='*60}")
    print(f"  {display_name}")
    print(f"  {len(texts)} samples ({n_pos} injection, {n_neg} clean)")
    print(f"{'='*60}")

    results = []
    for layer in layers:
        t0 = time.time()
        if layer == "l1":
            metrics = eval_l1(texts, labels)
        elif layer == "l2":
            metrics = eval_l2_transformer(texts, labels)
        elif layer == "full":
            metrics = eval_full_pipeline(texts, labels)
        else:
            continue
        elapsed = time.time() - t0

        metrics["dataset"] = display_name
        metrics["elapsed_s"] = round(elapsed, 1)
        results.append(metrics)

        if "error" in metrics:
            print(f"  {metrics['layer']}: {metrics['error']}")
            continue

        line = (
            f"  {metrics['layer']:20s} | "
            f"P={metrics['precision']:.3f} R={metrics['recall']:.3f} F1={metrics['f1']:.3f}"
        )
        if "auc_roc" in metrics:
            line += f" AUC={metrics['auc_roc']:.3f}"
        line += f" | TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} TN={metrics['tn']}"
        line += f" | {elapsed:.1f}s"
        print(line)

    return results


def print_summary_table(all_results: list[dict]):
    """Print a markdown-style summary table."""
    print(f"\n{'='*80}")
    print("  SUMMARY")
    print(f"{'='*80}\n")
    print(f"| {'Dataset':35s} | {'Layer':20s} | {'Prec':>5s} | {'Recall':>6s} | {'F1':>5s} | {'AUC':>5s} |")
    print(f"|{'-'*37}|{'-'*22}|{'-'*7}|{'-'*8}|{'-'*7}|{'-'*7}|")
    for r in all_results:
        if "error" in r:
            continue
        auc = f"{r['auc_roc']:.3f}" if "auc_roc" in r else "  -  "
        print(
            f"| {r['dataset']:35s} | {r['layer']:20s} | "
            f"{r['precision']:.3f} | {r['recall']:.4f} | {r['f1']:.3f} | {auc} |"
        )


def main():
    parser = argparse.ArgumentParser(description="StegOFF external benchmarks")
    parser.add_argument(
        "--dataset",
        choices=list(LOADERS.keys()) + ["all"],
        default="all",
    )
    parser.add_argument(
        "--layer",
        choices=["l1", "l2", "full", "all"],
        default="all",
    )
    parser.add_argument("--json-out", type=Path, help="Save results to JSON file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    datasets = list(LOADERS.keys()) if args.dataset == "all" else [args.dataset]
    layers = ["l1", "l2", "full"] if args.layer == "all" else [args.layer]

    all_results = []
    for ds_name in datasets:
        results = run_benchmark(ds_name, layers)
        all_results.extend(results)

    print_summary_table(all_results)

    if args.json_out:
        args.json_out.write_text(json.dumps(all_results, indent=2))
        print(f"\nResults saved to {args.json_out}")


if __name__ == "__main__":
    main()
