"""Quick spike: does VulBERTa (an established supervised classifier, RoBERTa-MLP
fine-tuned on CodeXGLUE Devign) separate this project's vulnerable/fixed pairs at
all, and does it rate the LLM-reconstructed candidate closer to one side?

Not a committed experiment arm yet - a feasibility sample, run locally on CPU
(the model is ~0.1B params, no GPU/SLURM needed, unlike the Qwen arms).

Usage: python3 experiments/2026-08-23_vulberta-baseline/spike.py [--n 40]
"""
import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CASES_DIR = ROOT / "cases"


def load_ok_cases():
    cases = []
    for fp in CASES_DIR.glob("*.json"):
        d = json.loads(fp.read_text(encoding="utf-8"))
        if d.get("extraction_status") == "ok":
            cases.append(d)
    return cases


def find_candidate(case_id):
    """Pull a previously-generated candidate for this case if one exists,
    preferring the cleanest/most recent source."""
    for results_dir in ["pilot", "ablation_baseline", "ablation_context"]:
        fp = ROOT / "results" / results_dir / f"{case_id}.json"
        if fp.exists():
            d = json.loads(fp.read_text(encoding="utf-8"))
            code = d.get("generated_code")
            if code:
                return code, results_dir
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--max-length", type=int, default=1024)
    args = ap.parse_args()

    import torch
    import torch.nn.functional as F
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    print("loading claudios/VulBERTa-MLP-D2A ...", file=sys.stderr)
    tok = AutoTokenizer.from_pretrained("claudios/VulBERTa-MLP-D2A", trust_remote_code=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        "claudios/VulBERTa-MLP-D2A", trust_remote_code=True)
    model.eval()

    def score(code):
        inputs = tok(code, return_tensors="pt", truncation=True, max_length=args.max_length)
        with torch.no_grad():
            logits = model(**inputs).logits
        probs = F.softmax(logits, dim=-1)[0].tolist()
        return probs  # [P(label0), P(label1)]

    all_cases = load_ok_cases()
    random.seed(args.seed)
    sample = random.sample(all_cases, min(args.n, len(all_cases)))
    print(f"sampled {len(sample)}/{len(all_cases)} extraction-ok cases (seed={args.seed})\n",
          file=sys.stderr)

    rows = []
    for i, case in enumerate(sample, 1):
        cid = case["case_id"]
        p_vuln = score(case["vulnerable_snippet"])
        p_fixed = score(case["fixed_snippet"])
        cand_code, cand_src = find_candidate(cid)
        p_cand = score(cand_code) if cand_code else None
        rows.append({
            "case_id": cid, "cve_id": case.get("cve_id"),
            "p_vuln": p_vuln, "p_fixed": p_fixed,
            "p_cand": p_cand, "cand_src": cand_src,
        })
        print(f"[{i}/{len(sample)}] {cid:15s} vuln={p_vuln} fixed={p_fixed}"
              + (f" cand={p_cand} ({cand_src})" if p_cand else ""), file=sys.stderr)

    out_dir = Path(__file__).resolve().parent
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "spike_results.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")

    # Directional check on EACH label index as "the vulnerable label" - this
    # resolves the label convention empirically rather than by assumption,
    # since id2label on the HF port is uninformative (LABEL_0/LABEL_1).
    for label_idx, name in [(0, "label0"), (1, "label1")]:
        higher_on_vuln = sum(1 for r in rows if r["p_vuln"][label_idx] > r["p_fixed"][label_idx])
        tied = sum(1 for r in rows if r["p_vuln"][label_idx] == r["p_fixed"][label_idx])
        n = len(rows)
        print(f"\n[{name} as 'vulnerable' score] "
              f"P({name})[vuln_snippet] > P({name})[fixed_snippet]: "
              f"{higher_on_vuln}/{n} ({higher_on_vuln/n:.1%}), ties={tied}")

    n_cand = sum(1 for r in rows if r["p_cand"] is not None)
    print(f"\ncandidates available for {n_cand}/{len(rows)} sampled cases "
          f"(from prior pilot/ablation runs)")


if __name__ == "__main__":
    main()
