"""Does an independent supervised classifier (VulBERTa) corroborate the cases
where our own pipeline (results/qwen_full/) flagged a divergence?

Selection is driven entirely by the method's own judge_vs_vulnerable verdict on
the REAL reference snippets (vulnerable_snippet / fixed_snippet from cases/) -
not the generated candidate. This asks: on the specific cases our method calls
"security_vulnerability_concern", does VulBERTa's P(vulnerable) on the real
vulnerable_snippet come out high (TP), and on the real fixed_snippet for the
SAME cases come out low (no FP)? And does that differ from cases our method did
NOT flag, and from the whole-corpus baseline?

label0 = "vulnerable" per experiments/2026-08-23_vulberta-baseline/spike.py's
empirical direction check.

Usage: python3 experiments/2026-08-23_vulberta-baseline/corroboration.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = ROOT / "results" / "qwen_full"
CASES_DIR = ROOT / "cases"
VULN_LABEL_IDX = 0


def main():
    import torch
    import torch.nn.functional as F
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    print("loading claudios/VulBERTa-MLP-D2A ...", file=sys.stderr)
    tok = AutoTokenizer.from_pretrained("claudios/VulBERTa-MLP-D2A", trust_remote_code=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        "claudios/VulBERTa-MLP-D2A", trust_remote_code=True)
    model.eval()

    def p_vuln(code):
        inputs = tok(code, return_tensors="pt", truncation=True, max_length=1024)
        with torch.no_grad():
            logits = model(**inputs).logits
        return F.softmax(logits, dim=-1)[0][VULN_LABEL_IDX].item()

    result_files = sorted(RESULTS_DIR.glob("*.json"))
    print(f"{len(result_files)} results in {RESULTS_DIR}", file=sys.stderr)

    rows = []
    for i, fp in enumerate(result_files, 1):
        r = json.loads(fp.read_text(encoding="utf-8"))
        cid = r["case_id"]
        case_fp = CASES_DIR / f"{cid}.json"
        if not case_fp.exists():
            continue
        case = json.loads(case_fp.read_text(encoding="utf-8"))
        if not case.get("vulnerable_snippet") or not case.get("fixed_snippet"):
            continue

        flagged_vuln = r["judge_vs_vulnerable"]["category"] == "security_vulnerability_concern"
        flagged_fixed = r["judge_vs_fixed"]["category"] == "security_vulnerability_concern"
        paired_correct = flagged_vuln and not flagged_fixed

        pv = p_vuln(case["vulnerable_snippet"])
        pf = p_vuln(case["fixed_snippet"])

        rows.append({
            "case_id": cid, "cve_id": case.get("cve_id"),
            "flagged_vuln": flagged_vuln, "flagged_fixed": flagged_fixed,
            "paired_correct": paired_correct,
            "p_vuln_snippet": pv, "p_fixed_snippet": pf,
        })
        if i % 50 == 0 or i == len(result_files):
            print(f"[{i}/{len(result_files)}] scored", file=sys.stderr)

    out_dir = Path(__file__).resolve().parent
    (out_dir / "corroboration_results.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")

    def report(name, subset):
        n = len(subset)
        if n == 0:
            print(f"\n=== {name} (n=0) === skipped, empty subset")
            return
        tp = sum(1 for r in subset if r["p_vuln_snippet"] > 0.5)
        fp = sum(1 for r in subset if r["p_fixed_snippet"] > 0.5)
        print(f"\n=== {name} (n={n}) ===")
        print(f"  TP rate (VulBERTa flags real vulnerable_snippet) : {tp}/{n} ({tp/n:.1%})")
        print(f"  FP rate (VulBERTa flags real fixed_snippet)      : {fp}/{n} ({fp/n:.1%})")
        print(f"  gap (TP - FP)                                    : {(tp-fp)/n:+.1%}")

    report("ALL cases (whole-corpus baseline)", rows)
    report("Our method FLAGGED vulnerable side (judge_vs_vulnerable = security_vulnerability_concern)",
           [r for r in rows if r["flagged_vuln"]])
    report("Our method did NOT flag vulnerable side (control group)",
           [r for r in rows if not r["flagged_vuln"]])
    report("Our method's PAIRED-CORRECT cases (flagged vuln AND NOT flagged fixed)",
           [r for r in rows if r["paired_correct"]])


if __name__ == "__main__":
    main()
