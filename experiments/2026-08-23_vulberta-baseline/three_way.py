"""VulBERTa, three-way: for every case that has at least one previously
generated candidate (pilot / ablation_baseline / ablation_context), score
vulnerable_snippet, fixed_snippet, AND every stored candidate. Tests whether an
independent, non-LLM, supervised classifier (never trained on this corpus,
never trained on anything LLM-generated) agrees with the project's own
LLM-judge verdicts about which side the candidate resembles.

label0 = 'vulnerable-leaning' per experiments/2026-08-23_vulberta-baseline/spike.py's
directional check on this corpus's own ground truth (confirm on a larger sample
before treating as settled).

Usage: python3 experiments/2026-08-23_vulberta-baseline/three_way.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
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

    cases = {d["case_id"]: d for fp in CASES_DIR.glob("*.json")
              for d in [json.loads(fp.read_text(encoding="utf-8"))]}

    candidates = {}  # case_id -> {arm: code}
    for arm in ["pilot", "ablation_baseline", "ablation_context"]:
        for fp in (ROOT / "results" / arm).glob("*.json"):
            r = json.loads(fp.read_text(encoding="utf-8"))
            code = r.get("generated_code")
            if code:
                candidates.setdefault(r["case_id"], {})[arm] = code

    rows = []
    n_cand_closer_to_fixed = 0
    n_cand_closer_to_vuln = 0
    n_cand_tie = 0
    n_cand_total = 0

    for cid, arms in sorted(candidates.items()):
        case = cases.get(cid)
        if case is None:
            continue
        pv = p_vuln(case["vulnerable_snippet"])
        pf = p_vuln(case["fixed_snippet"])
        row = {"case_id": cid, "cve_id": case.get("cve_id"),
               "p_vuln_snippet": pv, "p_fixed_snippet": pf, "candidates": {}}
        print(f"\n{cid} ({case.get('cve_id')})", file=sys.stderr)
        print(f"  vulnerable_snippet p_vuln={pv:.3f}   fixed_snippet p_vuln={pf:.3f}",
              file=sys.stderr)
        for arm, code in arms.items():
            pc = p_vuln(code)
            row["candidates"][arm] = pc
            dist_to_vuln = abs(pc - pv)
            dist_to_fixed = abs(pc - pf)
            closer = "VULNERABLE" if dist_to_vuln < dist_to_fixed else "FIXED" if dist_to_fixed < dist_to_vuln else "TIE"
            if closer == "VULNERABLE":
                n_cand_closer_to_vuln += 1
            elif closer == "FIXED":
                n_cand_closer_to_fixed += 1
            else:
                n_cand_tie += 1
            n_cand_total += 1
            print(f"  candidate[{arm:18s}] p_vuln={pc:.3f}  closer to -> {closer}",
                  file=sys.stderr)
        rows.append(row)

    out_dir = Path(__file__).resolve().parent
    (out_dir / "three_way_results.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")

    print(f"\n\n=== Summary over {n_cand_total} (case, arm) candidate scorings "
          f"across {len(rows)} cases ===")
    print(f"candidate closer to VULNERABLE reference: {n_cand_closer_to_vuln} "
          f"({n_cand_closer_to_vuln/n_cand_total:.1%})")
    print(f"candidate closer to FIXED reference     : {n_cand_closer_to_fixed} "
          f"({n_cand_closer_to_fixed/n_cand_total:.1%})")
    print(f"tie                                      : {n_cand_tie} "
          f"({n_cand_tie/n_cand_total:.1%})")


if __name__ == "__main__":
    main()
