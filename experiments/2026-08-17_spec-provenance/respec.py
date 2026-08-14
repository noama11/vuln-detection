"""WP4(b) - the causal test of the provenance confound.

WP4(a) shows the corpus's specifications are derived from the vulnerable code:
identifiers unique to the vulnerable side appear in docstrings 3.7x more often
than fixed-only ones (p = 2.9e-6). That is correlational. This arm makes it
causal by regenerating the specification from the **fixed** side and re-running
the method against it.

Prediction if provenance is the mechanism: the direction of the bias flips - the
mean score gap turns positive and ROC-AUC crosses 0.5. If nothing moves,
provenance is exonerated and the information-deficit account stands alone. Both
outcomes are reportable.

Writes regenerated cases to this arm's own `cases_fixed_spec/`. **`cases/*.json`
is never modified** - unlike the earlier `apply_docstring_fixes.py` pass, which
rewrote docstrings in place.

Two stages:
    --stage respec   generate the fixed-side specifications
    --stage run      run the full method (generator + 2 judges) against them

Usage:
    python3 experiments/2026-08-17_spec-provenance/respec.py --stage respec --limit 150
    python3 experiments/2026-08-17_spec-provenance/respec.py --stage run
"""
import argparse
import json
import random
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import vllm_client as V  # noqa: E402
from data import load_cases  # noqa: E402

CASES_OUT = HERE / "cases_fixed_spec"
RESULTS_OUT = HERE / "results" / "fixed_spec_method"

FORBIDDEN_IN_GENERATOR = ["vulnerable_snippet", "fixed_snippet", "cve_id",
                          "cve_summary", "commit_message", "repo", "changed_file"]

_lock = threading.Lock()


def log(m):
    with _lock:
        print(m, flush=True)


def stratified_subset(cases, n, seed=1234):
    """Sample n cases, at most one per CVE, spread across repos in proportion.

    One per CVE keeps the sample's effective size honest: multi-function commits
    would otherwise contribute several correlated cases.
    """
    by_cve = defaultdict(list)
    for cid, c in sorted(cases.items()):
        by_cve[c["cve_id"]].append(cid)
    rng = random.Random(seed)
    reps = [rng.choice(v) for v in by_cve.values()]
    rng.shuffle(reps)
    return {cid: cases[cid] for cid in sorted(reps[:n])}


# --------------------------------------------------------------------------- #

def do_respec(cases, client, args):
    system = (HERE / "prompts" / "respec_from_fixed.md").read_text(encoding="utf-8")
    sha = V.prompt_sha(system)
    CASES_OUT.mkdir(parents=True, exist_ok=True)
    todo = [c for cid, c in sorted(cases.items())
            if args.force or not (CASES_OUT / f"{cid}.json").exists()]
    print(f"respec prompt sha : {sha}\ncases to respec   : {len(todo)}\n")
    if not todo:
        return

    def worker(case):
        raw, finish = client.chat(
            system=system,
            user=f"language: {case['language']}\nfunction:\n{case['fixed_snippet']}",
            temperature=args.temperature, max_tokens=args.max_tokens)
        spec = V.THINK_RE.sub("", raw).strip()
        if spec.startswith("```"):
            spec = V.strip_code_fences(spec)
        if len(spec) < 80:
            raise ValueError(f"suspiciously short spec ({len(spec)} chars)")
        out = dict(case)
        out["docstring"] = spec
        out["docstring_provenance"] = "regenerated_from_fixed_snippet"
        out["original_docstring"] = case["docstring"]
        out["respec_prompt_sha"] = sha
        out["respec_finish_reason"] = finish
        return out

    done = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(worker, c): c for c in todo}
        for fut in as_completed(futures):
            case = futures[fut]
            done += 1
            try:
                out = fut.result()
            except Exception as exc:  # noqa: BLE001
                log(f"[{done}/{len(todo)}] {case['case_id']}: FAILED {exc}")
                continue
            (CASES_OUT / f"{out['case_id']}.json").write_text(
                json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
            if done % 20 == 0 or done == len(todo):
                log(f"[{done}/{len(todo)}] respecced")

    # Leakage gate: the regenerated spec must not quote the code it came from.
    # Same >=25-char shared-line check the published arm's section 7 describes.
    leaks = []
    for fp in sorted(CASES_OUT.glob("*.json")):
        c = json.loads(fp.read_text(encoding="utf-8"))
        spec_lines = {l.strip() for l in c["docstring"].split("\n") if len(l.strip()) >= 25}
        for side in ("vulnerable_snippet", "fixed_snippet"):
            code_lines = {l.strip() for l in (c[side] or "").split("\n")
                          if len(l.strip()) >= 25}
            shared = spec_lines & code_lines
            if shared:
                leaks.append((c["case_id"], side, sorted(shared)[:2]))
    print(f"\nleakage gate: {len(leaks)} case(s) share a >=25-char line with a snippet")
    for cid, side, ex in leaks[:10]:
        print(f"  {cid} [{side}]: {ex}")
    (HERE / "respec_leakage_gate.json").write_text(
        json.dumps([{"case_id": c, "side": s, "shared": e} for c, s, e in leaks],
                   indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #

def do_run(client, args, max_model_len):
    """The published method, verbatim, against the regenerated specs."""
    prompts = V.load_prompts()  # unmodified rubric -> prompt_sha 1de29ae28c7d
    cases = {}
    for fp in sorted(CASES_OUT.glob("*.json")):
        c = json.loads(fp.read_text(encoding="utf-8"))
        cases[c["case_id"]] = c
    if not cases:
        print(f"no regenerated cases in {CASES_OUT} - run --stage respec first")
        return
    (RESULTS_OUT / "logs").mkdir(parents=True, exist_ok=True)
    todo = [c for cid, c in sorted(cases.items())
            if args.force or not (RESULTS_OUT / f"{cid}.json").exists()]
    print(f"prompt sha : {prompts['sha']}  (expect 1de29ae28c7d)\n"
          f"cases      : {len(todo)}\n")
    if not todo:
        return

    def worker(case):
        cid = case["case_id"]
        gen_user = f"language: {case['language']}\ndocstring:\n{case['docstring']}"
        for field in FORBIDDEN_IN_GENERATOR:
            v = case.get(field)
            if isinstance(v, str) and v.strip() and v in gen_user:
                raise AssertionError(f"leakage guard tripped on {field}")
        gen_text, _ = client.chat(system=prompts["generator"], user=gen_user,
                                  temperature=0.2, max_tokens=args.gen_max_tokens)
        candidate = V.strip_code_fences(gen_text)
        if not candidate:
            raise RuntimeError("generator returned empty output")

        def judge(reference):
            raw, finish = client.chat(
                system=prompts["judge"],
                user=V.judge_user_message(case["docstring"], candidate, reference),
                temperature=0.0, max_tokens=1024, json_schema=V.JUDGE_SCHEMA)
            return V.parse_verdict(raw, finish)

        jv, jf = judge(case["vulnerable_snippet"]), judge(case["fixed_snippet"])
        return {
            "case_id": cid, "sample_id": case["sample_id"], "func_idx": case["func_idx"],
            "language": case["language"], "repo": case["repo"], "cve_id": case["cve_id"],
            "cve_summary": case["cve_summary"], "changed_file": case["changed_file"],
            "docstring": case["docstring"],
            "heuristic_leakage_flag": case["heuristic_leakage_flag"],
            "generated_code": candidate,
            "generator_model": args.model_label, "judge_model": args.model_label,
            "judge_vs_vulnerable": jv, "judge_vs_fixed": jf,
            "pairwise_ranking_correct": jf["score"] > jv["score"],
            "paired_flag_correct": (jv["category"] == "security_vulnerability_concern"
                                    and jf["category"] != "security_vulnerability_concern"),
            "runtime": {"arm": "fixed_spec_method", "backend": "vllm",
                        "served_model": client.model, "seed": args.seed,
                        "docstring_provenance": "regenerated_from_fixed_snippet",
                        "respec_prompt_sha": case.get("respec_prompt_sha"),
                        "prompt_sha": prompts["sha"]},
        }

    done = flagged = failed = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(worker, c): c for c in todo}
        for fut in as_completed(futures):
            case = futures[fut]
            done += 1
            try:
                rec = fut.result()
            except Exception as exc:  # noqa: BLE001
                failed += 1
                with (RESULTS_OUT / "logs" / "failures.jsonl").open("a") as f:
                    f.write(json.dumps({"case_id": case["case_id"],
                                        "error": f"{type(exc).__name__}: {exc}"}) + "\n")
                log(f"[{done}/{len(todo)}] {case['case_id']}: FAILED {exc}")
                continue
            (RESULTS_OUT / f"{rec['case_id']}.json").write_text(
                json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
            flagged += rec["paired_flag_correct"]
            if done % 20 == 0 or done == len(todo):
                log(f"[{done}/{len(todo)}] paired-flag {flagged}")
    print(f"\ndone - paired-flag {flagged}/{done - failed} "
          f"({flagged/max(done - failed, 1):.1%}), failed {failed}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=["respec", "run"], required=True)
    p.add_argument("--limit", type=int, default=150,
                   help="stratified subset size for --stage respec (one per CVE)")
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--model-label", default="qwen3-32b-awq")
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--max-tokens", type=int, default=1024)
    p.add_argument("--gen-max-tokens", type=int, default=4096,
                   help="4096, not the published 2048 - that cap truncated 4 candidates")
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    base_url = V.read_endpoint(args.base_url)
    try:
        served_model, max_model_len = V.server_info(base_url)
    except Exception as exc:
        print(f"cannot reach vLLM at {base_url} ({exc}).\n"
              f"Start it with: bash scripts/serve_qwen.sh")
        return 1
    client = V.Client(base_url, served_model, False, args.seed, args.timeout)

    if args.stage == "respec":
        cases = stratified_subset(load_cases(), args.limit, args.seed)
        print(f"stratified subset: {len(cases)} cases, one per CVE")
        do_respec(cases, client, args)
    else:
        do_run(client, args, max_model_len)
    return 0


if __name__ == "__main__":
    sys.exit(main())
