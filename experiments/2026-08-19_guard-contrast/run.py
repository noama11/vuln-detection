"""The strongest defensible version of the original method.

WHAT IS PRESERVED (the core research premise, unchanged):
  - the Generator sees ONLY {language, docstring}. Never any code, CVE id, repo
    or commit message. This arm does not even re-run it: it reuses the exact
    candidates from results/qwen_full/, so the generation half is byte-identical
    to the published arm.
  - the Judge compares that candidate against ONE reference at a time, and is
    never told which reference it is or that a vulnerability is involved.
  - no supervised labels, no training. The vulnerable/fixed pairing is the
    evaluation harness only; the detector never sees it.

WHAT CHANGES (the judge's question, and only that):
  - the 5-way holistic taxonomy is replaced by one narrow predicate: which side,
    if either, omits a defensive step the other performs?
  - the two implementations are presented as anonymous peers, 1 and 2, in an
    order randomised per case, so the judge cannot key on "the reference looks
    authentic". The slot assignment is fixed within a case, so the two judge
    calls differ only in the reference content.
  - the output is a continuous exposure score plus explicit lists of the
    defensive steps that differ, instead of a category whose score range the
    rubric pre-binds.
  - `neither` is a first-class answer, so the detector may abstain rather than
    being forced into a coin flip. Abstentions are reported, never silently
    counted as negatives.

WHY THIS IS THE RIGHT CHANGE: WP5 showed the same model reaches 84.4% when asked
the guard-omission question with both versions present, against 16.0% for the
published rubric. The information and the capability are both there; the
formulation was throwing them away. This arm applies the working question to the
deployable setting - one reference at a time, the other side supplied by
reconstruction from the spec alone.

Usage:
    python3 experiments/2026-08-19_guard-contrast/run.py --limit 3
    python3 experiments/2026-08-19_guard-contrast/run.py --concurrency 8
"""
import argparse
import json
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import vllm_client as V  # noqa: E402
from data import load_cases, load_records  # noqa: E402

SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string"},
        "defensive_steps_only_in_1": {"type": "array", "items": {"type": "string"}},
        "defensive_steps_only_in_2": {"type": "array", "items": {"type": "string"}},
        "exposure_of_1": {"type": "integer", "minimum": 0, "maximum": 10},
        "exposure_of_2": {"type": "integer", "minimum": 0, "maximum": 10},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["rationale", "defensive_steps_only_in_1", "defensive_steps_only_in_2",
                 "exposure_of_1", "exposure_of_2", "confidence"],
    "additionalProperties": False,
}

KEY_ORDER = ("Emit the JSON object with its keys in this order: rationale, "
             "defensive_steps_only_in_1, defensive_steps_only_in_2, "
             "exposure_of_1, exposure_of_2, confidence.")

_lock = threading.Lock()


def log(m):
    with _lock:
        print(m, flush=True)


def judge_one(case, candidate, reference, cand_slot, client, system, args, max_model_len):
    """One judge call. `cand_slot` is 1 or 2 - which label the candidate wears."""
    impl1 = candidate if cand_slot == 1 else reference
    impl2 = reference if cand_slot == 1 else candidate
    user = (f"specification:\n{case['docstring']}\n\n"
            f"implementation_1:\n{impl1}\n\n"
            f"implementation_2:\n{impl2}\n\n{KEY_ORDER}")
    if V.estimate_tokens(system, user) > max_model_len - 1024:
        raise ValueError("oversize_prompt")

    raw, finish = client.chat(system=system, user=user, temperature=args.temperature,
                              max_tokens=args.max_tokens, json_schema=SCHEMA)
    v = json.loads(V.THINK_RE.sub("", raw).strip())

    ref_slot = 2 if cand_slot == 1 else 1
    # Steps the CANDIDATE performs and the reference does not are, by definition,
    # listed under the candidate's own slot.
    ref_missing = v[f"defensive_steps_only_in_{cand_slot}"]
    cand_missing = v[f"defensive_steps_only_in_{ref_slot}"]

    return {
        # The detection signal: how exposed the REFERENCE is left by what it omits.
        # Rated independently of the candidate's own rating, so the candidate being
        # generally weaker (it usually is) cannot suppress it.
        "reference_exposure": v[f"exposure_of_{ref_slot}"],
        "candidate_exposure": v[f"exposure_of_{cand_slot}"],
        "reference_missing_steps": ref_missing,
        "candidate_missing_steps": cand_missing,
        "n_reference_missing": len(ref_missing),
        "n_candidate_missing": len(cand_missing),
        "confidence": v["confidence"],
        "rationale": v["rationale"],
        "finish_reason": finish,
    }


def run_case(case, candidate, client, system, args, max_model_len):
    cid = case["case_id"]
    # Slot is fixed within a case: both judge calls put the candidate in the same
    # position, so the only thing that differs between them is the reference.
    cand_slot = 1 if random.Random(f"{args.seed}:{cid}").random() < 0.5 else 2

    jv = judge_one(case, candidate, case["vulnerable_snippet"], cand_slot,
                   client, system, args, max_model_len)
    jf = judge_one(case, candidate, case["fixed_snippet"], cand_slot,
                   client, system, args, max_model_len)

    return {
        "case_id": cid, "sample_id": case["sample_id"], "func_idx": case["func_idx"],
        "language": case["language"], "repo": case["repo"], "cve_id": case["cve_id"],
        "cve_summary": case["cve_summary"], "changed_file": case["changed_file"],
        "docstring": case["docstring"],
        "heuristic_leakage_flag": case["heuristic_leakage_flag"],
        "generated_code": candidate,
        "candidate_slot": cand_slot,
        "judge_vs_vulnerable": jv,
        "judge_vs_fixed": jf,
        # Primary: does the vulnerable reference look more exposed than the fixed
        # one to the same candidate? Chance = 50% on the decided subset.
        "correct_direction": jv["reference_exposure"] > jf["reference_exposure"],
        "tied": jv["reference_exposure"] == jf["reference_exposure"],
        "runtime": {"arm": "guard_contrast", "backend": "vllm",
                    "served_model": client.model, "temperature": args.temperature,
                    "seed": args.seed, "thinking": args.thinking,
                    "judge_prompt_sha": args.prompt_sha,
                    "candidates_from": "results/qwen_full (published arm, unmodified)"},
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--thinking", action="store_true")
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=1536)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--run", default="guard_contrast")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    base_url = V.read_endpoint(args.base_url)
    try:
        served_model, max_model_len = V.server_info(base_url)
    except Exception as exc:
        print(f"cannot reach vLLM at {base_url} ({exc}).\n"
              f"Start it with: bash scripts/serve_qwen.sh")
        return 1
    if args.thinking:
        args.max_tokens = max(args.max_tokens, 4096)

    system = (HERE / "prompts" / "judge_guard_contrast.md").read_text(encoding="utf-8")
    args.prompt_sha = V.prompt_sha(system)

    cases = load_cases()
    published = load_records(ROOT / "results" / "qwen_full")
    candidates = {cid: r.get("generated_code", "") for cid, r in published.items()}
    cases = {cid: c for cid, c in cases.items() if candidates.get(cid, "").strip()}

    results_dir = HERE / "results" / args.run
    (results_dir / "logs").mkdir(parents=True, exist_ok=True)
    todo = [c for cid, c in sorted(cases.items())
            if args.force or not (results_dir / f"{cid}.json").exists()]
    if args.limit:
        todo = todo[:args.limit]

    print(f"endpoint    : {base_url} (model {served_model})")
    print(f"judge prompt: {args.prompt_sha}  (guard-contrast rubric; the generator "
          f"half is untouched)")
    print(f"candidates  : reused verbatim from results/qwen_full/ - the generation "
          f"step is identical to the published arm")
    print(f"cases       : {len(todo)}\n")
    if not todo:
        print("nothing to do")
        return 0

    client = V.Client(base_url, served_model, args.thinking, args.seed, args.timeout)
    ok = failed = done = correct = tied = 0
    t0 = time.time()

    def worker(case):
        last = None
        for attempt in (1, 2):
            try:
                return run_case(case, candidates[case["case_id"]], client, system,
                                args, max_model_len)
            except Exception as exc:  # noqa: BLE001
                last = exc
                if attempt == 1:
                    time.sleep(2)
        raise last

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(worker, c): c for c in todo}
        for fut in as_completed(futures):
            case = futures[fut]
            done += 1
            try:
                rec = fut.result()
            except Exception as exc:  # noqa: BLE001
                failed += 1
                with (results_dir / "logs" / "failures.jsonl").open("a") as f:
                    f.write(json.dumps({"case_id": case["case_id"],
                                        "error": f"{type(exc).__name__}: {exc}"}) + "\n")
                log(f"[{done}/{len(todo)}] {case['case_id']}: FAILED {exc}")
                continue
            (results_dir / f"{rec['case_id']}.json").write_text(
                json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
            ok += 1
            correct += rec["correct_direction"]
            tied += rec["tied"]
            if done % 25 == 0 or done == len(todo):
                dec = ok - tied
                log(f"[{done}/{len(todo)}] correct {correct}/{dec} decided "
                    f"({correct/max(dec,1):.1%}), tied {tied}")

    dec = ok - tied
    print(f"\ndone in {(time.time()-t0)/60:.1f} min - ok={ok} failed={failed}")
    print(f"directional accuracy (decided) : {correct}/{dec} "
          f"({correct/max(dec,1):.1%})   [chance = 50%]")
    print(f"ties / abstentions             : {tied}/{ok} ({tied/max(ok,1):.1%})")
    print("\nnext: python3 experiments/2026-08-19_guard-contrast/report.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
