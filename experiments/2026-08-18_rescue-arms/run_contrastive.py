"""WP5-R2 - the contrastive judge.

The published method asks the judge two independent questions that share the
candidate and differ only in the reference. WP1's permutation test shows the
reference barely enters the verdict: paired flag accuracy is indistinguishable
from a null in which the label has no effect. The likely reason is structural -
each call sees only one reference, so "is this difference security-relevant?" is
dominated by whatever the candidate happens to differ from in general.

The contrastive arm asks **one** question with **both** references present, in
randomised order, and narrows it to the only thing that matters: does one side
omit a defensive step the other performs? That

  - removes the shared-candidate confound the permutation test identified,
  - gives a clean 50% chance baseline instead of PFA's 25%,
  - halves the number of judge calls.

Two modes, because WP2 showed the judge is a bottleneck in its own right:

  --mode oracle     A/B are the vulnerable and fixed snippets themselves.
                    No reconstruction at all: the ceiling for the judging half.
  --mode generated  A/B are the same two references, but the spec-reconstruction
                    candidate is also supplied as context, matching the method.

`neither` is a permitted answer and is scored as an abstention, reported
separately, so the arm cannot inflate accuracy by forcing guesses.

Usage:
    python3 experiments/2026-08-18_rescue-arms/run_contrastive.py --mode oracle
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
        "missing_guard_side": {"type": "string", "enum": ["A", "B", "neither"]},
        "guard_description": {"type": "string"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["rationale", "missing_guard_side", "guard_description", "confidence"],
    "additionalProperties": False,
}

KEY_ORDER = ("Emit the JSON object with its keys in this order: rationale, "
             "missing_guard_side, guard_description, confidence.")

_lock = threading.Lock()


def log(m):
    with _lock:
        print(m, flush=True)


def run_case(case, client, system, args, max_model_len, candidate=None):
    cid = case["case_id"]
    # Order is randomised per case and derived from the case id, so it is stable
    # across reruns but uncorrelated with anything else. Without this the judge
    # could score well by always answering "A".
    rng = random.Random(f"{args.seed}:{cid}")
    vuln_is_a = rng.random() < 0.5
    a = case["vulnerable_snippet"] if vuln_is_a else case["fixed_snippet"]
    b = case["fixed_snippet"] if vuln_is_a else case["vulnerable_snippet"]

    parts = [f"specification:\n{case['docstring']}"]
    if candidate:
        parts.append(f"independent_reference_implementation:\n{candidate}")
    parts += [f"implementation_A:\n{a}", f"implementation_B:\n{b}", KEY_ORDER]
    user = "\n\n".join(parts)

    if V.estimate_tokens(system, user) > max_model_len - 1024:
        return "skipped", {"case_id": cid, "reason": "oversize_prompt"}

    raw, finish = client.chat(system=system, user=user,
                              temperature=args.temperature,
                              max_tokens=args.max_tokens, json_schema=SCHEMA)
    v = json.loads(V.THINK_RE.sub("", raw).strip())
    side = v["missing_guard_side"]
    # The vulnerable side is the one missing the guard, so a correct answer
    # points at whichever label the vulnerable snippet was assigned.
    correct_side = "A" if vuln_is_a else "B"
    return "ok", {
        "case_id": cid, "sample_id": case["sample_id"], "func_idx": case["func_idx"],
        "language": case["language"], "repo": case["repo"], "cve_id": case["cve_id"],
        "changed_file": case["changed_file"], "docstring": case["docstring"],
        "vulnerable_label": correct_side,
        "answer": side,
        "abstained": side == "neither",
        "correct": side == correct_side,
        "guard_description": v["guard_description"],
        "confidence": v["confidence"],
        "rationale": v["rationale"],
        "finish_reason": finish,
        "runtime": {"arm": f"contrastive_{args.mode}", "backend": "vllm",
                    "served_model": client.model, "temperature": args.temperature,
                    "seed": args.seed, "thinking": args.thinking,
                    "prompt_sha": args.prompt_sha, "candidate_supplied": bool(candidate)},
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=["oracle", "generated"], default="oracle")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--thinking", action="store_true")
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=1024)
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
    if args.thinking:
        args.max_tokens = max(args.max_tokens, 4096)

    system = (HERE / "prompts" / "judge_contrastive.md").read_text(encoding="utf-8")
    args.prompt_sha = V.prompt_sha(system)
    cases = load_cases()

    candidates = {}
    if args.mode == "generated":
        recs = load_records(ROOT / "results" / "qwen_full")
        candidates = {cid: r.get("generated_code", "") for cid, r in recs.items()}
        cases = {cid: c for cid, c in cases.items() if candidates.get(cid)}

    results_dir = HERE / "results" / f"contrastive_{args.mode}"
    (results_dir / "logs").mkdir(parents=True, exist_ok=True)
    todo = [c for cid, c in sorted(cases.items())
            if args.force or not (results_dir / f"{cid}.json").exists()]
    if args.limit:
        todo = todo[:args.limit]

    client = V.Client(base_url, served_model, args.thinking, args.seed, args.timeout)
    print(f"endpoint   : {base_url} (model {served_model})")
    print(f"prompt sha : {args.prompt_sha}  (contrastive rubric - intentionally "
          f"differs from 1de29ae28c7d)")
    print(f"mode       : {args.mode}\ncases      : {len(todo)}\n")
    if not todo:
        print("nothing to do")
        return 0

    counts = {"ok": 0, "skipped": 0, "failed": 0}
    correct = abstain = done = 0
    t0 = time.time()

    def worker(case):
        last = None
        for attempt in (1, 2):
            try:
                return run_case(case, client, system, args, max_model_len,
                                candidates.get(case["case_id"]))
            except Exception as exc:  # noqa: BLE001
                last = exc
                if attempt == 1:
                    time.sleep(2)
        return "failed", {"case_id": case["case_id"],
                          "error": f"{type(last).__name__}: {last}"}

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(worker, c): c for c in todo}
        for fut in as_completed(futures):
            status, payload = fut.result()
            done += 1
            counts[status] += 1
            if status == "ok":
                (results_dir / f"{payload['case_id']}.json").write_text(
                    json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                correct += payload["correct"]
                abstain += payload["abstained"]
                if done % 25 == 0 or done == len(todo):
                    decided = done - abstain
                    log(f"[{done}/{len(todo)}] correct {correct} "
                        f"({correct/max(decided,1):.1%} of {decided} decided), "
                        f"abstained {abstain}")
            else:
                fn = "skipped.jsonl" if status == "skipped" else "failures.jsonl"
                with (results_dir / "logs" / fn).open("a", encoding="utf-8") as f:
                    f.write(json.dumps(payload) + "\n")
                log(f"[{done}/{len(todo)}] {payload['case_id']}: {status}")

    decided = counts["ok"] - abstain
    print(f"\ndone in {(time.time()-t0)/60:.1f} min - ok={counts['ok']} "
          f"skipped={counts['skipped']} failed={counts['failed']}")
    print(f"accuracy over decided cases : {correct}/{decided} "
          f"({correct/max(decided,1):.1%})   [chance = 50%]")
    print(f"accuracy over all cases     : {correct}/{counts['ok']} "
          f"({correct/max(counts['ok'],1):.1%})")
    print(f"abstentions ('neither')     : {abstain}/{counts['ok']} "
          f"({abstain/max(counts['ok'],1):.1%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
