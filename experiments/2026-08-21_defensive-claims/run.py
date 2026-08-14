"""Defensive reconstruction with explicit guard claims — chapter 12.

THE PREMISE IS INTACT. Generator sees only {language, docstring}: no code, no CVE
id, no repo, no commit message, asserted per call. Judge sees one reference at a
time and is never told which. No supervised labels.

WHAT CHANGES, AND WHY

Every previous arm asked the generator to be *faithful* to the specification -
the published prompt says implement "exactly as specified" and make "the
standard, conventional engineering choice" where the spec is silent. Chapter 8
established that these specifications are derived from the vulnerable code, so
faithfulness optimises for reproducing the bug.

This arm asks instead for a *defensively hardened* implementation, plus an
explicit list of the guards it performs. Two consequences:

  - the candidate now draws on secure-coding priors, which are information the
    specification does not contain and every prior arm suppressed;
  - the judge's task becomes per-claim verification ("does this reference perform
    this specific check?") rather than open-ended comparison, which chapter 6
    showed it performs lexically. Irrelevant differences are never asked about,
    so the baseline gap is sidestepped by construction rather than by rubric.

The `not_applicable` verdict is load-bearing: without it, every guard invented
for a construct the real code does not use would score as a false omission.

Usage:
    python3 experiments/2026-08-21_defensive-claims/run.py --stage generate
    python3 experiments/2026-08-21_defensive-claims/run.py --stage judge
"""
import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import vllm_client as V  # noqa: E402
from data import load_cases  # noqa: E402

CAND_DIR = HERE / "candidates"  # overridden per-run by --cand-dir (seed replications)

FORBIDDEN_IN_GENERATOR = ["vulnerable_snippet", "fixed_snippet", "cve_id",
                          "cve_summary", "commit_message", "repo", "changed_file"]

GEN_SCHEMA = {
    "type": "object",
    "properties": {
        "implementation": {"type": "string"},
        "defensive_steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"type": "string"},
                    "protects_against": {"type": "string"},
                },
                "required": ["step", "protects_against"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["implementation", "defensive_steps"],
    "additionalProperties": False,
}

VERDICTS = ["performs", "not_applicable", "omits"]

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"type": "string"},
                    # Reasoning before verdict: a verdict-first schema once
                    # produced self-contradictory output (HANDOFF.md s6).
                    "reasoning": {"type": "string"},
                    "verdict": {"type": "string", "enum": VERDICTS},
                    "severity": {"type": "integer", "minimum": 0, "maximum": 10},
                },
                "required": ["step", "reasoning", "verdict", "severity"],
                "additionalProperties": False,
            },
        },
        "overall_confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["items", "overall_confidence"],
    "additionalProperties": False,
}

GEN_KEY_ORDER = ("Emit the JSON object with its keys in this order: "
                 "implementation, defensive_steps.")
JUDGE_KEY_ORDER = ("Emit the JSON object with its keys in this order: items, "
                   "overall_confidence. Within each item: step, reasoning, "
                   "verdict, severity.")

_lock = threading.Lock()


def log(m):
    with _lock:
        print(m, flush=True)


# --------------------------------------------------------------------------- #

def generate(cases, client, args):
    system = (HERE / "prompts" / "generator_defensive.md").read_text(encoding="utf-8")
    sha = V.prompt_sha(system)
    CAND_DIR.mkdir(parents=True, exist_ok=True)
    todo = [c for cid, c in sorted(cases.items())
            if args.force or not (CAND_DIR / f"{cid}.json").exists()]
    if args.limit:
        todo = todo[:args.limit]
    print(f"defensive generator prompt sha : {sha}")
    print(f"cases to generate : {len(todo)}\n")
    if not todo:
        return

    def worker(case):
        user = (f"language: {case['language']}\ndocstring:\n{case['docstring']}\n\n"
                f"{GEN_KEY_ORDER}")
        for field in FORBIDDEN_IN_GENERATOR:
            v = case.get(field)
            if isinstance(v, str) and v.strip() and v in user:
                raise AssertionError(f"leakage guard tripped on {field}")
        raw, finish = client.chat(system=system, user=user,
                                  temperature=args.temperature,
                                  max_tokens=args.gen_max_tokens,
                                  json_schema=GEN_SCHEMA)
        v = json.loads(V.THINK_RE.sub("", raw).strip())
        code = V.strip_code_fences(v["implementation"])
        if not code.strip():
            raise RuntimeError("empty implementation")
        return {"case_id": case["case_id"], "implementation": code,
                "defensive_steps": v["defensive_steps"],
                "n_steps": len(v["defensive_steps"]),
                "generator_prompt_sha": sha, "temperature": args.temperature,
                "seed": args.seed, "finish_reason": finish}

    done = 0
    steps_total = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(worker, c): c for c in todo}
        for fut in as_completed(futures):
            case = futures[fut]
            done += 1
            try:
                rec = fut.result()
            except Exception as exc:  # noqa: BLE001
                log(f"[{done}/{len(todo)}] {case['case_id']}: FAILED {exc}")
                continue
            (CAND_DIR / f"{rec['case_id']}.json").write_text(
                json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
            steps_total += rec["n_steps"]
            if done % 25 == 0 or done == len(todo):
                log(f"[{done}/{len(todo)}] generated, "
                    f"mean {steps_total/done:.1f} defensive steps/case")


# --------------------------------------------------------------------------- #

def judge_side(case, cand, reference, client, system, args, max_model_len):
    steps = cand["defensive_steps"]
    if not steps:
        # No claims to check: the detector abstains rather than guessing.
        return {"score": 0, "n_omits": 0, "n_performs": 0, "n_na": 0,
                "items": [], "no_claims": True, "confidence": "low"}
    checklist = "\n".join(
        f"{i+1}. {s['step']} — protects against: {s['protects_against']}"
        for i, s in enumerate(steps))
    user = (f"specification:\n{case['docstring']}\n\n"
            f"checklist of defensive steps:\n{checklist}\n\n"
            f"implementation:\n{reference}\n\n{JUDGE_KEY_ORDER}")
    if V.estimate_tokens(system, user) > max_model_len - 1500:
        raise ValueError("oversize_prompt")

    raw, finish = client.chat(system=system, user=user,
                              temperature=args.judge_temperature,
                              max_tokens=args.judge_max_tokens,
                              json_schema=JUDGE_SCHEMA)
    v = json.loads(V.THINK_RE.sub("", raw).strip())
    items = v["items"]
    omits = [i for i in items if i["verdict"] == "omits"]
    return {
        # Severity-weighted omission count: the detection score.
        "score": sum(i["severity"] for i in omits),
        "n_omits": len(omits),
        "n_performs": sum(1 for i in items if i["verdict"] == "performs"),
        "n_na": sum(1 for i in items if i["verdict"] == "not_applicable"),
        "max_severity": max((i["severity"] for i in omits), default=0),
        "items": items,
        "no_claims": False,
        "confidence": v["overall_confidence"],
        "finish_reason": finish,
    }


def judge(cases, client, args, max_model_len):
    system = (HERE / "prompts" / "judge_claim_check.md").read_text(encoding="utf-8")
    sha = V.prompt_sha(system)
    results_dir = HERE / "results" / args.run
    (results_dir / "logs").mkdir(parents=True, exist_ok=True)

    cands = {}
    for fp in sorted(CAND_DIR.glob("*.json")):
        d = json.loads(fp.read_text(encoding="utf-8"))
        cands[d["case_id"]] = d
    todo = [c for cid, c in sorted(cases.items())
            if cid in cands and (args.force or not (results_dir / f"{cid}.json").exists())]
    if args.limit:
        todo = todo[:args.limit]
    print(f"claim-check judge prompt sha : {sha}")
    print(f"cases to judge : {len(todo)}\n")
    if not todo:
        print("nothing to do")
        return

    ok = failed = done = correct = tied = 0
    t0 = time.time()

    def worker(case):
        cand = cands[case["case_id"]]
        last = None
        for attempt in (1, 2):
            try:
                jv = judge_side(case, cand, case["vulnerable_snippet"],
                                client, system, args, max_model_len)
                jf = judge_side(case, cand, case["fixed_snippet"],
                                client, system, args, max_model_len)
                return {
                    "case_id": case["case_id"], "sample_id": case["sample_id"],
                    "func_idx": case["func_idx"], "language": case["language"],
                    "repo": case["repo"], "cve_id": case["cve_id"],
                    "cve_summary": case["cve_summary"],
                    "changed_file": case["changed_file"],
                    "docstring": case["docstring"],
                    "heuristic_leakage_flag": case["heuristic_leakage_flag"],
                    "generated_code": cand["implementation"],
                    "defensive_steps": cand["defensive_steps"],
                    "n_claims": len(cand["defensive_steps"]),
                    "judge_vs_vulnerable": jv, "judge_vs_fixed": jf,
                    "correct_direction": jv["score"] > jf["score"],
                    "tied": jv["score"] == jf["score"],
                    "runtime": {"arm": "defensive_claims", "backend": "vllm",
                                "served_model": client.model, "seed": args.seed,
                                "generator_prompt_sha": cand["generator_prompt_sha"],
                                "judge_prompt_sha": sha},
                }
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
    print(f"ties : {tied}/{ok} ({tied/max(ok,1):.1%})")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=["generate", "judge"], required=True)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--judge-temperature", type=float, default=0.0)
    p.add_argument("--gen-max-tokens", type=int, default=3072)
    p.add_argument("--judge-max-tokens", type=int, default=2048)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--run", default="defensive_claims")
    p.add_argument("--cand-dir", default="candidates",
                   help="candidate directory; use a distinct one per seed so a "
                        "replication regenerates rather than reusing")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    global CAND_DIR
    CAND_DIR = HERE / args.cand_dir

    base_url = V.read_endpoint(args.base_url)
    try:
        served_model, max_model_len = V.server_info(base_url)
    except Exception as exc:
        print(f"cannot reach vLLM at {base_url} ({exc}).\n"
              f"Start it with: bash scripts/serve_qwen.sh")
        return 1
    client = V.Client(base_url, served_model, False, args.seed, args.timeout)
    cases = load_cases()
    if args.stage == "generate":
        generate(cases, client, args)
    else:
        judge(cases, client, args, max_model_len)
    return 0


if __name__ == "__main__":
    sys.exit(main())
