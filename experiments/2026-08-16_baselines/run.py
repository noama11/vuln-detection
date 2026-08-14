"""WP3 - baselines, scored with the same paired metric as the method.

A negative result about a method is only worth reading if the alternatives are
measured on the same cases with the same yardstick. Three baselines:

  B1  direct prompting  - same local model, no candidate, no reconstruction:
                          "is this function vulnerable?", asked independently of
                          each side. This is what a practitioner would actually
                          do, and the paper currently has no answer to "why not
                          just ask?".
  B1s direct + spec     - same, but the docstring is supplied too, isolating
                          whether the spec helps at all outside reconstruction.
  B2  flawfinder        - a conventional static analyser over both sides.
  B3  trivial           - always-flag / never-flag / coin-flip / longer-is-worse,
                          computed in report.py (no inference needed).

Every arm emits the published result schema, so experiments/common/metrics.py
scores all of them and the method identically. `vulnerable=true` maps onto
`security_vulnerability_concern` so Paired Flag Accuracy means the same thing
everywhere; `safety_score` maps onto `score` with the same polarity as the judge
(higher = cleaner), so 2AFC and ROC-AUC stay comparable.

Usage:
    python3 experiments/2026-08-16_baselines/run.py --arms B1 B1s
    python3 experiments/2026-08-16_baselines/run.py --arms B2          # no GPU needed
"""
import argparse
import json
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "experiments" / "common"))

import vllm_client as V  # noqa: E402
from data import load_cases  # noqa: E402

SECURITY = "security_vulnerability_concern"
CLEAN = "equivalent_implementation_difference"

DETECTOR_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string"},
        "vulnerable": {"type": "boolean"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "safety_score": {"type": "integer", "minimum": 1, "maximum": 10},
    },
    "required": ["rationale", "vulnerable", "confidence", "safety_score"],
    "additionalProperties": False,
}

KEY_ORDER_NOTE = ("Emit the JSON object with its keys in this order: rationale, "
                  "vulnerable, confidence, safety_score.")

_lock = threading.Lock()


def log(m):
    with _lock:
        print(m, flush=True)


def as_verdict(v):
    """Detector output -> the published judge-verdict shape, so one metrics
    implementation scores every arm."""
    return {"score": int(v["safety_score"]),
            "category": SECURITY if v["vulnerable"] else CLEAN,
            "security_relevant": bool(v["vulnerable"]),
            "confidence": v["confidence"],
            "rationale": v["rationale"]}


def record(case, jv, jf, arm, extra=None):
    return {
        "case_id": case["case_id"], "sample_id": case["sample_id"],
        "func_idx": case["func_idx"], "language": case["language"],
        "repo": case["repo"], "cve_id": case["cve_id"],
        "cve_summary": case["cve_summary"], "changed_file": case["changed_file"],
        "docstring": case["docstring"],
        "heuristic_leakage_flag": case["heuristic_leakage_flag"],
        "generated_code": "",  # no reconstruction step in a baseline
        "generator_model": None,
        "judge_model": arm,
        "judge_vs_vulnerable": jv,
        "judge_vs_fixed": jf,
        "pairwise_ranking_correct": jf["score"] > jv["score"],
        "paired_flag_correct": (jv["category"] == SECURITY and jf["category"] != SECURITY),
        "runtime": dict({"arm": arm}, **(extra or {})),
    }


# --------------------------------------------------------------------------- #
# B1 / B1s - direct prompting
# --------------------------------------------------------------------------- #

def run_direct(case, client, system, args, max_model_len, with_spec):
    cid = case["case_id"]
    longest = max(case["vulnerable_snippet"], case["fixed_snippet"], key=len)
    if V.estimate_tokens(system, case["docstring"], longest) > max_model_len - 2048:
        return "skipped", {"case_id": cid, "reason": "oversize_prompt"}

    def ask(snippet):
        parts = []
        if with_spec:
            parts.append(f"specification:\n{case['docstring']}")
        parts.append(f"function ({case['language']}):\n{snippet}")
        parts.append(KEY_ORDER_NOTE)
        raw, finish = client.chat(system=system, user="\n\n".join(parts),
                                  temperature=args.temperature,
                                  max_tokens=args.max_tokens,
                                  json_schema=DETECTOR_SCHEMA)
        v = json.loads(V.THINK_RE.sub("", raw).strip())
        out = as_verdict(v)
        out["finish_reason"] = finish
        return out

    # Two independent calls, exactly as the method makes two independent judge
    # calls - so the comparison is like-for-like.
    return "ok", record(case, ask(case["vulnerable_snippet"]), ask(case["fixed_snippet"]),
                        "direct_spec" if with_spec else "direct",
                        {"backend": "vllm", "served_model": client.model,
                         "temperature": args.temperature, "seed": args.seed,
                         "with_spec": with_spec, "thinking": args.thinking,
                         "prompt_sha": args.prompt_sha})


# --------------------------------------------------------------------------- #
# B2 - flawfinder
# --------------------------------------------------------------------------- #

def flawfinder_scan(snippet, language, tmpdir):
    """Highest CWE risk level flawfinder reports for this snippet, 0 if none.

    flawfinder needs a file with a C/C++ extension; --dataonly --quiet keeps the
    output to one line per hit.
    """
    suffix = ".c" if language == "c" else ".cpp"
    fp = Path(tmpdir) / f"snippet{suffix}"
    fp.write_text(snippet, encoding="utf-8")
    proc = subprocess.run(
        ["flawfinder", "--dataonly", "--quiet", "--singleline", "--minlevel=0", str(fp)],
        capture_output=True, text=True, timeout=120)
    hits, top = 0, 0
    for line in proc.stdout.splitlines():
        # format: file:line:col:  [level] (rule) name: description
        if "[" in line and "]" in line:
            try:
                lvl = int(line.split("[", 1)[1].split("]", 1)[0].strip())
            except (ValueError, IndexError):
                continue
            hits += 1
            top = max(top, lvl)
    return top, hits


def run_flawfinder(case, threshold):
    with tempfile.TemporaryDirectory() as td:
        def side(snippet):
            top, hits = flawfinder_scan(snippet, case["language"], td)
            flagged = top >= threshold
            return {"score": max(1, 10 - top),  # same polarity as the judge score
                    "category": SECURITY if flagged else CLEAN,
                    "security_relevant": flagged,
                    "confidence": "high" if top >= 4 else "medium" if top >= 2 else "low",
                    "rationale": f"flawfinder: {hits} hit(s), highest risk level {top}"}
        return "ok", record(case, side(case["vulnerable_snippet"]),
                            side(case["fixed_snippet"]), "flawfinder",
                            {"tool": "flawfinder", "version": flawfinder_version(),
                             "threshold": threshold})


def flawfinder_version():
    try:
        p = subprocess.run(["flawfinder", "--version"], capture_output=True,
                           text=True, timeout=30)
        return p.stdout.strip() or p.stderr.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


# --------------------------------------------------------------------------- #

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--arms", nargs="+", default=["B1", "B1s", "B2"],
                   choices=["B1", "B1s", "B2"])
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--thinking", action="store_true")
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tokens", type=int, default=1024)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--flawfinder-threshold", type=int, default=2,
                   help="minimum flawfinder risk level counted as a flag (0-5)")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    cases = load_cases()
    system = (HERE / "prompts" / "direct_detector.md").read_text(encoding="utf-8")
    args.prompt_sha = V.prompt_sha(system)

    client = None
    max_model_len = 16384
    if {"B1", "B1s"} & set(args.arms):
        base_url = V.read_endpoint(args.base_url)
        try:
            served_model, max_model_len = V.server_info(base_url)
        except Exception as exc:
            print(f"cannot reach vLLM at {base_url} ({exc}).\n"
                  f"Start it with: bash scripts/serve_qwen.sh")
            return 1
        if args.thinking:
            args.max_tokens = max(args.max_tokens, 4096)
        client = V.Client(base_url, served_model, args.thinking, args.seed, args.timeout)
        print(f"endpoint   : {base_url} (model {served_model})")
    print(f"detector prompt sha : {args.prompt_sha}")
    print(f"cases      : {len(cases)}\narms       : {' '.join(args.arms)}\n")

    for arm in args.arms:
        name = {"B1": "direct", "B1s": "direct_spec", "B2": "flawfinder"}[arm]
        results_dir = HERE / "results" / name
        (results_dir / "logs").mkdir(parents=True, exist_ok=True)
        todo = [c for cid, c in sorted(cases.items())
                if args.force or not (results_dir / f"{cid}.json").exists()]
        if args.limit:
            todo = todo[:args.limit]
        if not todo:
            print(f"{arm} ({name}): nothing to do")
            continue
        print(f"=== {arm} ({name}): {len(todo)} cases ===")

        def worker(case, arm=arm):
            last = None
            for attempt in (1, 2):
                try:
                    if arm == "B2":
                        return run_flawfinder(case, args.flawfinder_threshold)
                    return run_direct(case, client, system, args, max_model_len,
                                      with_spec=(arm == "B1s"))
                except Exception as exc:  # noqa: BLE001
                    last = exc
                    if attempt == 1:
                        time.sleep(2)
            return "failed", {"case_id": case["case_id"],
                              "error": f"{type(last).__name__}: {last}"}

        counts = {"ok": 0, "skipped": 0, "failed": 0}
        flagged = done = 0
        t0 = time.time()
        workers = args.concurrency if arm != "B2" else min(8, args.concurrency)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(worker, c): c for c in todo}
            for fut in as_completed(futures):
                status, payload = fut.result()
                done += 1
                counts[status] += 1
                if status == "ok":
                    (results_dir / f"{payload['case_id']}.json").write_text(
                        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                    flagged += payload["paired_flag_correct"]
                    if done % 25 == 0 or done == len(todo):
                        log(f"[{done}/{len(todo)}] {name}: paired-flag {flagged}")
                else:
                    fn = "skipped.jsonl" if status == "skipped" else "failures.jsonl"
                    with (results_dir / "logs" / fn).open("a", encoding="utf-8") as f:
                        f.write(json.dumps(payload) + "\n")
                    log(f"[{done}/{len(todo)}] {name} {payload['case_id']}: {status}")
        print(f"{name} done in {(time.time()-t0)/60:.1f} min - ok={counts['ok']} "
              f"skipped={counts['skipped']} failed={counts['failed']}  "
              f"paired-flag {flagged}/{counts['ok'] or 1} "
              f"({flagged/(counts['ok'] or 1):.1%})\n")

    print("next: python3 experiments/2026-08-16_baselines/report.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
