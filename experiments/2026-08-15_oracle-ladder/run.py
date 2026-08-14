"""WP2 - the oracle ladder: locate where the detection signal is lost.

Holds the judge, the rubric and `prompt_sha` fixed at the published values and
varies ONLY what plays the role of `candidate_implementation`:

    L0  candidate = the fixed snippet, verbatim
        -> can this judge flag the CVE when handed the true pair?
    L1  candidate = the fixed snippet, locals renamed + comments stripped
        -> how much of L0 was string alignment rather than reading behaviour?
    L2  candidate = the fixed snippet of a DIFFERENT, random case
        -> negative control: what does this rubric flag on unrelated code?
    L3  candidate = the generated implementation  (= the published results/qwen_full/)

This is the substitute for a frontier-model arm, which the local-only budget
rules out - and a better argument than one anyway. If L0 detects well, judge
capability is demonstrably not the binding constraint, so no stronger judge can
rescue L3 and the loss is provably in the reconstruction step. If L0 also fails,
the claim becomes a rubric/dataset claim. Either outcome is reportable; the
current write-up can state neither.

Writes only inside this directory. cases/, results/, scripts/ are read-only.

Usage:
    python3 experiments/2026-08-15_oracle-ladder/run.py --rungs L0 L1 L2
    python3 experiments/2026-08-15_oracle-ladder/run.py --rungs L0 --limit 3
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
sys.path.insert(0, str(HERE))

import vllm_client as V  # noqa: E402
from data import load_cases  # noqa: E402
from transform import perturb  # noqa: E402

RUNGS = ("L0", "L1", "L2")
_lock = threading.Lock()


def log(msg):
    with _lock:
        print(msg, flush=True)


def build_candidates(cases, rung, seed=1234):
    """case_id -> (candidate_code, provenance dict)."""
    ids = sorted(cases)
    if rung == "L0":
        return {c: (cases[c]["fixed_snippet"], {"source": "fixed_snippet_verbatim"})
                for c in ids}
    if rung == "L1":
        out = {}
        for c in ids:
            code, st = perturb(cases[c]["fixed_snippet"])
            out[c] = (code, {"source": "fixed_snippet_perturbed",
                             "identifiers_renamed": st["identifiers_renamed"]})
        return out
    if rung == "L2":
        # A derangement: every case gets another case's fixed snippet, never its
        # own. Seeded, so the control is reproducible.
        rng = random.Random(seed)
        shuffled = ids[:]
        for _ in range(100):
            rng.shuffle(shuffled)
            if all(a != b for a, b in zip(ids, shuffled)):
                break
        else:  # pragma: no cover - astronomically unlikely
            shuffled = ids[1:] + ids[:1]
        return {a: (cases[b]["fixed_snippet"], {"source": "fixed_snippet_of_other_case",
                                                "donor_case_id": b})
                for a, b in zip(ids, shuffled)}
    raise ValueError(rung)


def run_case(case, candidate, prov, client, prompts, args, max_model_len, rung):
    cid = case["case_id"]
    budget = max_model_len - 2048
    est = V.estimate_tokens(prompts["judge"], case["docstring"], candidate,
                            max(case["vulnerable_snippet"], case["fixed_snippet"], key=len))
    if est > budget:
        return "skipped", {"case_id": cid, "reason": "oversize_prompt",
                           "estimated_tokens": est, "budget": budget}

    def judge(reference):
        raw, finish = client.chat(
            system=prompts["judge"],
            user=V.judge_user_message(case["docstring"], candidate, reference),
            temperature=args.judge_temperature,
            max_tokens=args.judge_max_tokens,
            json_schema=V.JUDGE_SCHEMA)
        return V.parse_verdict(raw, finish)

    jv = judge(case["vulnerable_snippet"])
    jf = judge(case["fixed_snippet"])

    return "ok", {
        "case_id": cid, "sample_id": case["sample_id"], "func_idx": case["func_idx"],
        "language": case["language"], "repo": case["repo"], "cve_id": case["cve_id"],
        "cve_summary": case["cve_summary"], "changed_file": case["changed_file"],
        "docstring": case["docstring"],
        "heuristic_leakage_flag": case["heuristic_leakage_flag"],
        # Same key the published schema uses, so experiments/common/metrics.py and
        # scripts/compute_metrics.py both consume these records unmodified.
        "generated_code": candidate,
        "candidate_provenance": prov,
        "generator_model": f"oracle_{rung}",
        "judge_model": args.model_label,
        "judge_vs_vulnerable": jv,
        "judge_vs_fixed": jf,
        "pairwise_ranking_correct": jf["score"] > jv["score"],
        "paired_flag_correct": (jv["category"] == "security_vulnerability_concern"
                                and jf["category"] != "security_vulnerability_concern"),
        "runtime": {"arm": "oracle_ladder", "rung": rung, "backend": "vllm",
                    "served_model": client.model,
                    "judge_temperature": args.judge_temperature,
                    "seed": args.seed, "thinking": args.thinking,
                    "max_model_len": max_model_len,
                    "judge_key_order": "rationale_first",
                    "prompt_sha": prompts["sha"]},
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rungs", nargs="+", default=list(RUNGS), choices=RUNGS)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--model-label", default="qwen3-32b-awq")
    p.add_argument("--thinking", action="store_true")
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--judge-temperature", type=float, default=0.0)
    p.add_argument("--judge-max-tokens", type=int, default=1024)
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
        args.judge_max_tokens = max(args.judge_max_tokens, 4096)

    prompts = V.load_prompts()  # published rubric, unmodified
    cases = load_cases()
    client = V.Client(base_url, served_model, args.thinking, args.seed, args.timeout)

    print(f"endpoint    : {base_url}  (model {served_model}, max_model_len {max_model_len})")
    print(f"prompt sha  : {prompts['sha']}  (expect 1de29ae28c7d - rubric unchanged)")
    print(f"cases       : {len(cases)} eligible")
    print(f"rungs       : {' '.join(args.rungs)}\n")

    for rung in args.rungs:
        results_dir = HERE / "results" / rung
        (results_dir / "logs").mkdir(parents=True, exist_ok=True)
        candidates = build_candidates(cases, rung, args.seed)
        todo = [c for cid, c in sorted(cases.items())
                if args.force or not (results_dir / f"{cid}.json").exists()]
        if args.limit:
            todo = todo[:args.limit]
        if not todo:
            print(f"{rung}: nothing to do")
            continue

        print(f"=== {rung}: {len(todo)} cases ===")
        counts = {"ok": 0, "skipped": 0, "failed": 0}
        flagged = 0
        t0 = time.time()

        def worker(case, rung=rung, candidates=candidates):
            cand, prov = candidates[case["case_id"]]
            last = None
            for attempt in (1, 2):
                try:
                    return run_case(case, cand, prov, client, prompts, args,
                                    max_model_len, rung)
                except Exception as exc:  # noqa: BLE001
                    last = exc
                    if attempt == 1:
                        time.sleep(2)
            return "failed", {"case_id": case["case_id"],
                              "error": f"{type(last).__name__}: {last}"}

        done = 0
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(worker, c): c for c in todo}
            for fut in as_completed(futures):
                status, payload = fut.result()
                done += 1
                counts[status] += 1
                if status == "ok":
                    (results_dir / f"{payload['case_id']}.json").write_text(
                        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                    jv, jf = payload["judge_vs_vulnerable"], payload["judge_vs_fixed"]
                    flagged += payload["paired_flag_correct"]
                    log(f"[{done}/{len(todo)}] {rung} {payload['case_id']}: "
                        f"vuln={jv['category']}/{jv['score']} "
                        f"fixed={jf['category']}/{jf['score']}"
                        f"{'  <-- PAIRED FLAG' if payload['paired_flag_correct'] else ''}")
                else:
                    fn = "skipped.jsonl" if status == "skipped" else "failures.jsonl"
                    with (results_dir / "logs" / fn).open("a", encoding="utf-8") as f:
                        f.write(json.dumps(payload) + "\n")
                    log(f"[{done}/{len(todo)}] {rung} {payload['case_id']}: {status}")

        print(f"{rung} done in {(time.time()-t0)/60:.1f} min - "
              f"ok={counts['ok']} skipped={counts['skipped']} failed={counts['failed']}"
              f"  paired-flag {flagged}/{counts['ok'] or 1} "
              f"({flagged/(counts['ok'] or 1):.1%})\n")

    print("next: python3 experiments/2026-08-15_oracle-ladder/report.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
