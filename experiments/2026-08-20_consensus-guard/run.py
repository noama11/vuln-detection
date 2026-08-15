"""Consensus spec-reconstruction: the strongest defensible form of the method.

THE PREMISE IS INTACT. The Generator still sees only {language, docstring} - the
published `.claude/agents/vuln-generator.md`, unmodified, so `prompt_sha` on the
generator half is unchanged. The Judge still sees one reference at a time and is
never told which it is. No supervised labels. The vulnerable/fixed pairing is the
evaluation harness; the detector never sees it.

WHAT CHANGES, AND WHY IT FOLLOWS FROM THE EVIDENCE

The published method draws ONE sample from the generator. That is the
maximum-noise configuration of its own idea. `PILOT_INSIGHTS.md` Finding 2 named
the consequence - the candidate differs from both references in ways unrelated
to the CVE - and the single-candidate guard-contrast arm
(`experiments/2026-08-19_guard-contrast/`) measured the mechanism: the judge
rates the reference's exposure at 0 in ~72% of cases, because one from-spec
reconstruction is usually LESS defensive than real code, not more.

The fix is to stop treating one sample as the specification's meaning. Draw K
independent samples and keep only what a MAJORITY of them agree on. A defensive
step that 3 of 5 independent implementations perform is a consequence of the
specification; a step only one performs is that sample's idiosyncrasy. Consensus
is precisely the filter the baseline gap has needed since the pilot.

All K candidates go into a single judge call, so the judge itself applies the
majority rule with the evidence in front of it, and cost stays at 2 judge calls
per case rather than 2K.

Usage:
    python3 experiments/2026-08-20_consensus-guard/run.py --stage generate --k 5
    python3 experiments/2026-08-20_consensus-guard/run.py --stage judge
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

CAND_DIR = HERE / "candidates"

FORBIDDEN_IN_GENERATOR = ["vulnerable_snippet", "fixed_snippet", "cve_id",
                          "cve_summary", "commit_message", "repo", "changed_file"]

SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string"},
        "consensus_steps_missing_from_target": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"type": "string"},
                    "performed_by_count": {"type": "integer", "minimum": 0, "maximum": 16},
                    "why_it_matters": {"type": "string"},
                },
                "required": ["step", "performed_by_count", "why_it_matters"],
                "additionalProperties": False,
            },
        },
        "steps_the_target_performs_that_most_others_omit": {
            "type": "array", "items": {"type": "string"}},
        "target_exposure": {"type": "integer", "minimum": 0, "maximum": 10},
        # The control arm of the comparison. Lets the report compute net exposure
        # (target - consensus), which removes the per-call baseline offset a weak
        # reconstruction introduces into BOTH judge calls equally.
        "consensus_exposure": {"type": "integer", "minimum": 0, "maximum": 10},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["rationale", "consensus_steps_missing_from_target",
                 "steps_the_target_performs_that_most_others_omit",
                 "target_exposure", "consensus_exposure", "confidence"],
    "additionalProperties": False,
}

KEY_ORDER = ("Emit the JSON object with its keys in this order: rationale, "
             "consensus_steps_missing_from_target, "
             "steps_the_target_performs_that_most_others_omit, "
             "target_exposure, consensus_exposure, confidence.")

_lock = threading.Lock()


def log(m):
    with _lock:
        print(m, flush=True)


# --------------------------------------------------------------------------- #
# stage 1: K independent reconstructions, spec only
# --------------------------------------------------------------------------- #

def generate(cases, client, args):
    prompts = V.load_prompts()          # published generator, unmodified
    CAND_DIR.mkdir(parents=True, exist_ok=True)
    todo = [c for cid, c in sorted(cases.items())
            if args.force or not (CAND_DIR / f"{cid}.json").exists()]
    print(f"generator prompt sha (combined): {prompts['sha']}  (expect 1de29ae28c7d)")
    print(f"K = {args.k} samples/case at temperature {args.temperature}")
    print(f"cases to generate: {len(todo)}\n")
    if not todo:
        return

    def worker(case):
        user = f"language: {case['language']}\ndocstring:\n{case['docstring']}"
        for field in FORBIDDEN_IN_GENERATOR:
            v = case.get(field)
            if isinstance(v, str) and v.strip() and v in user:
                raise AssertionError(f"leakage guard tripped on {field}")
        out = []
        for i in range(args.k):
            # A distinct seed per sample: without this vLLM returns K copies of
            # the same greedy-ish completion and the consensus is vacuous.
            raw, finish = client.chat(system=prompts["generator"], user=user,
                                      temperature=args.temperature,
                                      max_tokens=args.gen_max_tokens,
                                      seed=args.seed + 1000 * i)
            code = V.strip_code_fences(raw)
            if code:
                out.append({"sample": i, "code": code, "finish_reason": finish})
        if not out:
            raise RuntimeError("generator returned no usable samples")
        return {"case_id": case["case_id"], "k": len(out),
                "temperature": args.temperature, "seed": args.seed,
                "generator_prompt_sha": prompts["sha"], "samples": out}

    done = 0
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
            if done % 25 == 0 or done == len(todo):
                log(f"[{done}/{len(todo)}] generated")


# --------------------------------------------------------------------------- #
# stage 2: one judge call per reference, all K candidates in view
# --------------------------------------------------------------------------- #

def judge_side(case, samples, reference, client, system, args, max_model_len):
    """Drops the least-informative samples if the prompt would overflow, rather
    than skipping the case: a smaller consensus is still a consensus."""
    used = list(samples)
    while used:
        blocks = "\n\n".join(
            f"independent_implementation_{i+1}:\n{s['code']}" for i, s in enumerate(used))
        user = (f"specification:\n{case['docstring']}\n\n{blocks}\n\n"
                f"target_implementation:\n{reference}\n\n{KEY_ORDER}")
        if V.estimate_tokens(system, user) <= max_model_len - 1200:
            break
        used = used[:-1]
    if len(used) < 2:
        raise ValueError("oversize_prompt: fewer than 2 samples fit")

    raw, finish = client.chat(system=system, user=user,
                              temperature=args.judge_temperature,
                              max_tokens=args.judge_max_tokens, json_schema=SCHEMA)
    v = json.loads(V.THINK_RE.sub("", raw).strip())
    steps = v["consensus_steps_missing_from_target"]
    majority = [s for s in steps if s["performed_by_count"] * 2 > len(used)]
    return {
        "target_exposure": v["target_exposure"],
        "consensus_exposure": v["consensus_exposure"],
        # Pre-registered secondary rule: differencing removes the per-call
        # baseline that a weak reconstruction adds to both judge calls alike.
        "net_exposure": v["target_exposure"] - v["consensus_exposure"],
        "n_steps_reported": len(steps),
        "n_steps_majority": len(majority),
        "n_steps_target_only": len(v["steps_the_target_performs_that_most_others_omit"]),
        "steps": steps,
        "k_used": len(used),
        "confidence": v["confidence"],
        "rationale": v["rationale"],
        "finish_reason": finish,
    }


def judge(cases, client, args, max_model_len):
    system = (HERE / "prompts" / "judge_consensus.md").read_text(encoding="utf-8")
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

    print(f"judge prompt sha : {sha}  (consensus rubric)")
    print(f"cases with candidates: {len(cands)}\ncases to judge  : {len(todo)}\n")
    if not todo:
        print("nothing to do")
        return

    ok = failed = done = correct = tied = 0
    t0 = time.time()

    def worker(case):
        samples = cands[case["case_id"]]["samples"]
        last = None
        for attempt in (1, 2):
            try:
                jv = judge_side(case, samples, case["vulnerable_snippet"],
                                client, system, args, max_model_len)
                jf = judge_side(case, samples, case["fixed_snippet"],
                                client, system, args, max_model_len)
                return {
                    "case_id": case["case_id"], "sample_id": case["sample_id"],
                    "func_idx": case["func_idx"], "language": case["language"],
                    "repo": case["repo"], "cve_id": case["cve_id"],
                    "cve_summary": case["cve_summary"],
                    "changed_file": case["changed_file"],
                    "docstring": case["docstring"],
                    "heuristic_leakage_flag": case["heuristic_leakage_flag"],
                    "k": len(samples),
                    "judge_vs_vulnerable": jv, "judge_vs_fixed": jf,
                    "correct_direction": jv["target_exposure"] > jf["target_exposure"],
                    "tied": jv["target_exposure"] == jf["target_exposure"],
                    "runtime": {"arm": "consensus_guard", "backend": "vllm",
                                "served_model": client.model,
                                "judge_temperature": args.judge_temperature,
                                "seed": args.seed,
                                "judge_prompt_sha": sha,
                                "generator_prompt_sha":
                                    cands[case["case_id"]]["generator_prompt_sha"]},
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
    print(f"ties                           : {tied}/{ok} ({tied/max(ok,1):.1%})")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=["generate", "judge"], required=True)
    p.add_argument("--k", type=int, default=5)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--temperature", type=float, default=0.8,
                   help="generator sampling temperature; needs to be high enough "
                        "that the K samples actually differ")
    p.add_argument("--judge-temperature", type=float, default=0.0)
    p.add_argument("--gen-max-tokens", type=int, default=2048)
    p.add_argument("--judge-max-tokens", type=int, default=1536)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--run", default="consensus_k5")
    p.add_argument("--force", action="store_true")
    # Corpus override. Defaults reproduce the published arm byte for byte. A
    # re-run on a different corpus MUST pass a distinct --cand-dir, or it will
    # reuse candidates generated from the old snippets.
    p.add_argument("--cases-dir", default=None,
                   help="corpus directory (default: cases/)")
    p.add_argument("--cand-dir", default="candidates",
                   help="candidate directory, relative to this arm")
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
    cases = load_cases(args.cases_dir)
    if args.stage == "generate":
        if args.limit:
            cases = dict(sorted(cases.items())[:args.limit])
        generate(cases, client, args)
    else:
        judge(cases, client, args, max_model_len)
    return 0


if __name__ == "__main__":
    sys.exit(main())
