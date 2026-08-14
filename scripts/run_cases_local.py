"""Local-model arm of the spec-reconstruction vulnerability-detection pipeline.

Mirrors `.claude/commands/run-case.md` step for step, but sends the Generator and
Judge calls to a local vLLM OpenAI-compatible endpoint (Qwen3-32B-AWQ) instead of
Claude Code subagents. The system prompts are read out of
`.claude/agents/vuln-{generator,judge}.md` by `scripts/agent_prompts.py`, so the
two arms share prompt text exactly; only the orchestration differs.

The result records use the same schema as the Claude arm, so
`scripts/compute_metrics.py <run>` consumes them unmodified.

Information isolation: the Generator request body is built from `language` and
`docstring` only. It is structurally impossible for it to see the snippets, the
CVE metadata, or the Judge's verdicts - each call is a fresh, stateless request.

Usage:
    python3 scripts/run_cases_local.py --run qwen_smoke --limit 3
    python3 scripts/run_cases_local.py --run qwen_full --concurrency 8
"""
import argparse
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_prompts import load_agent_prompt, prompt_sha  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "cases"
ENDPOINT_FILE = ROOT / ".vllm" / "endpoint"

# Fields the Generator must never see. Asserted per call, not just documented.
FORBIDDEN_IN_GENERATOR = [
    "vulnerable_snippet", "fixed_snippet", "cve_id", "cve_summary",
    "commit_message", "repo", "changed_file",
]

CATEGORIES = [
    "equivalent_implementation_difference",
    "functional_mismatch",
    "quality_bug",
    "security_vulnerability_concern",
    "degenerate_generation",
]

# Property order is deliberate: rationale/evidence BEFORE the verdict fields.
# HANDOFF.md section 6 records a case (C_652__0) where a schema that put the
# verdict first led the model to commit before reasoning, producing a
# self-contradictory output. Guided decoding emits keys in declaration order,
# so this ordering is what the model actually generates.
JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {
            "type": "string",
            "description": "1-4 sentences citing the specific behavioral difference, or stating there is none.",
        },
        "category": {"type": "string", "enum": CATEGORIES},
        "security_relevant": {"type": "boolean"},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "score": {"type": "integer", "minimum": 1, "maximum": 10},
    },
    "required": ["rationale", "category", "security_relevant", "confidence", "score"],
    "additionalProperties": False,
}

JUDGE_KEY_ORDER_NOTE = (
    "Emit the JSON object with its keys in this order: rationale, category, "
    "security_relevant, confidence, score."
)

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def read_endpoint(explicit):
    if explicit:
        return explicit.rstrip("/")
    if ENDPOINT_FILE.exists():
        return ENDPOINT_FILE.read_text(encoding="utf-8").strip().rstrip("/")
    return "http://127.0.0.1:8000/v1"


def http_post_json(url, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer local"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get_json(url, timeout=10):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer local"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def server_info(base_url):
    """Returns (model_id, max_model_len) from the live server."""
    info = http_get_json(f"{base_url}/models")
    entry = info["data"][0]
    return entry["id"], entry.get("max_model_len")


class Client:
    def __init__(self, base_url, model, thinking, seed, timeout):
        self.base_url = base_url
        self.model = model
        self.thinking = thinking
        self.seed = seed
        self.timeout = timeout

    def chat(self, system, user, temperature, max_tokens, json_schema=None):
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "top_p": 0.95 if temperature > 0 else 1.0,
            "max_tokens": max_tokens,
            "seed": self.seed,
            "chat_template_kwargs": {"enable_thinking": self.thinking},
        }
        if json_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "judge_verdict", "schema": json_schema, "strict": True},
            }
        resp = http_post_json(f"{self.base_url}/chat/completions", payload, self.timeout)
        choice = resp["choices"][0]
        text = choice["message"]["content"] or ""
        return text, choice.get("finish_reason")


# --------------------------------------------------------------------------- #
# prompt construction (must match .claude/commands/run-case.md exactly)
# --------------------------------------------------------------------------- #

def generator_user_message(case):
    msg = f"language: {case['language']}\ndocstring:\n{case['docstring']}"
    for field in FORBIDDEN_IN_GENERATOR:
        value = case.get(field)
        if isinstance(value, str) and value.strip() and value in msg:
            raise AssertionError(
                f"leakage guard tripped: '{field}' content appears in the generator prompt"
            )
    return msg


def judge_user_message(docstring, candidate, reference):
    return (
        f"specification:\n{docstring}\n\n"
        f"candidate_implementation:\n{candidate}\n\n"
        f"reference_implementation:\n{reference}\n\n"
        f"{JUDGE_KEY_ORDER_NOTE}"
    )


THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
FENCE_RE = re.compile(r"```[a-zA-Z0-9+#_-]*\n(.*?)```", re.DOTALL)


def strip_code_fences(text):
    text = THINK_RE.sub("", text).strip()
    blocks = FENCE_RE.findall(text)
    if blocks:
        # The agent is told to emit exactly one fenced block; if it emits more,
        # keep them all rather than silently dropping part of the implementation.
        return "\n\n".join(b.strip() for b in blocks).strip()
    return text.strip()


def estimate_tokens(*texts):
    """Deliberately conservative: source code tokenizes worse than prose, so
    chars/3.0 over-estimates rather than risking a mid-run context overflow."""
    return int(sum(len(t) for t in texts) / 3.0)


# --------------------------------------------------------------------------- #
# per-case pipeline
# --------------------------------------------------------------------------- #

def run_case(case, client, prompts, args, max_model_len):
    """Returns (status, payload). status in {'ok','skipped','failed'}."""
    cid = case["case_id"]
    budget = max_model_len - 2048

    est = estimate_tokens(
        prompts["judge"], case["docstring"],
        max(case["vulnerable_snippet"], case["fixed_snippet"], key=len),
    )
    if est > budget:
        return "skipped", {
            "case_id": cid, "reason": "oversize_prompt",
            "estimated_tokens": est, "budget": budget,
        }

    # 1. Generator - docstring only.
    gen_text, gen_finish = client.chat(
        system=prompts["generator"],
        user=generator_user_message(case),
        temperature=args.gen_temperature,
        max_tokens=args.gen_max_tokens,
    )
    generated_code = strip_code_fences(gen_text)
    if not generated_code:
        raise RuntimeError(f"generator returned empty output (finish_reason={gen_finish})")

    # 2 & 3. Two fully independent judge calls. Neither request references the
    # other; the server holds no state between them.
    def judge(reference):
        raw, finish = client.chat(
            system=prompts["judge"],
            user=judge_user_message(case["docstring"], generated_code, reference),
            temperature=args.judge_temperature,
            max_tokens=args.judge_max_tokens,
            json_schema=JUDGE_SCHEMA,
        )
        verdict = json.loads(THINK_RE.sub("", raw).strip())
        if verdict["category"] not in CATEGORIES:
            raise ValueError(f"bad category {verdict['category']!r}")
        if not 1 <= int(verdict["score"]) <= 10:
            raise ValueError(f"score out of range: {verdict['score']}")
        return {
            "score": int(verdict["score"]),
            "category": verdict["category"],
            "security_relevant": bool(verdict["security_relevant"]),
            "confidence": verdict["confidence"],
            "rationale": verdict["rationale"],
            "finish_reason": finish,
        }

    jv = judge(case["vulnerable_snippet"])
    jf = judge(case["fixed_snippet"])

    # 4. Metrics, identical definitions to run-case.md.
    pairwise = jf["score"] > jv["score"]
    paired = (
        jv["category"] == "security_vulnerability_concern"
        and jf["category"] != "security_vulnerability_concern"
    )

    record = {
        "case_id": cid,
        "sample_id": case["sample_id"],
        "func_idx": case["func_idx"],
        "language": case["language"],
        "repo": case["repo"],
        "cve_id": case["cve_id"],
        "cve_summary": case["cve_summary"],
        "changed_file": case["changed_file"],
        "docstring": case["docstring"],
        "heuristic_leakage_flag": case["heuristic_leakage_flag"],
        "generated_code": generated_code,
        "generator_model": args.model_label,
        "judge_model": args.model_label,
        "judge_vs_vulnerable": jv,
        "judge_vs_fixed": jf,
        "pairwise_ranking_correct": pairwise,
        "paired_flag_correct": paired,
        "human_review": {
            "reviewed": False, "human_category": None,
            "is_security_relevant_function": None,
            "docstring_leakage_suspected": None, "notes": "",
        },
        "runtime": {
            "arm": "local_vllm",
            "backend": "vllm",
            "base_url": client.base_url,
            "served_model": client.model,
            "gen_temperature": args.gen_temperature,
            "judge_temperature": args.judge_temperature,
            "seed": args.seed,
            "thinking": args.thinking,
            "max_model_len": max_model_len,
            "judge_key_order": "rationale_first",
            "prompt_sha": prompts["sha"],
        },
    }
    return "ok", record


def write_outputs(record, case, results_dir):
    cid = record["case_id"]
    (results_dir / f"{cid}.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    snip = results_dir / "snippets" / cid
    snip.mkdir(parents=True, exist_ok=True)
    (snip / "vulnerable.txt").write_text(case["vulnerable_snippet"], encoding="utf-8")
    (snip / "fixed.txt").write_text(case["fixed_snippet"], encoding="utf-8")
    (snip / "generated.txt").write_text(record["generated_code"], encoding="utf-8")


# --------------------------------------------------------------------------- #

def select_cases(args):
    all_cases = {}
    for fp in sorted(CASES_DIR.glob("*.json")):
        d = json.loads(fp.read_text(encoding="utf-8"))
        all_cases[d["case_id"]] = d

    if args.cases:
        wanted = [c["case_id"] for c in json.loads(Path(args.cases).read_text(encoding="utf-8"))]
        selected = [all_cases[c] for c in wanted if c in all_cases]
    else:
        selected = list(all_cases.values())

    # Same exclusion compute_metrics.py applies: only clean extractions count.
    selected = [c for c in selected if c.get("extraction_status") == "ok"]
    selected.sort(key=lambda c: c["case_id"])
    if args.limit:
        selected = selected[: args.limit]
    return selected


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", default="qwen_full", help="results/<run>/ subdirectory")
    p.add_argument("--cases", default=None, help="optional case-list JSON (e.g. pilot/pilot_cases.json)")
    p.add_argument("--limit", type=int, default=0, help="only the first N selected cases")
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--base-url", default=None)
    p.add_argument("--model-label", default="qwen3-32b-awq")
    p.add_argument("--thinking", action="store_true", help="enable Qwen3 thinking mode")
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--gen-temperature", type=float, default=0.2)
    p.add_argument("--judge-temperature", type=float, default=0.0)
    p.add_argument("--gen-max-tokens", type=int, default=2048)
    p.add_argument("--judge-max-tokens", type=int, default=1024)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--force", action="store_true", help="re-run cases that already have results")
    args = p.parse_args()

    base_url = read_endpoint(args.base_url)
    try:
        served_model, max_model_len = server_info(base_url)
    except Exception as exc:
        print(f"cannot reach vLLM at {base_url} ({exc}).\nStart it with: bash scripts/serve_qwen.sh")
        return 1
    if not max_model_len:
        max_model_len = 16384

    if args.thinking:
        # Thinking traces are long; without headroom the JSON gets truncated.
        args.judge_max_tokens = max(args.judge_max_tokens, 4096)
        args.gen_max_tokens = max(args.gen_max_tokens, 4096)

    prompts = {
        "generator": load_agent_prompt("vuln-generator"),
        "judge": load_agent_prompt("vuln-judge"),
    }
    prompts["sha"] = prompt_sha(prompts["generator"], prompts["judge"])

    results_dir = ROOT / "results" / args.run
    logs_dir = results_dir / "logs"
    results_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    cases = select_cases(args)
    todo = [c for c in cases if args.force or not (results_dir / f"{c['case_id']}.json").exists()]
    already = len(cases) - len(todo)

    print(f"endpoint      : {base_url}  (model {served_model}, max_model_len {max_model_len})")
    print(f"prompts sha   : {prompts['sha']}  (from .claude/agents/*.md)")
    print(f"thinking      : {args.thinking}")
    print(f"run           : {args.run} -> {results_dir}")
    print(f"cases         : {len(cases)} eligible, {already} already done, {len(todo)} to run")
    print(f"concurrency   : {args.concurrency}")
    print()
    if not todo:
        print("nothing to do.")
        return 0

    client = Client(base_url, served_model, args.thinking, args.seed, args.timeout)
    counts = {"ok": 0, "skipped": 0, "failed": 0}
    flagged = 0
    t0 = time.time()

    def worker(case):
        last_exc = None
        for attempt in (1, 2):
            try:
                return run_case(case, client, prompts, args, max_model_len)
            except Exception as exc:  # noqa: BLE001 - one retry, then record and move on
                last_exc = exc
                if attempt == 1:
                    time.sleep(2)
        return "failed", {"case_id": case["case_id"], "error": f"{type(last_exc).__name__}: {last_exc}"}

    done = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(worker, c): c for c in todo}
        for fut in as_completed(futures):
            case = futures[fut]
            status, payload = fut.result()
            done += 1
            counts[status] += 1
            prefix = f"[{done}/{len(todo)}]"
            if status == "ok":
                write_outputs(payload, case, results_dir)
                jv, jf = payload["judge_vs_vulnerable"], payload["judge_vs_fixed"]
                if payload["paired_flag_correct"]:
                    flagged += 1
                log(f"{prefix} {payload['case_id']}: "
                    f"vulnerable={jv['category']}/{jv['score']} "
                    f"fixed={jf['category']}/{jf['score']}"
                    f"{'  <-- PAIRED FLAG' if payload['paired_flag_correct'] else ''}")
            elif status == "skipped":
                with (logs_dir / "skipped.jsonl").open("a", encoding="utf-8") as f:
                    f.write(json.dumps(payload) + "\n")
                log(f"{prefix} {payload['case_id']}: skipped ({payload['reason']})")
            else:
                with (logs_dir / "failures.jsonl").open("a", encoding="utf-8") as f:
                    f.write(json.dumps(payload) + "\n")
                log(f"{prefix} {payload['case_id']}: FAILED {payload['error']}")

    elapsed = time.time() - t0
    print()
    print(f"done in {elapsed/60:.1f} min - ok={counts['ok']} "
          f"skipped={counts['skipped']} failed={counts['failed']}")
    if counts["ok"]:
        print(f"paired-flag hits this run: {flagged}/{counts['ok']} ({flagged/counts['ok']:.1%})")
    print(f"next: python3 scripts/compute_metrics.py {args.run}")
    return 0 if counts["failed"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
