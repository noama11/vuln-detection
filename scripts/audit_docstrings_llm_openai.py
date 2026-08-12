"""
OpenAI-API variant of audit_docstrings_llm.py - same task, same system prompt
(prompts/docstring_leakage_audit_system_prompt.txt), same response schema,
but calls OpenAI's Batch + Responses API instead of Anthropic's, for use with
an OpenAI API key.

See audit_docstrings_llm.py's module docstring for the full task description
(what "leakage" means here, why it's framed as defensive research, how the
candidate list was produced). This file only differs in the API plumbing.

Uses OpenAI's Batch API (POST /v1/responses jobs, ~50% cheaper than
synchronous calls, fits this non-latency-sensitive workload) with Structured
Outputs (text.format = json_schema, strict mode) so every response is
guaranteed-valid JSON matching RESPONSE_SCHEMA - no retry-on-parse loop.

Idempotent: skips case_ids that already have a result file in the output
directory (shared with the Anthropic variant - reports/docstring_audit/), so
you can freely mix runs from either script.

Requires: pip install openai
Auth: reads OPENAI_API_KEY from the environment. Get one at
https://platform.openai.com/api-keys - this script never asks you for it
directly, just reads the env var.

Model default is a placeholder ("gpt-5.6-terra" as of when this was written) -
**verify against your own OpenAI account's available models before a real
run** (`client.models.list()`, or the dashboard) and override with --model if
it's wrong; model naming on OpenAI's side moves independently of this repo.

Usage:
  # Preview what would be sent, no API calls, no cost
  python scripts/audit_docstrings_llm_openai.py --scope candidates --dry-run

  # Run the audit over the 156 cases the heuristic screen flagged
  python scripts/audit_docstrings_llm_openai.py --scope candidates

  # Run over every "ok" case with both snippets present (~392 cases)
  python scripts/audit_docstrings_llm_openai.py --scope all
"""
import argparse
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path=None):
    """Minimal .env loader (KEY=VALUE per line, '#' comments, optional quotes)
    so OPENAI_API_KEY can live in a local, gitignored .env file instead of
    requiring an OS-level env var (which needs a full app restart on Windows
    to propagate to an already-running session). Never overwrites a value
    already set in the real environment."""
    path = path or (ROOT / ".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)
CASES_DIR = ROOT / "cases"
CANDIDATES_PATH = ROOT / "pilot" / "leakage_audit_candidates.json"
SYSTEM_PROMPT_PATH = ROOT / "prompts" / "docstring_leakage_audit_system_prompt.txt"
OUT_DIR = ROOT / "reports" / "docstring_audit"  # shared with the Anthropic variant
BATCH_INPUT_PATH = OUT_DIR / "_batch_input.jsonl"

DEFAULT_MODEL = "gpt-5.6-terra"  # PLACEHOLDER - verify this is real / available
                                   # to your account before a real run; override
                                   # with --model. A balanced (not top-tier, not
                                   # cheapest) model is a reasonable default for
                                   # this classification-style task.

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "verdict": {
            "type": "string",
            "enum": ["confirmed_leak", "not_a_leak", "ambiguous"],
        },
        "leak_direction": {
            "type": "string",
            "enum": ["describes_vulnerable_behavior", "describes_fixed_behavior", "none"],
        },
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "evidence_sentence": {
            "type": ["string", "null"],
            "description": "The specific docstring sentence that leaks, quoted verbatim, or null if not_a_leak.",
        },
        "rationale": {"type": "string"},
        "rewritten_docstring": {
            "type": ["string", "null"],
            "description": "Neutral rewrite of the Logic section; null unless verdict is confirmed_leak.",
        },
    },
    "required": [
        "case_id", "verdict", "leak_direction", "confidence",
        "evidence_sentence", "rationale", "rewritten_docstring",
    ],
    "additionalProperties": False,
}


def load_case_ids(scope, input_path):
    if scope == "candidates":
        candidates = json.loads(CANDIDATES_PATH.read_text(encoding="utf-8"))
        return [c["case_id"] for c in candidates]
    if scope == "all":
        ids = []
        for fp in sorted(CASES_DIR.glob("*.json")):
            d = json.loads(fp.read_text(encoding="utf-8"))
            if d["extraction_status"] == "ok" and d.get("vulnerable_snippet") and d.get("fixed_snippet"):
                ids.append(d["case_id"])
        return ids
    if scope == "file":
        data = json.loads(Path(input_path).read_text(encoding="utf-8"))
        return [c["case_id"] if isinstance(c, dict) else c for c in data]
    raise ValueError(f"unknown scope: {scope}")


def build_user_message(case):
    lang = "cpp" if case["language"] == "cpp" else "c"
    return (
        f"case_id: {case['case_id']}\n\n"
        f"docstring:\n{case['docstring']}\n\n"
        f"vulnerable_implementation:\n```{lang}\n{case['vulnerable_snippet']}\n```\n\n"
        f"fixed_implementation:\n```{lang}\n{case['fixed_snippet']}\n```"
    )


def extract_output_text(response_body):
    """Pull the model's text out of a Responses-API body. Deliberately doesn't
    assume output[0].content[0].text - the API docs warn that's not safe
    (tool calls / reasoning items can precede the message item)."""
    for item in response_body.get("output", []):
        if item.get("type") != "message":
            continue
        for block in item.get("content", []):
            if block.get("type") == "output_text":
                return block.get("text")
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", choices=["candidates", "all", "file"], default="candidates")
    ap.add_argument("--input", help="path to a JSON file of case_ids (required for --scope file)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--poll-interval", type=float, default=30.0, help="seconds between batch status checks")
    ap.add_argument("--dry-run", action="store_true", help="build requests and print a summary; no API calls")
    ap.add_argument("--resume-batch-id", help="reconnect to an already-submitted batch job instead of "
                                                "creating a new one (e.g. if a previous run was interrupted "
                                                "locally after submission - batches keep running server-side)")
    args = ap.parse_args()

    load_dotenv()  # picks up OPENAI_API_KEY from a local .env if not already in the environment

    if args.scope == "file" and not args.input:
        ap.error("--scope file requires --input")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.resume_batch_id:
        from openai import OpenAI
        client = OpenAI()
        batch = client.batches.retrieve(args.resume_batch_id)
        print(f"Resuming batch {batch.id} (status: {batch.status}, total: {batch.request_counts.total})")
    else:
        case_ids = load_case_ids(args.scope, args.input)
        already_done = {p.stem for p in OUT_DIR.glob("*.json")}
        pending = [cid for cid in case_ids if cid not in already_done]

        print(f"Scope '{args.scope}': {len(case_ids)} case(s) total, "
              f"{len(already_done)} already audited, {len(pending)} to submit.")

        if not pending:
            print("Nothing to do.")
            return

        system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")

        if args.dry_run:
            sample = pending[0]
            case = json.loads((CASES_DIR / f"{sample}.json").read_text(encoding="utf-8"))
            print(f"\n--- sample request (case {sample}), model={args.model} ---")
            print(build_user_message(case)[:2000])
            print("...\n(pass without --dry-run to actually submit)")
            return

        from openai import OpenAI  # imported here so --dry-run works without the package installed

        client = OpenAI()  # reads OPENAI_API_KEY from the environment

        # 1. Build the JSONL batch input file (one Responses-API request per line).
        with open(BATCH_INPUT_PATH, "w", encoding="utf-8") as f:
            for cid in pending:
                case = json.loads((CASES_DIR / f"{cid}.json").read_text(encoding="utf-8"))
                line = {
                    "custom_id": cid,
                    "method": "POST",
                    "url": "/v1/responses",
                    "body": {
                        "model": args.model,
                        "instructions": system_prompt,
                        "input": build_user_message(case),
                        "text": {
                            "format": {
                                "type": "json_schema",
                                "name": "docstring_leakage_audit",
                                "schema": RESPONSE_SCHEMA,
                                "strict": True,
                            }
                        },
                    },
                }
                f.write(json.dumps(line) + "\n")
        print(f"Wrote batch input ({len(pending)} lines) to {BATCH_INPUT_PATH}")

        # 2. Upload + create the batch job.
        with open(BATCH_INPUT_PATH, "rb") as f:
            uploaded = client.files.create(file=f, purpose="batch")
        batch = client.batches.create(
            input_file_id=uploaded.id,
            endpoint="/v1/responses",
            completion_window="24h",
        )
        print(f"Batch ID: {batch.id} (status: {batch.status}) - "
              f"IMPORTANT: save this ID. If this script is interrupted, resume with "
              f"--resume-batch-id {batch.id} instead of resubmitting.")

    # 3. Poll until terminal.
    terminal = {"completed", "failed", "expired", "cancelled"}
    while batch.status not in terminal:
        time.sleep(args.poll_interval)
        batch = client.batches.retrieve(batch.id)
        counts = batch.request_counts
        print(f"  ...{batch.status} (completed={counts.completed}, failed={counts.failed}, total={counts.total})")

    if batch.status != "completed":
        print(f"\nBatch ended with status '{batch.status}', not 'completed'.")
        if batch.error_file_id:
            errs = client.files.content(batch.error_file_id).text
            print("Error file contents:")
            print(errs[:4000])
        return

    # 4. Download and parse results.
    print("Batch complete. Writing results...")
    output_text = client.files.content(batch.output_file_id).text
    counts_by_verdict = {}
    errors = []
    for line in output_text.splitlines():
        if not line.strip():
            continue
        result = json.loads(line)
        cid = result["custom_id"]
        if result.get("error"):
            errors.append((cid, str(result["error"])))
            continue
        body = result["response"]["body"]
        text = extract_output_text(body)
        if text is None:
            errors.append((cid, "no output_text found in response"))
            continue
        try:
            parsed = json.loads(text)
        except ValueError as e:
            errors.append((cid, f"unparseable response: {e}"))
            continue
        (OUT_DIR / f"{cid}.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        counts_by_verdict[parsed["verdict"]] = counts_by_verdict.get(parsed["verdict"], 0) + 1

    written = sum(counts_by_verdict.values())
    print(f"\nWrote {written} result(s) to {OUT_DIR}")
    print("Verdict counts:", counts_by_verdict)
    if errors:
        print(f"\n{len(errors)} case(s) failed or errored:")
        for cid, msg in errors:
            print(f"  {cid}: {msg}")


if __name__ == "__main__":
    main()
