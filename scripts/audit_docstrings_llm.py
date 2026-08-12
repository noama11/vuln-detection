"""
LLM-based audit of docstring leakage: does a case's auto-generated docstring
describe the VULNERABLE implementation's specific bug, or the FIXED
implementation's specific mitigation, rather than staying a neutral
black-box behavioral spec?

This is the LLM follow-up to the cheap heuristic screen in
audit_docstring_alignment.py (token-overlap against the vulnerable/fixed
diff) - that screen sized the problem (~23% vulnerable-echo-leaning, ~15%
fix-leak-leaning out of 392 "ok" cases) and produced the candidate list this
script verifies. See reports/docstring_alignment_audit.md and
pilot/leakage_audit_candidates.json.

Uses the Anthropic Message Batches API (50% cheaper, fits this
non-latency-sensitive workload) with structured outputs so every response is
guaranteed-valid JSON - no retry-on-parse-failure loop needed. The system
prompt (prompts/docstring_leakage_audit_system_prompt.txt) explicitly frames
this as defensive research over a public, already-patched CVE dataset.

Idempotent: skips case_ids that already have a result file in the output
directory, so an interrupted/resumed run just picks up the remainder - same
convention as scripts/run_batch.ps1.

Requires: pip install anthropic
Auth: reads ANTHROPIC_API_KEY from the environment (or an `ant auth login`
profile - see the Anthropic CLI docs); this script never asks for a key
directly.

Usage:
  # Preview what would be sent, no API calls, no cost
  python scripts/audit_docstrings_llm.py --scope candidates --dry-run

  # Run the audit over the 156 cases the heuristic screen flagged
  python scripts/audit_docstrings_llm.py --scope candidates

  # Run over every "ok" case with both snippets present (~392 cases)
  python scripts/audit_docstrings_llm.py --scope all

  # Run over an explicit list of case_ids
  python scripts/audit_docstrings_llm.py --scope file --input my_ids.json
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path=None):
    """Minimal .env loader (KEY=VALUE per line, '#' comments, optional quotes)
    so ANTHROPIC_API_KEY can live in a local, gitignored .env file. Never
    overwrites a value already set in the real environment."""
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
OUT_DIR = ROOT / "reports" / "docstring_audit"
DEFAULT_MODEL = "claude-opus-5"  # override with --model; this is a classification
                                  # task, so claude-sonnet-5 or claude-haiku-4-5 are
                                  # reasonable, cheaper alternatives - your call.

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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", choices=["candidates", "all", "file"], default="candidates")
    ap.add_argument("--input", help="path to a JSON file of case_ids (required for --scope file)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--poll-interval", type=float, default=30.0, help="seconds between batch status checks")
    ap.add_argument("--dry-run", action="store_true", help="build requests and print a summary; no API calls")
    args = ap.parse_args()

    load_dotenv()  # picks up ANTHROPIC_API_KEY from a local .env if not already in the environment

    if args.scope == "file" and not args.input:
        ap.error("--scope file requires --input")

    case_ids = load_case_ids(args.scope, args.input)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    already_done = {p.stem for p in OUT_DIR.glob("*.json")}
    pending = [cid for cid in case_ids if cid not in already_done]

    print(f"Scope '{args.scope}': {len(case_ids)} case(s) total, "
          f"{len(already_done)} already audited, {len(pending)} to submit.")

    if not pending:
        print("Nothing to do.")
        return

    if args.dry_run:
        sample = pending[0]
        case = json.loads((CASES_DIR / f"{sample}.json").read_text(encoding="utf-8"))
        print(f"\n--- sample request (case {sample}) ---")
        print(build_user_message(case)[:2000])
        print("...\n(pass without --dry-run to actually submit)")
        return

    import anthropic  # imported here so --dry-run works without the package installed
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    from anthropic.types.messages.batch_create_params import Request

    client = anthropic.Anthropic()
    system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")

    requests = []
    for cid in pending:
        case = json.loads((CASES_DIR / f"{cid}.json").read_text(encoding="utf-8"))
        requests.append(Request(
            custom_id=cid,
            params=MessageCreateParamsNonStreaming(
                model=args.model,
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": build_user_message(case)}],
                output_config={"format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
            ),
        ))

    print(f"Submitting a batch of {len(requests)} request(s) on model {args.model}...")
    batch = client.messages.batches.create(requests=requests)
    print(f"Batch ID: {batch.id} (status: {batch.processing_status})")

    while True:
        batch = client.messages.batches.retrieve(batch.id)
        if batch.processing_status == "ended":
            break
        counts = batch.request_counts
        print(f"  ...{batch.processing_status} "
              f"(processing={counts.processing}, succeeded={counts.succeeded}, errored={counts.errored})")
        time.sleep(args.poll_interval)

    print("Batch complete. Writing results...")
    counts_by_verdict = {}
    errors = []
    for result in client.messages.batches.results(batch.id):
        cid = result.custom_id
        if result.result.type == "succeeded":
            msg = result.result.message
            text = next((b.text for b in msg.content if b.type == "text"), None)
            try:
                parsed = json.loads(text)
            except (TypeError, ValueError) as e:
                errors.append((cid, f"unparseable response: {e}"))
                continue
            (OUT_DIR / f"{cid}.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
            counts_by_verdict[parsed["verdict"]] = counts_by_verdict.get(parsed["verdict"], 0) + 1
        else:
            errors.append((cid, f"{result.result.type}: {getattr(result.result, 'error', '')}"))

    print(f"\nWrote {len(pending) - len(errors)} result(s) to {OUT_DIR}")
    print("Verdict counts:", counts_by_verdict)
    if errors:
        print(f"\n{len(errors)} case(s) failed or errored:")
        for cid, msg in errors:
            print(f"  {cid}: {msg}")


if __name__ == "__main__":
    main()
