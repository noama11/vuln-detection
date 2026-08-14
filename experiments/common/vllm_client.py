"""Local vLLM client shared by the experiment arms.

Adapted from `scripts/run_cases_local.py` rather than imported from it, on
purpose: that script is the published arm and must stay byte-reproducible, so
arms that need a different rubric, a different candidate, or a different call
shape vendor the transport instead of editing it. The schema, the
rationale-before-verdict key ordering, and the fence-stripping behaviour are
carried over unchanged so verdicts remain comparable across arms.

Prompts are loaded through `scripts/agent_prompts.py` (read-only) by default, so
an arm that does not intend to change the rubric produces the same
`prompt_sha` (1de29ae28c7d) as the published run. An arm that *does* change it
passes an explicit path under its own `prompts/` directory.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ENDPOINT_FILE = ROOT / ".vllm" / "endpoint"

sys.path.insert(0, str(ROOT / "scripts"))
from agent_prompts import load_agent_prompt, prompt_sha  # noqa: E402,F401

CATEGORIES = [
    "equivalent_implementation_difference",
    "functional_mismatch",
    "quality_bug",
    "security_vulnerability_concern",
    "degenerate_generation",
]

# Rationale first: guided decoding emits keys in declaration order, and a
# verdict-first schema once produced self-contradictory output (HANDOFF.md s6).
JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string", "description":
                      "1-4 sentences citing the specific behavioral difference, "
                      "or stating there is none."},
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

THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
FENCE_RE = re.compile(r"```[a-zA-Z0-9+#_-]*\n(.*?)```", re.DOTALL)


def read_endpoint(explicit=None):
    if explicit:
        return explicit.rstrip("/")
    if ENDPOINT_FILE.exists():
        return ENDPOINT_FILE.read_text(encoding="utf-8").strip().rstrip("/")
    return "http://127.0.0.1:8000/v1"


def _post(url, payload, timeout):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer local"},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def server_info(base_url, timeout=10):
    req = urllib.request.Request(f"{base_url}/models",
                                 headers={"Authorization": "Bearer local"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        entry = json.loads(resp.read().decode("utf-8"))["data"][0]
    return entry["id"], entry.get("max_model_len") or 16384


class Client:
    def __init__(self, base_url, model, thinking=False, seed=1234, timeout=900):
        self.base_url = base_url
        self.model = model
        self.thinking = thinking
        self.seed = seed
        self.timeout = timeout

    def chat(self, system, user, temperature, max_tokens, json_schema=None, seed=None):
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": temperature,
            "top_p": 0.95 if temperature > 0 else 1.0,
            "max_tokens": max_tokens,
            "seed": self.seed if seed is None else seed,
            "chat_template_kwargs": {"enable_thinking": self.thinking},
        }
        if json_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "verdict", "schema": json_schema, "strict": True},
            }
        choice = _post(f"{self.base_url}/chat/completions", payload, self.timeout)["choices"][0]
        return (choice["message"]["content"] or ""), choice.get("finish_reason")


def strip_code_fences(text):
    text = THINK_RE.sub("", text).strip()
    blocks = FENCE_RE.findall(text)
    if blocks:
        return "\n\n".join(b.strip() for b in blocks).strip()
    return text.strip()


def judge_user_message(docstring, candidate, reference):
    """Byte-identical to run_cases_local.py:169 so verdicts stay comparable."""
    return (f"specification:\n{docstring}\n\n"
            f"candidate_implementation:\n{candidate}\n\n"
            f"reference_implementation:\n{reference}\n\n"
            f"{JUDGE_KEY_ORDER_NOTE}")


def parse_verdict(raw, finish=None):
    v = json.loads(THINK_RE.sub("", raw).strip())
    if v["category"] not in CATEGORIES:
        raise ValueError(f"bad category {v['category']!r}")
    if not 1 <= int(v["score"]) <= 10:
        raise ValueError(f"score out of range: {v['score']}")
    return {"score": int(v["score"]), "category": v["category"],
            "security_relevant": bool(v["security_relevant"]),
            "confidence": v["confidence"], "rationale": v["rationale"],
            "finish_reason": finish}


def estimate_tokens(*texts):
    """Conservative: source tokenizes worse than prose, so chars/3 over-estimates
    rather than risking a mid-run context overflow."""
    return int(sum(len(t) for t in texts) / 3.0)


def load_prompts(generator=None, judge=None):
    """Explicit paths override the published agent files. Returns the same
    prompt_sha as run_cases_local.py when both are left as defaults."""
    g = (Path(generator).read_text(encoding="utf-8") if generator
         else load_agent_prompt("vuln-generator"))
    j = (Path(judge).read_text(encoding="utf-8") if judge
         else load_agent_prompt("vuln-judge"))
    return {"generator": g, "judge": j, "sha": prompt_sha(g, j)}
