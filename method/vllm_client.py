"""Transport for the local vLLM OpenAI-compatible server.

`Client.chat` is the single point through which both stages talk to the model.
Grammar-constrained JSON decoding is used for every judge call, so a response
either parses or the request fails - there is no free-text fallback that could
silently change what a verdict means.

Prompts are loaded through `scripts/agent_prompts.py`, which reads the system
prompts out of `.claude/agents/` and digests them. Leaving both defaults gives
the generator `prompt_sha` recorded in every result file (1de29ae28c7d); a run
that changes the rubric passes an explicit path and stamps a different digest.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENDPOINT_FILE = ROOT / ".vllm" / "endpoint"

sys.path.insert(0, str(ROOT / "scripts"))
from agent_prompts import load_agent_prompt, prompt_sha  # noqa: E402,F401

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


def estimate_tokens(*texts):
    """Conservative: source tokenizes worse than prose, so chars/3 over-estimates
    rather than risking a mid-run context overflow."""
    return int(sum(len(t) for t in texts) / 3.0)


def load_prompts(generator=None, judge=None):
    """Explicit paths override the `.claude/agents/` definitions. Both prompts
    feed the digest even though the consensus judge uses its own rubric from
    `method/prompts/`, so the generator half of `prompt_sha` stays comparable
    with every run recorded to date."""
    g = (Path(generator).read_text(encoding="utf-8") if generator
         else load_agent_prompt("vuln-generator"))
    j = (Path(judge).read_text(encoding="utf-8") if judge
         else load_agent_prompt("vuln-judge"))
    return {"generator": g, "judge": j, "sha": prompt_sha(g, j)}
