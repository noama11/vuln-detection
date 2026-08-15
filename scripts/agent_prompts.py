"""Single source of truth for the generator system prompt.

The prompt is read straight out of its `.claude/agents/` definition file rather
than copied into Python, so there is exactly one copy of the text and no way
for a second one to drift from it.

`prompt_sha` digests what was actually used and is stamped into every result
file. That is what lets a later reader tell whether two runs shared prompt text
without having to trust a changelog: if the digest differs, the rubric differed.
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = ROOT / ".claude" / "agents"


def load_agent_prompt(name):
    """Return the body of .claude/agents/<name>.md with frontmatter removed."""
    text = (AGENTS_DIR / f"{name}.md").read_text(encoding="utf-8")
    if text.startswith("---"):
        # Split off the frontmatter block delimited by the first two '---' lines.
        parts = text.split("---", 2)
        if len(parts) == 3:
            text = parts[2]
    return text.strip()


def prompt_sha(*texts):
    """Short digest over the prompts actually used, recorded in each result file
    so a later reader can tell whether two runs shared prompt text."""
    h = hashlib.sha256()
    for t in texts:
        h.update(t.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()[:12]


if __name__ == "__main__":
    g = load_agent_prompt("vuln-generator")
    j = load_agent_prompt("vuln-judge")
    print(f"generator prompt: {len(g)} chars")
    print(f"judge prompt:     {len(j)} chars")
    print(f"combined sha:     {prompt_sha(g, j)}")
