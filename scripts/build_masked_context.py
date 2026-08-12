"""
Builds "masked file context" for the context-arm of the wider-context ablation.

For each case, reads the REAL vulnerable-side source file out of D.zip (never
the fixed side - that would leak the fix) and produces a version with the
target function's body replaced by a masked placeholder, so the Generator can
see real includes/macros/type defs/sibling functions from the same file
without ever seeing the function it's asked to (re)implement.

To keep prompt size bounded for large files (some are 1000-3500+ lines), the
context is not the whole file. It is:
  - a header block: the first HEADER_LINES lines of the file (where
    #include/#define/typedef/struct declarations conventionally live), and
  - a local window of WINDOW_LINES lines before/after the masked function,
  with an omission marker if there's a gap between the header block and the
  window, and a hard character cap as a final safety net.

Read-only w.r.t. D.zip and cases/. Writes one .txt per case to
pilot/masked_context/, plus a manifest.json with size/truncation stats.

Usage: python scripts/build_masked_context.py <case_id> [<case_id> ...]
       python scripts/build_masked_context.py --all-ok
"""
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZIP_PATH = ROOT / "D.zip"
CASES_DIR = ROOT / "cases"
OUT_DIR = ROOT / "pilot" / "masked_context"

HEADER_LINES = 60
WINDOW_LINES = 40
HARD_CHAR_CAP = 9000

MASK_MARKER = (
    "/* [MASKED: this function's body has been removed. Implement it from "
    "the specification you were given separately - do not guess its "
    "original contents from anything in this file.] */"
)
OMIT_MARKER = "/* ... ({n} lines omitted) ... */"


def split_lines_strict(text):
    lines = text.split("\n")
    return [l + "\n" for l in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def build_masked_context(file_text, start, end):
    lines = split_lines_strict(file_text)
    n = len(lines)
    start = max(1, min(start, n))
    end = max(start, min(end, n))

    header_end = min(HEADER_LINES, start - 1)  # 0-indexed exclusive
    window_start = max(header_end, start - 1 - WINDOW_LINES)
    window_end = min(n, end + WINDOW_LINES)

    parts = []
    truncated = False

    parts.extend(lines[0:header_end])
    if window_start > header_end:
        parts.append(OMIT_MARKER.format(n=window_start - header_end) + "\n")
    elif header_end > 0 and window_start < header_end:
        window_start = header_end  # no overlap/duplication

    parts.extend(lines[window_start:start - 1])
    parts.append(MASK_MARKER + "\n")
    parts.extend(lines[end:window_end])

    if window_end < n:
        parts.append(OMIT_MARKER.format(n=n - window_end) + "\n")

    text = "".join(parts)
    if len(text) > HARD_CHAR_CAP:
        text = text[:HARD_CHAR_CAP] + "\n" + OMIT_MARKER.format(n="rest, char-cap reached")
        truncated = True

    return text, truncated, n


def main():
    args = sys.argv[1:]
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args == ["--all-ok"]:
        case_ids = sorted(
            json.loads(fp.read_text(encoding="utf-8"))["case_id"]
            for fp in CASES_DIR.glob("*.json")
            if json.loads(fp.read_text(encoding="utf-8"))["extraction_status"] == "ok"
        )
    else:
        case_ids = args

    if not case_ids:
        print("No case ids given. Usage: build_masked_context.py <case_id> ... | --all-ok")
        return

    zf = zipfile.ZipFile(ZIP_PATH)
    manifest = {}

    for cid in case_ids:
        case = json.loads((CASES_DIR / f"{cid}.json").read_text(encoding="utf-8"))
        ext = "cpp" if case["language"] == "cpp" else "c"
        path = f"{case['sample_id']}/vulnerable.{ext}"
        file_text = zf.read(path).decode("utf-8", errors="replace")
        s, e = case["vulnerable_line_range"]

        masked, truncated, n_lines = build_masked_context(file_text, s, e)
        out_path = OUT_DIR / f"{cid}.txt"
        out_path.write_text(masked, encoding="utf-8")

        manifest[cid] = {
            "source_path": path,
            "original_file_lines": n_lines,
            "masked_context_chars": len(masked),
            "truncated": truncated,
        }
        print(f"{cid}: {n_lines} lines -> {len(masked)} chars context (truncated={truncated})")

    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nWrote {len(case_ids)} masked-context file(s) to {OUT_DIR}")


if __name__ == "__main__":
    main()
