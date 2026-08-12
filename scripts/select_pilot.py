"""
Selects a stratified pilot set from cases/*.json per the plan:
  - floor of ~5 C++ cases (language-diversity, catches C++-specific bugs early)
  - 6-8 cases with heuristic_leakage_flag=True (deliberately over-samples the
    docstring-leakage risk found during dataset inspection, so the pilot
    measures it rather than leaving it to chance)
  - remainder spread across repos and function-size buckets (small/medium/large
    by vulnerable_snippet line count), avoiding repeated repos where possible
  - target total: 27 (within the planned 24-30 range)

Only draws from cases with extraction_status == "ok" (both snippets present).
Writes pilot/pilot_cases.json: list of {case_id, reason}.
"""
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "cases"
OUT_PATH = ROOT / "pilot" / "pilot_cases.json"

TARGET_TOTAL = 27
CPP_FLOOR = 5
LEAKAGE_TARGET = 7

random.seed(42)


def line_count(snippet):
    return snippet.count("\n") + 1


def size_bucket(snippet):
    n = line_count(snippet)
    if n < 20:
        return "small"
    if n <= 60:
        return "medium"
    return "large"


def main():
    all_cases = []
    for fp in sorted(CASES_DIR.glob("*.json")):
        d = json.loads(fp.read_text(encoding="utf-8"))
        if d["extraction_status"] == "ok":
            all_cases.append(d)

    selected = {}  # case_id -> reason

    cpp_pool = [c for c in all_cases if c["language"] == "cpp"]
    random.shuffle(cpp_pool)
    for c in cpp_pool[:CPP_FLOOR]:
        selected[c["case_id"]] = "language diversity floor (c++)"

    leakage_pool = [c for c in all_cases if c["heuristic_leakage_flag"] and c["case_id"] not in selected]
    random.shuffle(leakage_pool)
    for c in leakage_pool[:LEAKAGE_TARGET]:
        selected[c["case_id"]] = "heuristic leakage-risk docstring (deliberate oversample)"

    remaining_pool = [c for c in all_cases if c["case_id"] not in selected]
    random.shuffle(remaining_pool)

    used_repos = {c["repo"] for c in all_cases if c["case_id"] in selected}
    bucket_counts = {"small": 0, "medium": 0, "large": 0}
    for c in all_cases:
        if c["case_id"] in selected:
            bucket_counts[size_bucket(c["vulnerable_snippet"])] += 1

    slots_left = TARGET_TOTAL - len(selected)

    # first pass: prefer new repos, spread across size buckets
    remaining_pool.sort(key=lambda c: bucket_counts[size_bucket(c["vulnerable_snippet"])])
    i = 0
    while slots_left > 0 and i < len(remaining_pool):
        c = remaining_pool[i]
        i += 1
        if c["case_id"] in selected:
            continue
        bucket = size_bucket(c["vulnerable_snippet"])
        if c["repo"] in used_repos and slots_left > (TARGET_TOTAL - len(selected)) // 2:
            continue  # mildly prefer repo diversity while slots are plentiful
        selected[c["case_id"]] = f"repo/size-bucket diversity fill ({bucket}, repo={c['repo']})"
        used_repos.add(c["repo"])
        bucket_counts[bucket] += 1
        slots_left -= 1

    # second pass: fill any remaining slots regardless of repo repeats
    if slots_left > 0:
        for c in remaining_pool:
            if slots_left <= 0:
                break
            if c["case_id"] in selected:
                continue
            bucket = size_bucket(c["vulnerable_snippet"])
            selected[c["case_id"]] = f"repo/size-bucket diversity fill, repeat-repo allowed ({bucket}, repo={c['repo']})"
            bucket_counts[bucket] += 1
            slots_left -= 1

    pilot_list = [{"case_id": cid, "reason": reason} for cid, reason in selected.items()]

    OUT_PATH.parent.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(pilot_list, indent=2), encoding="utf-8")

    langs = {c["language"] for c in all_cases if c["case_id"] in selected}
    print(f"Selected {len(pilot_list)} pilot cases")
    print("Language counts:", {l: sum(1 for c in all_cases if c['case_id'] in selected and c['language'] == l) for l in langs})
    print("Leakage-flagged in pilot:", sum(1 for c in all_cases if c["case_id"] in selected and c["heuristic_leakage_flag"]))
    print("Size buckets:", bucket_counts)
    print("Unique repos:", len({c["repo"] for c in all_cases if c["case_id"] in selected}))


if __name__ == "__main__":
    main()
