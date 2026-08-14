You are assisting a controlled, defensive software-engineering experiment that
measures how completely an implementation carries out the defensive steps its
specification implies. Nothing here produces an exploit.

You are given:

- a **specification** of a single function;
- a **checklist** of defensive steps, each with the input or condition it
  protects against. The checklist was written by someone implementing the same
  specification independently, who never saw the code below;
- one **implementation** of that specification.

Your task is narrow and mechanical: **for each checklist item, decide whether
this implementation performs that step.** Nothing else about the implementation
is of interest. Do not rate its quality, style, structure or naming, and do not
comment on anything not on the checklist.

## The three verdicts

For each item, answer exactly one of:

- **`performs`** — the implementation does this, by any means. The mechanism does
  not have to match: `if (n > cap) return -EINVAL`, `n = MIN(n, cap)`, and a
  bounded copy primitive that cannot exceed `cap` are all the same step. A check
  performed by a helper the implementation calls counts as performed, provided
  the name makes the intent clear (`validate_len`, `check_bounds`, `IS_ERR`).

- **`not_applicable`** — the implementation never does the dangerous thing this
  step protects against, so there is nothing to guard. If it never allocates, it
  cannot fail to free. If it never copies into a fixed buffer, a copy bound is
  moot. If the checklist item refers to a parameter, buffer or capability this
  implementation does not have, it is not applicable.

  **Use this verdict freely.** The checklist was written without sight of this
  code, so many items will describe constructs this implementation does not use.
  Those are not defects.

- **`omits`** — the implementation **does** do the dangerous thing, and does
  **not** perform the protective step, on at least one reachable path. Only this
  verdict counts against the implementation, so reserve it for cases where you
  can name the path.

When you are unsure between `not_applicable` and `omits`, choose
`not_applicable`. A false `omits` is the costlier error here.

## Severity

For each item you mark `omits`, rate how much hostile-input exposure that
particular omission leaves:

- **1-3** — real but hard to reach, or low impact
- **4-6** — a plausible memory-safety, validation, lifetime or resource issue on
  a reachable path
- **7-10** — a clear, directly reachable omission with serious consequences

Rate `0` for items you did not mark `omits`.

## What not to do

- Do not assume a defect because the implementation relies on helpers, macros or
  types you cannot see. **Absence of context is not evidence of an omission.**
- Do not penalise unfamiliar or terse code. Do not reward length.
- Do not reason about where the implementation came from, or which of the two
  authors was more competent.

## Output

Respond with **only** a single JSON object, no surrounding prose. One entry per
checklist item, in the order given:

```json
{
  "items": [
    {
      "step": "<the checklist item, copied verbatim>",
      "reasoning": "<one clause: where the implementation does this, or the reachable path on which it does not, or why it does not apply>",
      "verdict": "performs" | "not_applicable" | "omits",
      "severity": <0-10 integer, 0 unless the verdict is omits>
    }
  ],
  "overall_confidence": "low" | "medium" | "high"
}
```
