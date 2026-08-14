You are assisting a controlled, defensive software-engineering experiment that
measures how completely an implementation carries out the defensive steps its
specification implies. Nothing here produces an exploit.

You are shown a specification and **two independent implementations of it**,
labelled 1 and 2. They were written separately, by different authors, without
sight of each other. Neither is more authoritative than the other, and you are
not told anything about where either came from. Do not reason about which looks
more "real", more polished, or more like production code.

Because they were written independently they will differ in many ways that do
not matter: different names, different types, different helper functions,
different control-flow shape, different error-handling style, different length,
different comments. **Ignore every one of those.**

## The only question

Compare the two implementations on **defensive steps** alone. A defensive step
is a concrete action the code takes to stay safe on hostile or unexpected input:

- a bounds, range, length or size check before an access or a copy
- a null / error-return / failure check before using a result
- an arithmetic guard against overflow, underflow, truncation or a signedness error
- an initialisation or clearing of memory before use, or after free
- a lifetime or ownership step: a free, an unlock, a refcount change, or setting
  a pointer to null after release — including doing these in the correct order
- a validation or sanitisation of untrusted input before it is used
- a permission, capability or authentication check before a privileged action
- an explicit bound on how much work or memory an input can cause

For each implementation, determine which defensive steps it performs. Then report
the steps performed by **one and not the other**.

## How to compare fairly

- If both implementations achieve the same defensive effect by different means,
  that is **not** a difference. A bounds check written as `if (n > max) return`
  and one written as `n = MIN(n, max)` are the same step.
- If one implementation cannot perform a step because it does not use the
  construct at all — it never allocates, so it never frees — that is **not** a
  missing defensive step. Only count a step as missing when the implementation
  does the dangerous thing *and* omits the protection.
- Do not count extra checks that guard against something the specification rules
  out, or that protect a construct only that implementation uses.
- Length is not safety. The longer implementation is not the safer one.

## Rating each side independently

Rate the two implementations **separately**. Do not pick a winner, and do not let
one rating influence the other — it is entirely possible for both to be badly
exposed, for both to be sound, or for one to be much worse than the other.

For each implementation in turn, ask: *of the defensive steps the other one
performs and this one does not, how much hostile-input exposure does that leave?*

- **0** — it omits nothing the other performs, or only things that cannot matter
  (unreachable, or protecting a construct it does not use)
- **1-3** — a real omission, but hard to reach or low impact
- **4-6** — a plausible memory-safety, validation, lifetime or resource issue on
  a reachable path
- **7-10** — a clear, directly reachable omission with serious consequences

Most independently written pairs will score 0 or a low number on both sides. Say
so when that is the case; a confident 0 is far more useful than a guess.

## Output

Respond with **only** a single JSON object, no surrounding prose. Reason first,
then commit:

```json
{
  "rationale": "<1-4 sentences naming the specific defensive steps that differ, or stating that both perform the same ones>",
  "defensive_steps_only_in_1": ["<short name of each step implementation 1 performs and 2 does not>"],
  "defensive_steps_only_in_2": ["<short name of each step implementation 2 performs and 1 does not>"],
  "exposure_of_1": <0-10 integer: how exposed implementation 1 is left by what IT omits>,
  "exposure_of_2": <0-10 integer: how exposed implementation 2 is left by what IT omits>,
  "confidence": "low" | "medium" | "high"
}
```
