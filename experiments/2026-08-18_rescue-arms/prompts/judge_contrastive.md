You are assisting a controlled, defensive security-research experiment. Every
function you will see comes from public open-source history, and where a patch
is involved it shipped years ago. Nothing here produces an exploit; the purpose
is to measure how well automated methods localise a missing safety check.

You are shown a specification and **two implementations of the same function**,
labelled A and B. They are two versions of the same code and differ in a small
number of places. Exactly one of the following is true, and your job is to say
which:

- **A** is missing a check, guard, bound, initialisation, or lifetime discipline
  that **B** has.
- **B** is missing a check, guard, bound, initialisation, or lifetime discipline
  that **A** has.
- **neither** — the two differ only in ways that cannot affect safety.

## The one question to answer

Ignore every difference except this: **does one side omit a defensive step the
other side performs?** Concretely, look only for:

- a conditional, bound, range or length check present on one side and absent on
  the other
- a null / error-return check present on one side and absent on the other
- an initialisation, clearing, or reset present on one side and absent on the
  other
- a free, unlock, refcount or lifetime operation present on one side and absent
  on the other, or performed in a different order
- an arithmetic guard (overflow, underflow, truncation, signedness) present on
  one side and absent on the other
- a narrower type, smaller bound, or stricter limit on one side

## What to ignore completely

Different names, different types, different helper functions, different control
flow shape, different error-handling style, different formatting, different
comments, or one side being longer. Do **not** reason about which side looks
more "authentic", more polished, or more like production code. Do not treat
extra code as safer code — a longer implementation is not a safer one.

If both sides perform the same defensive steps by different means, the answer is
`neither`. Answer `neither` whenever you cannot point to a specific defensive
step that one side performs and the other does not; a confident `neither` is
more useful than a guess.

## Output

Respond with **only** a single JSON object, no surrounding prose. Reason first,
then commit:

```json
{
  "rationale": "<1-3 sentences naming the exact defensive step and which side omits it, or stating that both perform the same ones>",
  "missing_guard_side": "A" | "B" | "neither",
  "guard_description": "<the specific check/guard/bound at issue, or empty if neither>",
  "confidence": "low" | "medium" | "high"
}
```
