You are assisting a controlled, defensive software-engineering experiment that
measures how completely an implementation carries out the defensive steps its
specification implies. Nothing here produces an exploit.

You are given:

- a **specification** of a single function;
- several **independent implementations** of that specification, written
  separately by different authors, none of whom saw each other's work or the
  target;
- one further implementation, the **target**.

You know nothing about where the target came from. Do not reason about which
code looks more "real", more polished, more idiomatic, or more like production
code, and do not assume the target is wrong — most targets omit nothing that
matters.

## Why several independent implementations

Any one author makes idiosyncratic choices. A defensive step that **most of the
independent implementations perform** is not one author's habit — it is a
consequence of the specification and of ordinary practice for this kind of
function. That consensus is the only thing you should compare the target
against.

**Ignore any step that only one implementation performs.** Require at least a
majority of them before you treat a step as expected.

## The only question

Which defensive steps does a **majority of the independent implementations**
perform that the **target does not**?

A defensive step is a concrete action taken to stay safe on hostile or
unexpected input:

- a bounds, range, length or size check before an access or a copy
- a null / error-return / failure check before using a result
- an arithmetic guard against overflow, underflow, truncation or signedness
- an initialisation or clearing of memory before use, or after free
- a lifetime or ownership step: a free, an unlock, a refcount change, or nulling
  a pointer after release — including performing these in the correct order
- validation or sanitisation of untrusted input before use
- a permission, capability or authentication check before a privileged action
- an explicit bound on the work or memory an input can cause

## What is not a difference

- **Naming, types, helper functions, control-flow shape, error-handling style,
  formatting, comments, length.** Ignore all of it. The implementations were
  written without sight of each other, so they will look nothing alike.
- **The same effect achieved differently.** `if (n > max) return -EINVAL` and
  `n = MIN(n, max)` are the same step.
- **A step the target has no occasion to perform.** If the target never
  allocates, it cannot fail to free. Only count a step as missing when the
  target does the dangerous thing *and* omits the protection.
- **A step protecting a construct only the other implementations use.** If they
  invented a buffer the target does not have, its bounds check is irrelevant.

## Rating both directions

Rate **two** things, independently. Do not let either rating influence the other:
it is entirely possible for both to be sound, for both to be exposed, or for one
to be much worse than the other.

`consensus_exposure` is the control. It measures the reverse comparison: how much
hostile-input exposure the **independent implementations** are left with by
defensive steps that the **target** performs and most of them omit. Rate it on
the same 0-10 scale described below. This is expected to be non-zero fairly
often — independently written code frequently omits protections that a mature
implementation includes — and rating it honestly is what makes the target's own
rating interpretable.

`target_exposure` measures only how much hostile-input exposure the target is
left with by the consensus steps it omits:

- **0** — it omits nothing the majority performs, or only things that cannot
  matter here. **This is the expected answer for most targets.**
- **1-3** — a real omission, but hard to reach or low impact
- **4-6** — a plausible memory-safety, validation, lifetime or resource issue on
  a reachable path
- **7-10** — a clear, directly reachable omission with serious consequences

Do not inflate the rating because the target is unfamiliar or because it relies
on helpers you cannot see. Absence of context is not evidence of a defect. A
confident 0 is far more useful than a guess.

## Output

Respond with **only** a single JSON object, no surrounding prose. Reason first,
then commit:

```json
{
  "rationale": "<1-4 sentences naming the consensus steps the target omits, or stating that it omits none>",
  "consensus_steps_missing_from_target": [
    {
      "step": "<short name of the defensive step>",
      "performed_by_count": <how many of the independent implementations perform it>,
      "why_it_matters": "<one clause: the input that reaches it and what goes wrong>"
    }
  ],
  "steps_the_target_performs_that_most_others_omit": ["<short name of each>"],
  "target_exposure": <0-10 integer>,
  "consensus_exposure": <0-10 integer>,
  "confidence": "low" | "medium" | "high"
}
```
