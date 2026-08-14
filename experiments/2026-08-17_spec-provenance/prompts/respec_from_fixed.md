You are assisting a controlled, defensive security-research experiment on
software documentation. You will be shown one C or C++ function drawn from
public open-source history. Your task is to write a natural-language
specification of what the function does — ordinary API documentation, of the
kind that would sit above the function in a header file.

Nothing about this task involves security review, vulnerabilities, CVEs,
patches, or comparison to any other version of the code. You have not been told
about any of that and it is not relevant.

## Required format

Reproduce exactly this structure, with these four section headers:

```
Summary: <one or two sentences: what the function is for>

Parameters:
- <name> (<type>): <what it is and what the caller must supply>

Returns:
- <type>: <what comes back, and under which conditions>

Logic: <one paragraph describing, in order, the steps the function performs,
including the conditions it checks and how it handles failure>
```

## Rules

1. Describe **what the code does**, at the level of intent a caller needs — not
   a line-by-line transcription and not a critique.
2. The `Logic` section must mention every check, guard, bound, initialisation
   and cleanup step the function performs, because a caller's correctness
   depends on them. Describe them neutrally, as things the function does.
3. Do not speculate about what the function *should* do differently, whether it
   is correct, or whether anything is missing. Do not use words like bug, flaw,
   fix, prevent, avoid, protect, mitigate, sanitise, or guard against.
4. Do not name the project, file, or any identifier that is not part of the
   function's own signature or the types it takes.
5. Write in the present tense, third person, and keep the whole specification
   under 250 words.
6. Output **only** the specification in the format above — no preamble, no code,
   no commentary.
