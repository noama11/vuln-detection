"""Surface perturbation for ladder rung L1.

L0 hands the judge the fixed snippet verbatim as the candidate, which makes the
fixed-side comparison textually identical and therefore trivially "equivalent".
L1 removes that shortcut: same code, same semantics, different surface. The gap
L0 - L1 measures how much of the oracle's apparent detection ability came from
string alignment rather than from reading behaviour.

The judge's own rubric says naming is not a behavioural difference:

    "Different variable names, different type/struct names, different helper
     function names, or different code style are **not** behavioral differences"
     (.claude/agents/vuln-judge.md)

so L1 is also a direct test of whether the judge honours that instruction.

Deliberately conservative about what it renames. Only **locally declared
variables and parameters** are renamed. Macros and constants (ALL_CAPS), called
functions, struct tags and field names are left alone, because their names carry
semantic content a reader legitimately uses — renaming `spin_lock` to `f7` would
be testing comprehension of obfuscated code, not invariance to naming.
"""
import re

C_KEYWORDS = set("""
auto break case char const continue default do double else enum extern float for
goto if inline int long register restrict return short signed sizeof static
struct switch typedef union unsigned void volatile while _Bool bool true false
NULL class new delete this template typename namespace public private protected
virtual operator using nullptr explicit friend mutable
""".split())

# A declaration-ish line: optional qualifiers, a type, then the declared name,
# optionally an array suffix or initialiser, then ';' or ',' or ')'.
DECL = re.compile(
    r"""(?:^|[;,(])\s*
        (?:(?:const|static|volatile|register|unsigned|signed|struct|union|enum|
             long|short|extern|inline)\s+)*
        [A-Za-z_]\w*\s*                 # the type
        (?:\*\s*|\s)+                   # pointer stars / whitespace
        ([a-z_]\w*)                     # the declared name
        \s*(?:\[[^\]]*\])?              # optional array suffix
        \s*(?=[;,=)])
    """, re.VERBOSE | re.MULTILINE)

IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
LINE_COMMENT = re.compile(r"//[^\n]*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _declared_names(code):
    """Names that look like locals or parameters: declared somewhere, used at
    least twice, lower-case (ALL_CAPS is a macro), not a keyword."""
    names = set()
    for m in DECL.finditer(code):
        n = m.group(1)
        if n in C_KEYWORDS or n.isupper():
            continue
        if len(re.findall(rf"\b{re.escape(n)}\b", code)) < 2:
            continue
        names.add(n)
    return names


def rename_locals(code, prefix="v"):
    """Consistently rename locals/parameters. Returns (new_code, mapping)."""
    names = sorted(_declared_names(code), key=lambda n: (-len(n), n))
    mapping = {n: f"{prefix}{i}" for i, n in enumerate(sorted(names), start=1)}
    if not mapping:
        return code, {}
    out = IDENT.sub(lambda m: mapping.get(m.group(0), m.group(0)), code)
    return out, mapping


def reformat(code):
    """Strip comments and normalise whitespace, keeping structure readable.

    Comments are removed because a comment copied verbatim from the reference is
    pure string alignment — exactly the shortcut L1 exists to remove.
    """
    code = BLOCK_COMMENT.sub("", code)
    code = LINE_COMMENT.sub("", code)
    lines = []
    for line in code.split("\n"):
        line = line.replace("\t", "    ").rstrip()
        if line.strip():
            lines.append(line)
    return "\n".join(lines)


def perturb(code):
    """The full L1 transform. Returns (new_code, stats)."""
    if not code:
        return code, {"identifiers_renamed": 0, "mapping": {}}
    renamed, mapping = rename_locals(code)
    out = reformat(renamed)
    return out, {"identifiers_renamed": len(mapping), "mapping": mapping}
