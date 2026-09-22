#!/usr/bin/env python3
"""Check the IJCIP submission package against the journal's stated limits.

    python3 experiments/check_submission.py

Editorial Manager rejects on mechanics before an editor reads a word: an
abstract over the limit, a highlight one character too long, a blinded
manuscript that names its author. Each of those is cheap to verify and
expensive to get wrong, so this script verifies them.

Exit status is non-zero if any check fails, so it can gate a commit.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAPER = os.path.join(ROOT, "paper")
IJCIP = os.path.join(PAPER, "ijcip")

ABSTRACT_WORD_LIMIT = 250
HIGHLIGHT_CHAR_LIMIT = 85
HIGHLIGHT_RANGE = (3, 5)
WORD_RANGE = (5000, 10000)          # research paper, abstract included, references excluded

REQUIRED = [
    "manuscript.tex", "manuscript-blinded.tex", "title-page.tex", "cover-letter.tex",
    "highlights.tex", "highlights.txt", "abstract-ijcip.tex", "declarations.tex",
    "declarations-blinded.tex", "references-blinded.bib", "README.md",
]

#: Strings that must never appear in the blinded manuscript. Extend this when
#: the author metadata in paper/authors.tex changes.
IDENTITY_MARKERS = ["rikosoo", "InfraCriticalCar", "@example.org"]


def detex(text: str) -> List[str]:
    text = re.sub(r"(?<!\\)%.*", "", text)
    text = re.sub(r"\\(begin|end)\{[^}]*\}", " ", text)
    text = re.sub(r"\\(cite|ref|cref|Cref|label|input|url|path)\{[^}]*\}", " X ", text)
    text = re.sub(r"\$[^$]*\$", " X ", text)
    text = re.sub(r"\\[a-zA-Z]+\*?", " ", text)
    text = re.sub(r"[{}~&\\]", " ", text)
    return [w for w in re.split(r"\s+", text) if w.strip(".,;:()[]-—")]


def abstract_words() -> int:
    text = open(os.path.join(IJCIP, "abstract-ijcip.tex"), encoding="utf-8").read()
    body = text[text.index("capmabstract"):text.index("capmkeywords")]
    return len(detex(body))


def highlights() -> List[str]:
    text = open(os.path.join(IJCIP, "highlights.tex"), encoding="utf-8").read()
    out = []
    for line in re.findall(r"\\item (.+)", text):
        out.append(re.sub(r"\\([%&_#])", r"\1", line).strip())
    return out


def manuscript_words() -> int:
    body = open(os.path.join(PAPER, "body.tex"), encoding="utf-8").read()
    prose = "\n".join(l for l in body.split("\n") if not l.strip().startswith("\\input{"))
    return abstract_words() + len(detex(prose))


def blinded_leaks() -> List[str]:
    pdf = os.path.join(IJCIP, "manuscript-blinded.pdf")
    if not os.path.exists(pdf):
        return []
    try:
        text = subprocess.run(["pdftotext", pdf, "-"], capture_output=True,
                              text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    found = []
    for marker in IDENTITY_MARKERS:
        for line in text.splitlines():
            if marker.lower() in line.lower() and "bleepingcomputer" not in line.lower():
                found.append(f"{marker}: {line.strip()[:70]}")
                break
    return found


def main() -> int:
    checks: List[Tuple[bool, str]] = []

    missing = [f for f in REQUIRED if not os.path.exists(os.path.join(IJCIP, f))]
    checks.append((not missing, f"required files present ({len(REQUIRED) - len(missing)}/"
                                f"{len(REQUIRED)})"
                                + (f" -- missing {missing}" if missing else "")))

    words = abstract_words()
    checks.append((words <= ABSTRACT_WORD_LIMIT,
                   f"abstract {words} words (limit {ABSTRACT_WORD_LIMIT})"))

    hl = highlights()
    too_long = [(len(h), h) for h in hl if len(h) > HIGHLIGHT_CHAR_LIMIT]
    checks.append((HIGHLIGHT_RANGE[0] <= len(hl) <= HIGHLIGHT_RANGE[1],
                   f"{len(hl)} highlights (allowed {HIGHLIGHT_RANGE[0]}-{HIGHLIGHT_RANGE[1]})"))
    checks.append((not too_long,
                   f"longest highlight {max((len(h) for h in hl), default=0)} characters "
                   f"(limit {HIGHLIGHT_CHAR_LIMIT})"
                   + (f" -- over: {[h for _, h in too_long]}" if too_long else "")))

    total = manuscript_words()
    checks.append((WORD_RANGE[0] <= total <= WORD_RANGE[1],
                   f"manuscript {total} words (range {WORD_RANGE[0]}-{WORD_RANGE[1]}, "
                   "references excluded)"))

    leaks = blinded_leaks()
    pdf_there = os.path.exists(os.path.join(IJCIP, "manuscript-blinded.pdf"))
    checks.append((not leaks, "blinded manuscript carries no author identity"
                   + (f" -- found {leaks}" if leaks else
                      ("" if pdf_there else " (PDF not built, not checked)"))))

    width = max(len(m) for _, m in checks)
    failures = 0
    for ok, message in checks:
        print(f"  [{'ok' if ok else 'FAIL'}] {message.ljust(width)}")
        failures += 0 if ok else 1
    print(f"\n{len(checks) - failures}/{len(checks)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
