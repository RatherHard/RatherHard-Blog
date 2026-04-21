#!/usr/bin/env python3
"""Fix frontmatter date fields to normalized format: YYYY-MM-DD HH:MM:SS"""

import re
import glob

DATE_RE = re.compile(
    r"^(date:\s*)"
    r"(\d{4})-(\d{1,2})-(\d{1,2})"
    r"(?:\s+(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?"
    r"(?:[+\-]\d{4})?",
    re.MULTILINE,
)


def normalize_date(m):
    prefix = m.group(1)
    year = m.group(2)
    month = m.group(3).zfill(2)
    day = m.group(4).zfill(2)
    hour = (m.group(5) or "00").zfill(2)
    minute = (m.group(6) or "00").zfill(2)
    second = (m.group(7) or "00").zfill(2)
    return f"{prefix}{year}-{month}-{day} {hour}:{minute}:{second}"


files = glob.glob("content/**/*.md", recursive=True)
for path in sorted(files):
    with open(path, "r") as f:
        text = f.read()
    new_text = DATE_RE.sub(normalize_date, text)
    if new_text != text:
        with open(path, "w") as f:
            f.write(new_text)
        old = DATE_RE.search(text).group(0)
        new = DATE_RE.search(new_text).group(0)
        print(f"{path}: {old!r} -> {new!r}")
    else:
        print(f"{path}: ok")
