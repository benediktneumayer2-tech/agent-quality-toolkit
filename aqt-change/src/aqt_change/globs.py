"""``**``-aware globs for project-relative POSIX paths.

``*`` and ``?`` stay inside one path segment, ``**`` spans segments, a trailing
``/`` means "everything below this directory".
"""

from __future__ import annotations

import re
from functools import lru_cache


@lru_cache(maxsize=512)
def compile_glob(pattern: str) -> re.Pattern:
    if pattern.endswith("/"):
        pattern += "**"
    out, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
            continue
        if pattern.startswith("**", index):
            out.append(".*")
            index += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(char))
        index += 1
    return re.compile("^" + "".join(out) + "$")


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(compile_glob(pattern).match(path) for pattern in patterns)
