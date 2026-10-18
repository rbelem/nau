#!/usr/bin/env python3
"""Split an inline `#[cfg(test)] mod tests` into files that stay under the
token budget.

The dominant size pathology in this repo is not tangled code, it is a test
module that grew to hundreds of kilobytes in one file. Those tests exercise
private items, so they cannot move to `tests/`; they move to a sibling
`tests/` directory declared by `mod tests;`, which keeps `super::` access and
changes nothing else.

The split is lossless by construction. The script refuses unless the tail
after the module is empty and every emitted file fits the budget.

Usage:
  scripts/split-inline-tests.py <file.rs> [--chunk-bytes N] [--apply]

Without --apply it prints the plan and exits. With --apply it rewrites the
file and writes the module directory.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

ATTRIBUTE = re.compile(
    rb"(?m)^([ \t]*)#\[cfg\(test\)\][ \t]*\r?\n([ \t]*)mod tests[ \t]*\{"
)
BUDGET_BYTES = 20000
CHUNK_BYTES = 18000
TEST_ATTRS = (
    b"#[test]",
    b"#[tokio::test",
    b"#[rstest]",
    b"#[test_case",
    b"#[quickcheck]",
)
ITEM_START = re.compile(
    rb"^\s*(#\[|#!\[|use\b|pub\b|fn\b|async\b|struct\b|enum\b|impl\b|const\b|static\b|mod\b|type\b|macro_rules!)"
)
RAW_STRING = re.compile(rb'(?:b|c)?r(#*)?"')


class SplitError(Exception):
    pass


def skip_line_comment(data, i):
    end = data.find(b"\n", i)
    return len(data) if end < 0 else end


def skip_block_comment(data, i):
    depth = 0
    while i < len(data):
        if data[i : i + 2] == b"/*":
            depth += 1
            i += 2
        elif data[i : i + 2] == b"*/":
            depth -= 1
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    return len(data)


def skip_raw_string(data, i):
    m = RAW_STRING.match(data, i)
    close = b'"' + m.group(1)
    end = data.find(close, m.end())
    return len(data) if end < 0 else end + len(close)


def skip_quoted(data, i):
    j = i + 1
    while j < len(data):
        if data[j : j + 1] == b"\\":
            j += 2
            continue
        if data[j : j + 1] == b'"':
            return j + 1
        j += 1
    return len(data)


def skip_char(data, i):
    if data[i : i + 2] == b"\\'":
        j = i + 1
        while j < len(data):
            if data[j : j + 1] == b"\\":
                j += 2
                continue
            if data[j : j + 1] == b"'":
                return j + 1
            j += 1
        return len(data)
    if i + 2 < len(data) and data[i + 2 : i + 3] == b"'":
        return i + 3
    return i + 1


def skip_literal(data, i):
    """Return the index after the comment or literal starting at i."""
    c = data[i : i + 1]
    if c == b"/":
        if data[i : i + 2] == b"//":
            return skip_line_comment(data, i)
        if data[i : i + 2] == b"/*":
            return skip_block_comment(data, i)
        return i + 1
    if RAW_STRING.match(data, i):
        return skip_raw_string(data, i)
    if c == b'"':
        return skip_quoted(data, i)
    if c == b"'":
        return skip_char(data, i)
    return i + 1


def at_literal(data, i):
    """True when a comment, string, char, or raw string starts at i.

    A raw string begins with a letter (`r`, `br`), so gating on the quote byte
    alone misses it and the scan closes it at the first quote inside the body.
    """
    return (
        data[i : i + 1] in (b'"', b"'", b"/") or RAW_STRING.match(data, i) is not None
    )


def find_module(data):
    m = ATTRIBUTE.search(data)
    if not m:
        raise SplitError("no `#[cfg(test)] mod tests {` block")
    brace = data.index(b"{", m.end() - 1)
    depth = 0
    i = brace
    while i < len(data):
        c = data[i : i + 1]
        if at_literal(data, i):
            i = skip_literal(data, i)
            continue
        depth += 1 if c == b"{" else -1 if c == b"}" else 0
        if c == b"}" and depth == 0:
            end = i + 1
            break
        i += 1
    else:
        raise SplitError("unbalanced braces in the test module")

    if data[end:].strip():
        raise SplitError("the test module is not the last item in the file")
    return m.start(), end, data[brace + 1 : end - 1]


def begins_item(line, depth):
    if depth != 0:
        return False
    stripped = line.strip()
    return bool(ITEM_START.match(line)) or stripped.startswith((b"///", b"//!"))


def is_prefix_only(chunk):
    """True when the chunk holds only attributes or doc comments.

    A `#[test]` attribute and its `fn` line are separate depth-0 lines. Without
    this check the attribute would be split off as its own item.
    """
    for line in chunk.splitlines():
        text = line.strip()
        if not text:
            continue
        if text.startswith((b"#[", b"#![", b"///", b"//!")):
            continue
        return False
    return True


def item_boundary(body, i, item_start, line_start, depth):
    if not line_start or depth != 0 or i <= item_start:
        return False
    end = body.find(b"\n", i)
    line = body[i:] if end < 0 else body[i:end]
    return begins_item(line, 0) and not is_prefix_only(body[item_start:i])


def advance(body, i, depth):
    """Consume one token at i. Return (next index, depth, at line start)."""
    c = body[i : i + 1]
    if at_literal(body, i):
        j = skip_literal(body, i)
        j = j if j > i else i + 1
        return j, depth, body[j - 1 : j] == b"\n"
    if c == b"{":
        return i + 1, depth + 1, False
    if c == b"}":
        if depth == 0:
            raise SplitError("unbalanced braces in the test module")
        return i + 1, depth - 1, False
    return i + 1, depth, c == b"\n"


def top_level_chunks(body):
    """Split the module body into top-level items, attributes included.

    One pass over the whole body, not line by line: a raw string can span
    lines and its braces are text, not nesting.
    """
    chunks = []
    item_start = 0
    depth = 0
    i = 0
    line_start = True
    while i < len(body):
        if item_boundary(body, i, item_start, line_start, depth):
            chunks.append(body[item_start:i])
            item_start = i
        i, depth, line_start = advance(body, i, depth)
    if depth != 0:
        raise SplitError("unbalanced braces in the test module")
    chunks.append(body[item_start:])
    return [c for c in chunks if c.strip()]


def is_test(chunk):
    return any(attr in chunk for attr in TEST_ATTRS)


def test_name(chunk):
    m = re.search(rb"\bfn\s+([A-Za-z0-9_]+)", chunk)
    return m.group(1).decode() if m else "unnamed"


def theme_for(names):
    parts = names[0].split("_")
    base = "_".join(parts[:2]) if len(parts) > 1 else parts[0]
    base = re.sub(r"[^a-z0-9_]", "", base.lower())
    return base or "part"


def partition(tests, limit):
    groups = []
    current = []
    size = 0
    for chunk in tests:
        if current and size + len(chunk) > limit:
            groups.append(current)
            current = []
            size = 0
        current.append(chunk)
        size += len(chunk)
    if current:
        groups.append(current)
    return groups


def assign_names(groups):
    used = set()
    names = []
    for group in groups:
        base = theme_for([test_name(c) for c in group])
        name = base
        n = 2
        while name in used:
            name = f"{base}_{n}"
            n += 1
        used.add(name)
        names.append(name)
    return names


INCLUDE = re.compile(rb'(include(?:_str|_bytes)?!\s*\(\s*")([^"]+)(")')


def rebase_includes(content, prefix):
    """Point `include_str!` and friends at the same file from a deeper path.

    A relative include resolves against the file holding the macro, so a file
    that moved down one or two directories needs that many `../` in front.
    """

    def repl(m):
        rel = m.group(2)
        if rel.startswith(b"/") or b"://" in rel:
            return m.group(0)
        return m.group(1) + prefix + b"/" + rel + m.group(3)

    return INCLUDE.sub(repl, content)


def tests_dir_for(path):
    if os.path.basename(path) == "mod.rs":
        return os.path.join(os.path.dirname(os.path.abspath(path)), "tests")
    return os.path.abspath(path)[:-3] + "/tests"


def build_files(path, shared, names, groups):
    header = b"use super::*;\n\n"
    mod_file = (
        b"".join(shared)
        + b"\n"
        + b"".join(b"mod " + n.encode() + b";\n" for n in names)
    )
    tests_dir = tests_dir_for(path)
    original_dir = os.path.dirname(os.path.abspath(path))
    prefix = os.path.relpath(original_dir, tests_dir).encode()
    files = {os.path.join(tests_dir, "mod.rs"): mod_file}
    for name, group in zip(names, groups):
        files[os.path.join(tests_dir, name + ".rs")] = header + b"".join(group)
    return {name: rebase_includes(content, prefix) for name, content in files.items()}


def plan(path, chunk_bytes):
    data = open(path, "rb").read()
    start, end, body = find_module(data)
    items = top_level_chunks(body)
    shared = [c for c in items if not is_test(c)]
    tests = [c for c in items if is_test(c)]
    if not tests:
        raise SplitError("the test module holds no tests")

    groups = partition(tests, chunk_bytes - len(b"use super::*;\n\n"))
    names = assign_names(groups)
    return {
        "path": path,
        "start": start,
        "end": end,
        "replacement": b"#[cfg(test)]\nmod tests;\n",
        "files": build_files(path, shared, names, groups),
        "tests": len(tests),
        "shared": len(shared),
    }


def verify(result, original):
    for name, content in result["files"].items():
        if len(content) > BUDGET_BYTES:
            raise SplitError(
                f"{name} would be {len(content)} bytes, over the {BUDGET_BYTES} budget"
            )
    rebuilt = (
        original[: result["start"]] + result["replacement"] + original[result["end"] :]
    )
    if original[: result["start"]] != rebuilt[: result["start"]]:
        raise SplitError("prefix does not round-trip")
    return rebuilt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--chunk-bytes", type=int, default=CHUNK_BYTES)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.path):
        sys.exit(f"no such file: {args.path}")

    original = open(args.path, "rb").read()
    try:
        result = plan(args.path, args.chunk_bytes)
        rebuilt = verify(result, original)
    except SplitError as exc:
        sys.exit(f"{args.path}: {exc}")

    print(
        f"{args.path}: {len(original)} B -> {len(rebuilt)} B "
        f"({result['tests']} tests, {result['shared']} shared items)"
    )
    for name in sorted(result["files"]):
        print(f"  {len(result['files'][name]):7d} B  {name}")

    if not args.apply:
        print("\ndry run. pass --apply to write")
        return

    for name, content in result["files"].items():
        os.makedirs(os.path.dirname(name), exist_ok=True)
        if os.path.exists(name):
            sys.exit(f"refusing to overwrite {name}")
        with open(name, "wb") as fh:
            fh.write(content)
    with open(args.path, "wb") as fh:
        fh.write(rebuilt)
    print("written")


if __name__ == "__main__":
    main()
