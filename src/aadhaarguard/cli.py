"""Command line: aadhaarguard scan | redact | kinds"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Iterator, List, Optional, Tuple

from . import __version__
from .detectors import DEFAULT_DETECTORS, KINDS
from .scanner import STYLES, Scanner, partial_mask

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}
MAX_BYTES = 5 * 1024 * 1024


def _iter_files(paths: List[str]) -> Iterator[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for f in sorted(files):
                    yield os.path.join(root, f)
        else:
            yield p


def _read_text(path: str) -> Optional[str]:
    """Return file text, or None for binary / oversized / unreadable files."""
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _line_col(text: str, offset: int) -> Tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    col = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, col


def _kinds(arg: Optional[str]) -> Optional[List[str]]:
    return [k.strip() for k in arg.split(",") if k.strip()] if arg else None


def cmd_scan(args: argparse.Namespace) -> int:
    scanner = Scanner(kinds=_kinds(args.kinds), min_confidence=args.min_confidence, ignore_case=args.ignore_case)
    sources: List[Tuple[str, Optional[str]]]
    if not args.paths or args.paths == ["-"]:
        sources = [("<stdin>", sys.stdin.read())]
    else:
        sources = [(p, _read_text(p)) for p in _iter_files(args.paths)]

    results = []
    for name, text in sources:
        if text is None:
            continue
        for m in scanner.scan(text):
            line, col = _line_col(text, m.start)
            shown = m.value if args.show else partial_mask(m.kind, m.value)
            results.append(
                {"file": name, "line": line, "column": col, "kind": m.kind,
                 "value": shown, "confidence": m.confidence}
            )

    if args.json:
        json.dump(results, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        for r in results:
            print(f"{r['file']}:{r['line']}:{r['column']}: {r['kind']} {r['value']} ({r['confidence']:.2f})")
        if results:
            files = len({r["file"] for r in results})
            print(f"\n{len(results)} finding(s) in {files} file(s)", file=sys.stderr)
    return 1 if results else 0


def cmd_redact(args: argparse.Namespace) -> int:
    scanner = Scanner(kinds=_kinds(args.kinds), min_confidence=args.min_confidence, ignore_case=args.ignore_case)
    if args.path in (None, "-"):
        text = sys.stdin.read()
    else:
        text = _read_text(args.path)
        if text is None:
            print(f"aadhaarguard: cannot read {args.path} as text", file=sys.stderr)
            return 2
    out = scanner.redact(text, style=args.style)
    if args.in_place and args.path not in (None, "-"):
        with open(args.path, "w", encoding="utf-8", newline="") as fh:
            fh.write(out)
    elif args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return 0


def cmd_kinds(args: argparse.Namespace) -> int:
    for d in DEFAULT_DETECTORS:
        needs = " [needs keyword]" if d.requires_context else ""
        print(f"{d.kind:16} {d.label}: {d.description}{needs}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aadhaarguard", description="Find and redact Indian personal data.")
    p.add_argument("--version", action="version", version=f"aadhaarguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--kinds", help=f"comma-separated subset of: {','.join(KINDS)}")
        sp.add_argument("--min-confidence", type=float, default=0.5, metavar="N",
                        help="drop matches below this confidence (0-1, default 0.5)")
        sp.add_argument("-I", "--ignore-case", action="store_true",
                        help="also match lowercase PAN/GSTIN/IFSC/passport/voter ID/DL")

    s = sub.add_parser("scan", help="report PII; exits 1 if any is found")
    s.add_argument("paths", nargs="*", help="files or directories (default: stdin)")
    s.add_argument("--json", action="store_true", help="JSON output")
    s.add_argument("--show", action="store_true",
                   help="print full values (default: partially masked, safe for CI logs)")
    common(s)
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("redact", help="print the input with PII replaced")
    r.add_argument("path", nargs="?", help="file (default: stdin)")
    r.add_argument("--style", choices=STYLES, default="tag")
    g = r.add_mutually_exclusive_group()
    g.add_argument("-o", "--output", help="write to this file instead of stdout")
    g.add_argument("-i", "--in-place", action="store_true", help="overwrite the input file")
    common(r)
    r.set_defaults(func=cmd_redact)

    k = sub.add_parser("kinds", help="list what can be detected")
    k.set_defaults(func=cmd_kinds)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Hindi keywords, Windows consoles
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as e:
        print(f"aadhaarguard: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
