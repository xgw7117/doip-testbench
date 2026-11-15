# Pre-commit consistency check.
#
# Two things go wrong often enough to be automated:
#   1. HTML entities leak into source files when code is copy-pasted through a
#      chat window. A zero-width-space entity (ampersand, hash, digits) lands
#      in the file and Python happily parses it as part of a string, so the
#      module just silently does nothing.
#   2. README quotes a case count that no longer matches the suite.
#
# Run it before every commit:  make check

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[0]).resolve().parents[1]

# Built from code points so this file never trips its own scan.
ENTITY = chr(38) + chr(35)


def scan_entities() -> list[Path]:
    hits = []
    for pattern in ("src/**/*.py", "tests/**/*.py", "tests/**/*.yaml", "tools/**/*.py"):
        for path in ROOT.glob(pattern):
            text = path.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                if ENTITY in line:
                    hits.append((path.relative_to(ROOT), lineno))
    return hits


def collected() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    return int(match.group(1)) if match else -1


def claimed() -> int:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"一共 (\d+) 条", text)
    return int(match.group(1)) if match else -1


def main() -> int:
    ok = True

    hits = scan_entities()
    if hits:
        ok = False
        print("[FAIL] HTML entities leaked into source:")
        for path, lineno in hits:
            print(f"       {path}:{lineno}")
        print("       paste corruption; rewrite the file instead")
    else:
        print("[ ok ] no HTML entities in source")

    actual, quoted = collected(), claimed()
    if actual < 0:
        ok = False
        print("[FAIL] could not collect tests")
    elif actual != quoted:
        ok = False
        print(f"[FAIL] README says {quoted} cases, suite collects {actual}")
    else:
        print(f"[ ok ] case count {actual} matches README")

    return 0 if ok else 1


sys.exit(main())
