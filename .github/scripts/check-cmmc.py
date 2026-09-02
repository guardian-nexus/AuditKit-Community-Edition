#!/usr/bin/env python3
"""Reject CMMC practice ids that are not in the standard.

Pro shipped 36 practice ids that do not exist: each family's numbering had been
continued past where NIST SP 800-171 Rev 2 stops, so AC.L2-3.1.23 through
3.1.26, PE.L2-3.10.7 through 3.10.13 and others were being reported to defence
contractors as covered practices. A further 42 uses carried the wrong level or
the wrong family prefix, including CA.L2-3.13.x for controls that belong to SC,
and RE.L2-3.13.x in the crosswalk, where RE is not a family at all.

Every id is checkable: the family prefix follows from the control number, and
the level follows from whether the control is one of the 17 in FAR 52.204-21.

Run locally with: .github/scripts/check-cmmc.py
"""
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cmmc_ref import canonical  # noqa: E402

ROOT = os.environ.get("AUDITKIT_ROOT") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".."))
CAN = canonical()
PRACTICE = re.compile(r"^[A-Z]{2}\.L[12]-(3\.\d+\.\d+)$")
ANYWHERE = re.compile(r"\b([A-Z]{2})\.(L[12])-(3\.\d+\.\d+)\b")
# A bare level marks a check as in scope for a level without claiming a
# specific practice. It resolves to nothing in the crosswalk, by design.
LEVEL_ONLY = {"L1", "L2"}


def problems():
    """Any practice-shaped string anywhere in the scanner source must be canonical.

    Earlier versions of this guard matched only two syntactic forms, the Control
    field and the framework tag. That missed a table-driven check written as a
    positional slice literal, the CMMC checklist printed into every PDF report,
    the Azure Arc scanner, and a set of comments. Matching the pattern wherever
    it appears is the only version of this check that holds.
    """
    found = []
    roots = [os.path.join(ROOT, "scanner")]
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for fn in sorted(files):
                if not fn.endswith((".go", ".yaml", ".yml")):
                    continue
                f = os.path.join(dirpath, fn)
                rel = os.path.relpath(f, ROOT)
                for i, line in enumerate(open(f, encoding="utf-8", errors="ignore"), 1):
                    for m in ANYWHERE.finditer(line):
                        num = m.group(3)
                        if num not in CAN:
                            found.append(f"{rel}:{i}: {m.group(0)} is not in 800-171 Rev 2")
                        elif CAN[num] != m.group(0):
                            found.append(f"{rel}:{i}: {m.group(0)} should be {CAN[num]}")
    return found


def main():
    found = problems()
    if found:
        print("CMMC practice ids that do not match the standard:\n")
        for p in found:
            print(f"  {p}")
        return 1
    print("All CMMC practice ids match NIST SP 800-171 Rev 2.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
