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
# A bare level marks a check as in scope for a level without claiming a
# specific practice. It resolves to nothing in the crosswalk, by design.
LEVEL_ONLY = {"L1", "L2"}


def problems():
    found = []
    for prov in ("aws", "azure", "gcp"):
        for f in sorted(glob.glob(os.path.join(ROOT, "scanner", "pkg", prov, "checks", "*.go"))):
            text = open(f, encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r'(?:"CMMC"|FrameworkCMMC)\s*:\s*"([^"]+)"', text):
                line = text[: m.start()].count("\n") + 1
                for e in m.group(1).split(","):
                    e = e.strip()
                    if not e or e in LEVEL_ONLY:
                        continue
                    pm = PRACTICE.match(e)
                    rel = os.path.relpath(f, ROOT)
                    if not pm:
                        found.append(f"{rel}:{line}: {e} is not a practice id")
                    elif pm.group(1) not in CAN:
                        found.append(f"{rel}:{line}: {e} is not in 800-171 Rev 2")
                    elif CAN[pm.group(1)] != e:
                        found.append(f"{rel}:{line}: {e} should be {CAN[pm.group(1)]}")

    cw = os.path.join(ROOT, "scanner", "pkg", "mappings", "framework-crosswalk.yaml")
    if os.path.exists(cw):
        text = open(cw, encoding="utf-8").read()
        for m in re.finditer(r"^\s{2}([A-Z]{2}\.L[12]-3\.\d+\.\d+):", text, re.M):
            line = text[: m.start()].count("\n") + 1
            key = m.group(1)
            num = PRACTICE.match(key).group(1)
            if num not in CAN:
                found.append(f"framework-crosswalk.yaml:{line}: {key} is not in 800-171 Rev 2")
            elif CAN[num] != key:
                found.append(f"framework-crosswalk.yaml:{line}: {key} should be {CAN[num]}")
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
