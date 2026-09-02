#!/usr/bin/env python3
"""Derive the coverage numbers the documentation quotes, from the code.

Every count the site states - controls per provider, criteria per framework,
NIST 800-53 controls derivable through the crosswalk - is a property of the
checks and the crosswalk, not a fact to be maintained by hand. Maintaining them
by hand went badly: the same figures were corrected four times in one release,
and twice a number survived a sweep by appearing in a second place in the file
that was just edited.

This computes them, and checks the documentation agrees.

    coverage-counts.py            print the numbers
    coverage-counts.py --check    fail if any documented claim disagrees
    coverage-counts.py --write    rewrite the documented claims to match

Claims are declared in .github/coverage-claims.json so that adding a new one
does not mean touching this file. No third-party imports: it has to run on a
bare CI runner.
"""
import json
import os
import re
import sys

# AUDITKIT_ROOT lets the same script measure another checkout, which is how
# the Pro figures in the comparison tables are obtained.
ROOT = os.environ.get("AUDITKIT_ROOT") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".."))
SCANNER = os.path.join(ROOT, "scanner")
CROSSWALK = os.path.join(SCANNER, "pkg", "mappings", "framework-crosswalk.yaml")
CLAIMS = os.path.join(ROOT, ".github", "coverage-claims.json")
PROVIDERS = ("aws", "azure", "gcp")

# Framework tags are written either as a literal key or via a constant.
TAG = {
    "SOC2": "SOC2", "PCI-DSS": "PCI", "CMMC": "CMMC", "HIPAA": "HIPAA",
    "CIS-AWS": "CISAWS", "CIS-Azure": "CISAzure", "CIS-GCP": "CISGCP",
}


def read_crosswalk():
    """Parse the crosswalk without a YAML dependency.

    The file is a flat map of section -> {key: [values]} with comments, which
    is little enough syntax to read directly and saves needing pyyaml on a
    runner that has no pip step.
    """
    sections, current = {}, None
    for line in open(CROSSWALK, encoding="utf-8"):
        line = line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            current = line.rstrip(":").strip()
            sections[current] = {}
            continue
        m = re.match(r'\s+"?([^":]+)"?:\s*\[([^\]]*)\]', line)
        if m and current:
            key = m.group(1).strip()
            vals = [v.strip() for v in m.group(2).split(",") if v.strip()]
            sections[current][key] = vals
    return sections


def go_sources(provider):
    d = os.path.join(SCANNER, "pkg", provider, "checks")
    if not os.path.isdir(d):
        return []
    return [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".go")]


def tag_values(text, label):
    """Every value a check assigns to one framework, split on commas.

    Requirements are written bare ("5.2.1") or prefixed ("Req 5.2.1"); the
    prefix is dropped so both forms count once.
    """
    pat = re.compile(r'(?:"%s"|Framework%s)\s*:\s*"([^"]+)"' % (re.escape(label), TAG[label]))
    out = set()
    for v in pat.findall(text):
        for e in v.split(","):
            e = re.sub(r"^Req\s+", "", e.strip())
            if e:
                out.add(e)
    return out


def split_ids(value):
    """Requirements are written bare ("5.2.1") or prefixed ("Req 5.2.1")."""
    out = set()
    for e in value.split(","):
        e = re.sub(r"^Req\s+", "", e.strip())
        if e:
            out.add(e)
    return out


def tag_values(text, label):
    """Every id assigned to one framework anywhere in a provider's checks.

    Covers both ways a check declares a mapping: inline on the result, and as an
    entry in the FrameworkMappings lookup tables. Deliberately a flat scan of
    the source rather than an attempt to pair each Control with its own literal:
    pairing needs a window heuristic, and a heuristic that guesses wrong drops
    ids silently, which is the failure this script exists to prevent.
    """
    pat = re.compile(r'(?:"%s"|Framework%s)\s*:\s*"([^"]+)"' % (re.escape(label), TAG[label]))
    out = set()
    for v in pat.findall(text):
        out |= split_ids(v)
    return out


def measure():
    cw = read_crosswalk()
    fwd = {
        "SOC2": cw.get("soc2_to_800_53", {}),
        "PCI-DSS": {k[4:]: v for k, v in cw.get("pci_to_800_53", {}).items() if k.startswith("PCI-")},
        "CMMC": cw.get("cmmc_to_800_53", {}),
        "HIPAA": cw.get("hipaa_to_800_53", {}),
    }
    # 800-53 control -> the targets citing it, for frameworks we only derive.
    rev = {}
    for name, sec in (("iso27001", "iso27001_to_800_53"), ("gdpr", "gdpr_to_800_53"),
                      ("nistcsf", "nist_csf_to_800_53"), ("hipaa", "hipaa_to_800_53")):
        r = {}
        for k, vals in cw.get(sec, {}).items():
            for c in vals:
                r.setdefault(c, set()).add(k)
        rev[name] = r

    m = {}
    all_n53, all_pci = set(), set()
    all_cmmc_l1, all_cmmc_l2 = set(), set()
    for p in PROVIDERS:
        files = go_sources(p)
        if not files:
            continue
        text = "\n".join(open(f, encoding="utf-8", errors="ignore").read() for f in files)
        controls = set(re.findall(r'Control:\s*"([^"]+)"', text))
        m["controls.%s" % p] = len(controls)

        soc2 = tag_values(text, "SOC2") | {c for c in controls if re.match(r"^(CC|A1|C1|PI|P)[0-9]\.[0-9]+$", c)}
        pci = tag_values(text, "PCI-DSS")
        cmmc = tag_values(text, "CMMC")
        hipaa = tag_values(text, "HIPAA")
        cis = tag_values(text, {"aws": "CIS-AWS", "azure": "CIS-Azure", "gcp": "CIS-GCP"}[p])
        for c in controls:
            cm = re.match(r"^\[?CIS-(?:AWS-|Azure-|GCP-)?([0-9][0-9.]*)\]?$", c)
            if cm:
                cis.add(cm.group(1))

        m["soc2.%s" % p] = len(soc2)
        m["pci.%s" % p] = len(pci)
        m["cmmc_l1.%s" % p] = len([c for c in cmmc if ".L1-" in c])
        m["cmmc_l2.%s" % p] = len([c for c in cmmc if ".L2-" in c])
        m["cis.%s" % p] = len(cis)

        # 800-53 reachable from this provider. Framework tags first, then the
        # control id, which crosswalk.go falls back to when the tags resolve to
        # nothing (Get800_53String).
        n53 = set()
        for label, ids in (("SOC2", soc2), ("PCI-DSS", pci), ("CMMC", cmmc), ("HIPAA", hipaa)):
            for i in ids:
                n53.update(fwd[label].get(i, []))
        for c in controls:
            for table in fwd.values():
                if c in table:
                    n53.update(table[c])
        m["nist80053.%s" % p] = len(n53)

        all_pci |= pci
        all_cmmc_l1 |= {c for c in cmmc if ".L1-" in c}
        all_cmmc_l2 |= {c for c in cmmc if ".L2-" in c}
        all_n53 |= n53
        for name in ("iso27001", "gdpr", "nistcsf", "hipaa"):
            m["%s.%s" % (name, p)] = len({t for c in n53 for t in rev[name].get(c, ())})

    m["cmmc_l1.total"] = len(all_cmmc_l1)
    m["cmmc_l2.total"] = len(all_cmmc_l2)
    m["cmmc.total"] = len(all_cmmc_l1 | all_cmmc_l2)
    m["pci.total"] = len(all_pci)
    m["nist80053.total"] = len(all_n53)
    m["soc2.criteria"] = len(cw.get("soc2_to_800_53", {}))
    return m


def load_claims():
    if not os.path.exists(CLAIMS):
        return []
    return json.load(open(CLAIMS, encoding="utf-8"))["claims"]


def run_claims(metrics, write):
    problems, changed = [], 0
    for c in load_claims():
        path = os.path.join(ROOT, c["file"])
        if not os.path.exists(path):
            problems.append(f"{c['file']}: file not found")
            continue
        if c["metric"] not in metrics:
            problems.append(f"{c['file']}: unknown metric {c['metric']}")
            continue
        want = str(metrics[c["metric"]])
        text = open(path, encoding="utf-8").read()
        pat = re.compile(c["pattern"])
        found = pat.search(text)
        if not found:
            problems.append(f"{c['file']}: pattern did not match: {c['pattern']}")
            continue
        hits = [mm for mm in pat.finditer(text) if mm.group(1) != want]
        if not hits:
            continue
        if write:
            def sub(mm):
                if mm.group(1) == want:
                    return mm.group(0)
                s, e = mm.span(1)
                return mm.group(0)[: s - mm.start()] + want + mm.group(0)[e - mm.start():]
            open(path, "w", encoding="utf-8").write(pat.sub(sub, text))
            changed += len(hits)
        else:
            for mm in hits:
                line = text[: mm.start()].count("\n") + 1
                problems.append(f"{c['file']}:{line}: says {mm.group(1)}, {c['metric']} is {want}")
    return problems, changed


def main():
    metrics = measure()
    args = set(sys.argv[1:])

    if not args & {"--check", "--write"}:
        for k in sorted(metrics):
            print(f"  {k:<22} {metrics[k]}")
        return 0

    problems, changed = run_claims(metrics, write="--write" in args)
    if "--write" in args:
        print(f"  updated {changed} claim(s)")
        if problems:
            for p in problems:
                print(f"  {p}")
            return 1
        return 0

    if problems:
        print("Documented coverage disagrees with the code:\n")
        for p in problems:
            print(f"  {p}")
        print("\nRun .github/scripts/coverage-counts.py --write to correct them.")
        return 1
    print("Documented coverage matches the code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
