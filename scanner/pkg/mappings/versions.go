package mappings

import (
	"fmt"
	"sort"
	"time"
)

// Which edition of each standard AuditKit implements, and what was read to
// establish it.
//
// Before this existed the answer was scattered across print statements,
// comments, catalogs and docs, and they disagreed: Pro announced CIS Azure
// Foundations v2.0 while Community announced v3.0 of the same benchmark, and
// the AWS scan printed "(v1.4 & 3.0)" while the README claimed v3.0 and a
// comment in the same file said v1.5.0+. A reader had no way to tell which was
// true, and neither did we.
//
// There is deliberately no "current" field. Nothing in this repo can know that
// a standard has been superseded - that fact lives outside the system, and a
// boolean would go stale silently while still reading as an assurance. What is
// recorded instead is the document that was read and the date it was read, so
// staleness surfaces as age of last verification. "Last checked against TSC
// 2017 on 2026-09-10" is something the code can support; "SOC 2 is current" is
// not.
type Edition struct {
	// Framework is the key the rest of the codebase tags results with.
	Framework string
	// Name is the standard's own title, as printed on its title page.
	Name string
	// Version is the edition our control identifiers correspond to. Empty when
	// the identifiers have not been reconciled against any published edition,
	// which is not the same as unknown-and-unimportant: it is a defect with a
	// note attached.
	Version string
	// Document is what was read to establish Version. Empty means nobody has
	// opened the standard; the entry is an assertion, not a verification.
	Document string
	// Verified is the date Document was read, YYYY-MM-DD. Empty with a
	// Document set is a contradiction and the guard rejects it.
	Verified string
	// Note carries anything a reader needs before trusting the row.
	Note string
}

// editions is the single source of truth. Adding a row is a claim; adding one
// with a Document and Verified date is a checked claim.
var editions = map[string]Edition{
	"CIS-AWS": {
		Framework: "CIS-AWS",
		Name:      "CIS Amazon Web Services Foundations Benchmark",
		Document:  "CIS Amazon Web Services Foundations Benchmark v7.0.0, 03-25-2026",
		Verified:  "2026-09-10",
		Note: "v7.0.0 renumbered every section - Identity and Access Management moved from " +
			"section 1 to section 2 - and our control identifiers still use the older layout, " +
			"so no version is claimed until they are reconciled.",
	},
	"CIS-Azure": {
		Framework: "CIS-Azure",
		Name:      "CIS Microsoft Azure Foundations Benchmark",
		Document:  "CIS Microsoft Azure Foundations Benchmark V6.0.0, 04-19-2026",
		Verified:  "2026-09-10",
		Note: "v6.0.0 is organised by service category and bears no relation to the 1-9 " +
			"layout our identifiers use, so no version is claimed until they are reconciled.",
	},
	"CIS-GCP": {
		Framework: "CIS-GCP",
		Name:      "CIS Google Cloud Platform Foundation Benchmark",
		Document:  "CIS Google Cloud Platform Foundation Benchmark v5.0.0, 05-09-2026",
		Verified:  "2026-09-10",
		Note: "v5.0.0 section 8 is Dataproc, while our 8.x identifiers are GKE checks that " +
			"belong to the separate CIS GKE benchmark. Not claimed until reconciled.",
	},
	"PCI-DSS": {
		Framework: "PCI-DSS",
		Name:      "Payment Card Industry Data Security Standard",
		Version:   "4.0.1",
		Document:  "PCI DSS Requirements and Testing Procedures, Version 4.0.1, June 2024",
		Verified:  "2026-09-10",
	},
	"SOC2": {
		Framework: "SOC2",
		Name:      "AICPA Trust Services Criteria",
		Version:   "2017 (with 2022 revised points of focus)",
		Note:      "Asserted from the 43-criterion catalog, not read from the TSC document.",
	},
	"CMMC": {
		Framework: "CMMC",
		Name:      "Cybersecurity Maturity Model Certification",
		Version:   "Level 1 and 2, practices from NIST SP 800-171 Rev 2",
		Note: "800-171 Rev 3 exists but CMMC's rule points at Rev 2, so Rev 2 is correct " +
			"here. Confirm against the rule before anyone upgrades it.",
	},
	"HIPAA": {
		Framework: "HIPAA",
		Name:      "HIPAA Security Rule",
		Version:   "45 CFR Part 164 Subpart C",
		Note:      "A proposed update was in rulemaking; check whether it is final.",
	},
	"NIST 800-53": {
		Framework: "NIST 800-53",
		Name:      "NIST SP 800-53 Security and Privacy Controls",
		Version:   "Rev 5",
		Note:      "Asserted from the 1196-control catalog, not read from the publication.",
	},
	"ISO27001": {
		Framework: "ISO27001",
		Name:      "ISO/IEC 27001 Annex A",
		Version:   "2022",
		Note:      "Migrated from the 2013 numbering via Annex B; two mappings were flagged for spot-check.",
	},
	"FedRAMP": {
		Framework: "FedRAMP",
		Name:      "FedRAMP Baselines",
		Version:   "derived from NIST SP 800-53 Rev 5",
		Note:      "Membership is computed from the 800-53 baselines rather than declared separately.",
	},
	"NIST CSF": {
		Framework: "NIST CSF",
		Name:      "NIST Cybersecurity Framework",
		Version:   "2.0",
		Note:      "Asserted from the 106-entry catalog, not read from the publication.",
	},
	"GDPR": {
		Framework: "GDPR",
		Name:      "General Data Protection Regulation",
		Version:   "(EU) 2016/679",
		Note: "The regulation is not revised in editions, so the citation is the version. " +
			"Asserted rather than read from the Official Journal text.",
	},
}

// EditionFor returns the recorded edition for a framework tag.
func EditionFor(framework string) (Edition, bool) {
	e, ok := editions[framework]
	return e, ok
}

// Editions returns every row, ordered so output is stable between runs.
func Editions() []Edition {
	out := make([]Edition, 0, len(editions))
	for _, e := range editions {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	return out
}

// Describe names the standard and its edition for a report or a scan banner.
// When no edition has been established it says so rather than printing a
// version nobody checked, which is what the old hardcoded strings did.
func (e Edition) Describe() string {
	if e.Version == "" {
		return e.Name + " (edition not yet reconciled)"
	}
	return e.Name + " " + e.Version
}

// Checked reports whether a document was actually read for this row.
func (e Edition) Checked() bool { return e.Document != "" && e.Verified != "" }

// AgeDays is how long ago the document was read. Negative means never.
func (e Edition) AgeDays(now time.Time) int {
	if e.Verified == "" {
		return -1
	}
	t, err := time.Parse("2006-01-02", e.Verified)
	if err != nil {
		return -1
	}
	return int(now.Sub(t).Hours() / 24)
}

// Provenance is the one-line audit trail for a report appendix.
//
// Reading the standard and reconciling our identifiers against it are two
// different claims, and only the first is true for a row with no Version. Saying
// "verified against v7.0.0" for the CIS rows would assert the reconciliation
// that has not happened, which is the whole failure this registry exists to
// stop.
func (e Edition) Provenance(now time.Time) string {
	if !e.Checked() {
		return fmt.Sprintf("%s: asserted, not verified against the published standard", e.Framework)
	}
	age := plural(e.AgeDays(now), "day", "days")
	if e.Version == "" {
		return fmt.Sprintf("%s: %s read on %s (%s ago); our control identifiers are not "+
			"reconciled to it", e.Framework, e.Document, e.Verified, age)
	}
	return fmt.Sprintf("%s: verified against %s on %s (%s ago)",
		e.Framework, e.Document, e.Verified, age)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
