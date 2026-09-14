package report

import (
	"fmt"
	"strings"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
)

// scopeNote is the sentence a partial framework's report must carry. The CLI
// prints the caveat beside the score, but the PDF and HTML are what reach an
// assessor, and they said nothing: a GDPR report presented its obligations as
// though they were the Regulation.
func scopeNote(framework string) string {
	caveat, partial := mappings.PartialCatalogNote(framework)
	if !partial {
		return ""
	}
	return fmt.Sprintf("Scope: coverage for %s is incomplete - %s. This report is evidence toward "+
		"the framework's technical requirements; it is not legal advice and does not establish compliance.",
		strings.ToUpper(strings.TrimSpace(framework)), caveat)
}
