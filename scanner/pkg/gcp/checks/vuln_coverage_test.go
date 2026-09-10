package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/osconfig/v1"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/gcposconfig"
)

type stubReports struct {
	reports []*osconfig.VulnerabilityReport
	err     error
}

func (s stubReports) List(context.Context, string, string) (*osconfig.ListVulnerabilityReportsResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &osconfig.ListVulnerabilityReportsResponse{VulnerabilityReports: s.reports}, nil
}

type stubInstances struct{ names []string }

func (s stubInstances) AggregatedList(context.Context, string, string) (*compute.InstanceAggregatedList, error) {
	var out []*compute.Instance
	for _, n := range s.names {
		out = append(out, &compute.Instance{Name: n, Status: "RUNNING"})
	}
	return &compute.InstanceAggregatedList{
		Items: map[string]compute.InstancesScopedList{"z": {Instances: out}},
	}, nil
}

func run(t *testing.T, clients gcposconfig.Clients, emit Emit) []CheckResult {
	t.Helper()
	res, err := newWithClients(clients, "proj", emit, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	return res
}

// The two passes must not report each other's control, or a scan of every
// framework counts the same control twice in the score.
func TestEmitSelectsDisjointControls(t *testing.T) {
	clients := gcposconfig.Clients{
		Reports:   stubReports{reports: []*osconfig.VulnerabilityReport{{Name: "projects/p/locations/l/instances/vm-1/vulnerabilityReport", UpdateTime: time.Now().Format(time.RFC3339)}}},
		Instances: stubInstances{names: []string{"vm-1"}},
	}

	cmmc := map[string]bool{}
	for _, r := range run(t, clients, EmitCMMC) {
		cmmc[r.Control] = true
	}
	pci := map[string]bool{}
	for _, r := range run(t, clients, EmitPCI) {
		pci[r.Control] = true
	}

	if !cmmc["RA.L2-3.11.2"] {
		t.Errorf("the CMMC pass must answer RA.L2-3.11.2, got %v", cmmc)
	}
	if !pci["PCI-11.3.1"] {
		t.Errorf("the PCI pass must answer PCI-11.3.1, got %v", pci)
	}
	for c := range cmmc {
		if pci[c] {
			t.Errorf("%s is reported by both passes and would be double-counted", c)
		}
	}
}

// Every result must carry a framework tag, or the framework filter drops it and
// the check becomes invisible work.
func TestEveryResultIsFrameworkTagged(t *testing.T) {
	clients := gcposconfig.Clients{
		Reports:   stubReports{},
		Instances: stubInstances{names: []string{"vm-1"}},
	}
	for _, emit := range []Emit{EmitCMMC, EmitPCI} {
		for _, r := range run(t, clients, emit) {
			if len(r.Frameworks) == 0 {
				t.Errorf("%s carries no framework mapping", r.Control)
			}
			if r.Control == "" || r.Name == "" {
				t.Errorf("a result needs an id and a name, got %+v", r)
			}
			if r.Status != StatusPass && r.Status != StatusFail &&
				r.Status != StatusInfo && r.Status != StatusError {
				t.Errorf("%s has an unrecognised status %q", r.Control, r.Status)
			}
		}
	}
}

func TestUncoveredInstanceFailsTheControl(t *testing.T) {
	clients := gcposconfig.Clients{
		Reports:   stubReports{}, // VM Manager answered, but no reports exist
		Instances: stubInstances{names: []string{"vm-no-agent"}},
	}
	res := run(t, clients, EmitCMMC)
	var scanning CheckResult
	for _, r := range res {
		if r.Control == "RA.L2-3.11.2" {
			scanning = r
		}
	}
	if scanning.Status != StatusFail {
		t.Fatalf("an instance nothing is scanning must fail RA.L2-3.11.2, got %s: %s",
			scanning.Status, scanning.Evidence)
	}
	if scanning.ConsoleURL == "" || scanning.ScreenshotGuide == "" {
		t.Error("a failing control needs a console link and evidence guidance")
	}
}

// A read that did not complete must never produce a pass.
func TestCollectionFailureIsAnError(t *testing.T) {
	clients := gcposconfig.Clients{Reports: stubReports{err: errors.New("SERVICE_DISABLED")}}
	for _, emit := range []Emit{EmitCMMC, EmitPCI} {
		for _, r := range run(t, clients, emit) {
			if r.Status != StatusError {
				t.Errorf("%s should be ERROR when the read failed, got %s", r.Control, r.Status)
			}
		}
	}
}

func TestClientInitFailureIsAnErrorWithTheRightControl(t *testing.T) {
	c := newWithClients(gcposconfig.Clients{}, "proj", EmitPCI, errors.New("no credentials"))
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	if len(res) != 1 || res[0].Control != "PCI-11.3.1" || res[0].Status != StatusError {
		t.Fatalf("want one PCI-11.3.1 ERROR, got %+v", res)
	}
	if !strings.Contains(res[0].Evidence, "no credentials") {
		t.Errorf("the underlying cause should be reported: %s", res[0].Evidence)
	}
	if !strings.Contains(res[0].Remediation, "osconfig") {
		t.Errorf("the remediation should name the permissions needed: %s", res[0].Remediation)
	}
}
