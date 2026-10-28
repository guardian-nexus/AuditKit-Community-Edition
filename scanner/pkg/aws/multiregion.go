package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// globalSuites read services that are not regional - IAM, S3's bucket list,
// Organizations, Route 53 - or make no API call at all. In a multi-region
// scan they run once, in the first region; every other suite runs per region.
// Keyed on Check.Name().
var globalSuites = map[string]bool{
	"IAM Security Configuration":               true,
	"IAM Advanced Security":                    true,
	"IAM Extended Security Configuration":      true,
	"S3 Bucket Security":                       true,
	"AWS Organizations Advanced Configuration": true,
	"Route53 DNS Security":                     true,
	"CIS Manual Controls":                      true,
}

// Config returns the configuration the scanner's clients were built from.
func (s *AWSScanner) Config() aws.Config {
	return s.cfg
}

// EnabledRegions lists the regions the account can use, via EC2
// DescribeRegions in the configured region. Opted-out regions are excluded.
func EnabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	out, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, fmt.Errorf("listing enabled regions: %w", err)
	}
	var regions []string
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, *r.RegionName)
		}
	}
	sort.Strings(regions)
	return regions, nil
}

// ResolveRegions turns the -regions flag into a list: "" means the single
// configured region (nil), "all" means every enabled region, anything else is
// a comma-separated list. The configured region, when it is in the list, goes
// first so the global suites run there.
func ResolveRegions(ctx context.Context, cfg aws.Config, spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var regions []string
	if strings.EqualFold(spec, "all") {
		var err error
		if regions, err = EnabledRegions(ctx, cfg); err != nil {
			return nil, err
		}
	} else {
		seen := map[string]bool{}
		for _, r := range strings.Split(spec, ",") {
			r = strings.TrimSpace(r)
			if r != "" && !seen[r] {
				seen[r] = true
				regions = append(regions, r)
			}
		}
	}
	if len(regions) == 0 {
		return nil, fmt.Errorf("no regions to scan from %q", spec)
	}
	for i, r := range regions {
		if r == cfg.Region && i > 0 {
			regions = append([]string{r}, append(regions[:i:i], regions[i+1:]...)...)
			break
		}
	}
	return regions, nil
}

// ScanRegions runs the scan in every listed region and merges the results per
// control. Global suites run in the first region only. A region whose scan
// could not start is reported in err and left out of scanned; the rows that
// are returned then cover only the regions in scanned, which the caller
// states in the report.
func ScanRegions(ctx context.Context, cfg aws.Config, regions []string, services []string, verbose bool, framework string) (results []ScanResult, scanned []string, err error) {
	perRegion := map[string][]ScanResult{}
	var failures []string
	for i, region := range regions {
		rcfg := cfg.Copy()
		rcfg.Region = region
		s, serr := NewScannerWithConfig(rcfg)
		if serr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", region, serr))
			continue
		}
		s.multiRegion = true
		s.skipGlobal = i > 0
		if verbose {
			fmt.Printf("Region %s (%d of %d)\n", region, i+1, len(regions))
		}
		rows, serr := s.ScanServices(ctx, services, verbose, framework)
		if serr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", region, serr))
			continue
		}
		perRegion[region] = rows
		scanned = append(scanned, region)
	}
	if len(failures) > 0 {
		err = fmt.Errorf("%d region(s) could not be scanned: %s", len(failures), strings.Join(failures, "; "))
	}
	return mergeRegions(perRegion, scanned), scanned, err
}

// statusRank orders verdicts for a merge: a failure anywhere is the control's
// verdict, a region that could not be read beats a pass, and a pass beats the
// informational rows a region with nothing to evaluate emits.
var statusRank = map[string]int{"FAIL": 5, "ERROR": 4, "PASS": 3, "MANUAL": 2, "INFO": 1}

// mergeRegions folds per-region rows into one row per control. A row that is
// identical in every region (the global suites, or a uniform regional
// configuration) is kept as it is. Rows that differ are merged under the
// strongest status, with the evidence naming which regions said what.
func mergeRegions(perRegion map[string][]ScanResult, order []string) []ScanResult {
	type key struct{ control, name string }
	rowsByKey := map[key]map[string][]ScanResult{}
	var keys []key
	for _, region := range order {
		for _, r := range perRegion[region] {
			k := key{r.Control, r.Name}
			if rowsByKey[k] == nil {
				rowsByKey[k] = map[string][]ScanResult{}
				keys = append(keys, k)
			}
			rowsByKey[k][region] = append(rowsByKey[k][region], r)
		}
	}

	var out []ScanResult
	for _, k := range keys {
		byRegion := rowsByKey[k]
		// A suite that emits several rows under one control (one per resource)
		// is not merged; each row says which region it came from.
		multi := false
		for _, rows := range byRegion {
			if len(rows) > 1 {
				multi = true
			}
		}
		if multi {
			for _, region := range order {
				for _, r := range byRegion[region] {
					r.Evidence = region + ": " + r.Evidence
					out = append(out, r)
				}
			}
			continue
		}

		// Group the regions by what they said.
		type verdict struct{ status, evidence string }
		regionsBy := map[verdict][]string{}
		var verdicts []verdict
		first := ScanResult{}
		for _, region := range order {
			rows, ok := byRegion[region]
			if !ok {
				continue
			}
			r := rows[0]
			if first.Control == "" {
				first = r
			}
			v := verdict{r.Status, r.Evidence}
			if _, seen := regionsBy[v]; !seen {
				verdicts = append(verdicts, v)
			}
			regionsBy[v] = append(regionsBy[v], region)
		}
		if len(verdicts) == 1 {
			out = append(out, first)
			continue
		}
		sort.SliceStable(verdicts, func(i, j int) bool { return statusRank[verdicts[i].status] > statusRank[verdicts[j].status] })
		winner := verdicts[0]
		merged := first
		for _, region := range order {
			for _, r := range byRegion[region] {
				if r.Status == winner.status && r.Evidence == winner.evidence {
					merged = r
				}
			}
		}
		var parts []string
		for _, v := range verdicts {
			parts = append(parts, fmt.Sprintf("%s in %s: %s", v.status, strings.Join(regionsBy[v], ", "), v.evidence))
		}
		merged.Status = winner.status
		merged.Evidence = strings.Join(parts, " | ")
		out = append(out, merged)
	}
	return out
}
