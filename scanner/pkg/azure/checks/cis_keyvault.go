package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
)

// CISKeyVaultChecks answers the Key Vault object recommendations in CIS
// Microsoft Azure Foundations v6.0.0 section 8.3 that need the keys and secrets
// themselves rather than the vault.
//
// The editions pin different armkeyvault versions - Community v1.4.0, Pro
// v1.5.0 - so this file uses only fields present in both. That is the same
// trap the inspector2 collector documents: a constant that exists in one
// version does not compile in the other, and the file is meant to stay
// portable between the editions.
//
// One asymmetry in the SDK worth naming, because it is easy to write the same
// code twice and get one wrong: a key's expiry is Unix seconds (*int64) and a
// secret's is a *time.Time.
type CISKeyVaultChecks struct {
	vaults  *armkeyvault.VaultsClient
	keys    *armkeyvault.KeysClient
	secrets *armkeyvault.SecretsClient
}

func NewCISKeyVaultChecks(vaults *armkeyvault.VaultsClient, keys *armkeyvault.KeysClient,
	secrets *armkeyvault.SecretsClient) *CISKeyVaultChecks {
	return &CISKeyVaultChecks{vaults: vaults, keys: keys, secrets: secrets}
}

func (c *CISKeyVaultChecks) Name() string { return "CIS Azure Key Vault Objects" }

const keyVaultConsole = "https://portal.azure.com/#browse/Microsoft.KeyVault%2Fvaults"

// vault is one vault plus the one property that decides which recommendations
// apply to it: 8.3.1/8.3.3 are the RBAC variants and 8.3.2/8.3.4 the legacy
// access-policy ones, so the same vault must not be judged by both.
type vault struct {
	name, group string
	rbac        bool
}

func (c *CISKeyVaultChecks) gatherVaults(ctx context.Context) ([]vault, error) {
	if c.vaults == nil {
		return nil, fmt.Errorf("key vaults client not configured")
	}
	var out []vault
	pager := c.vaults.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			if v == nil || v.Name == nil {
				continue
			}
			rbac := v.Properties != nil && v.Properties.EnableRbacAuthorization != nil &&
				*v.Properties.EnableRbacAuthorization
			out = append(out, vault{
				name:  *v.Name,
				group: resourceGroupOf(deref(v.ID)),
				rbac:  rbac,
			})
		}
	}
	return out, nil
}

func (c *CISKeyVaultChecks) Run(ctx context.Context) ([]CheckResult, error) {
	return []CheckResult{
		c.legacyKeyExpiry(ctx),
		c.legacySecretExpiry(ctx),
		c.automaticKeyRotation(ctx),
		c.certificateValidityPeriod(),
	}, nil
}

func (c *CISKeyVaultChecks) legacyKeyExpiry(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.3.2",
		Name:        "Key Expiry Set on Access-Policy Key Vaults",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Set an expiry date on every enabled key in the vaults still using access policies",
		RemediationDetail: `az keyvault key set-attributes \
  --vault-name <vault> --name <key> --expires <yyyy-mm-ddTHH:MM:SSZ>

A key with no expiry never forces a rotation, so a compromise has no end date.
This is the access-policy half of the recommendation; vaults on RBAC are
covered by 8.3.1.`,
		ScreenshotGuide: "Key vaults -> each vault using access policies -> Objects -> Keys -> Screenshot the expiration date column",
		ConsoleURL:      keyVaultConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.3.2", "SOC2": "CC6.1", "PCI-DSS": "3.7.4"},
	}
	if c.keys == nil {
		base.Status = StatusError
		base.Evidence = "Key Vault keys client not configured"
		return base
	}
	vaults, err := c.gatherVaults(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list key vaults: %v", err)
		return base
	}
	legacy := legacyVaults(vaults)
	if len(legacy) == 0 {
		base.Status = StatusPass
		base.Priority = PriorityInfo
		base.Evidence = fmt.Sprintf("None of the %d key vault(s) use access policies; 8.3.1 covers the RBAC vaults", len(vaults))
		return base
	}
	offenders, total := []string{}, 0
	for _, v := range legacy {
		pager := c.keys.NewListPager(v.group, v.name, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, k := range page.Value {
				if k == nil || k.Properties == nil || k.Properties.Attributes == nil {
					continue
				}
				// A disabled key cannot be used, so the benchmark asks only
				// about enabled ones.
				if k.Properties.Attributes.Enabled != nil && !*k.Properties.Attributes.Enabled {
					continue
				}
				total++
				if k.Properties.Attributes.Expires == nil {
					offenders = append(offenders, fmt.Sprintf("%s/%s", v.name, deref(k.Name)))
				}
			}
		}
	}
	return netVerdict(base, "enabled key(s) in access-policy vaults", offenders, total)
}

func (c *CISKeyVaultChecks) legacySecretExpiry(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.3.4",
		Name:        "Secret Expiry Set on Access-Policy Key Vaults",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Set an expiry date on every enabled secret in the vaults still using access policies",
		RemediationDetail: `az keyvault secret set-attributes \
  --vault-name <vault> --name <secret> --expires <yyyy-mm-ddTHH:MM:SSZ>

This is the access-policy half of the recommendation; vaults on RBAC are
covered by 8.3.3.`,
		ScreenshotGuide: "Key vaults -> each vault using access policies -> Objects -> Secrets -> Screenshot the expiration date column",
		ConsoleURL:      keyVaultConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.3.4", "SOC2": "CC6.1", "PCI-DSS": "3.7.4"},
	}
	if c.secrets == nil {
		base.Status = StatusError
		base.Evidence = "Key Vault secrets client not configured"
		return base
	}
	vaults, err := c.gatherVaults(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list key vaults: %v", err)
		return base
	}
	legacy := legacyVaults(vaults)
	if len(legacy) == 0 {
		base.Status = StatusPass
		base.Priority = PriorityInfo
		base.Evidence = fmt.Sprintf("None of the %d key vault(s) use access policies; 8.3.3 covers the RBAC vaults", len(vaults))
		return base
	}
	offenders, total := []string{}, 0
	for _, v := range legacy {
		pager := c.secrets.NewListPager(v.group, v.name, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, s := range page.Value {
				if s == nil || s.Properties == nil || s.Properties.Attributes == nil {
					continue
				}
				if s.Properties.Attributes.Enabled != nil && !*s.Properties.Attributes.Enabled {
					continue
				}
				total++
				// A secret's expiry is a *time.Time here, not the Unix seconds
				// a key's expiry uses.
				if s.Properties.Attributes.Expires == nil {
					offenders = append(offenders, fmt.Sprintf("%s/%s", v.name, deref(s.Name)))
				}
			}
		}
	}
	return netVerdict(base, "enabled secret(s) in access-policy vaults", offenders, total)
}

// legacyVaults are the ones still on access policies. The RBAC vaults are a
// different recommendation, and judging a vault by both would report the same
// estate twice under two identifiers.
func legacyVaults(all []vault) []vault {
	var out []vault
	for _, v := range all {
		if !v.rbac && v.group != "" {
			out = append(out, v)
		}
	}
	return out
}

func (c *CISKeyVaultChecks) automaticKeyRotation(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.3.9",
		Name:        "Automatic Key Rotation Enabled",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Attach a rotation policy with a rotate action to every key",
		RemediationDetail: `az keyvault key rotation-policy update \
  --vault-name <vault> --name <key> --value <policy.json>

Where policy.json sets a lifetimeAction of type rotate with a timeAfterCreate
matching your rotation period. A policy carrying only a notify action warns
somebody and rotates nothing, so it does not satisfy this.`,
		ScreenshotGuide: "Key vaults -> each vault -> Objects -> Keys -> each key -> Rotation policy -> Screenshot auto rotation enabled and the rotation time",
		ConsoleURL:      keyVaultConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.3.9", "SOC2": "CC6.1", "PCI-DSS": "3.7.4"},
	}
	if c.keys == nil {
		base.Status = StatusError
		base.Evidence = "Key Vault keys client not configured"
		return base
	}
	vaults, err := c.gatherVaults(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list key vaults: %v", err)
		return base
	}
	offenders, total := []string{}, 0
	for _, v := range vaults {
		if v.group == "" {
			continue
		}
		pager := c.keys.NewListPager(v.group, v.name, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, k := range page.Value {
				if k == nil || k.Properties == nil {
					continue
				}
				if k.Properties.Attributes != nil && k.Properties.Attributes.Enabled != nil &&
					!*k.Properties.Attributes.Enabled {
					continue
				}
				total++
				if !rotatesAutomatically(k.Properties.RotationPolicy) {
					offenders = append(offenders, fmt.Sprintf("%s/%s", v.name, deref(k.Name)))
				}
			}
		}
	}
	return netVerdict(base, "enabled key(s)", offenders, total)
}

// rotatesAutomatically requires a lifetime action that actually rotates. A
// policy whose only action is "notify" tells somebody the key is old and
// changes nothing, which is the configuration most likely to be mistaken for
// compliance.
func rotatesAutomatically(p *armkeyvault.RotationPolicy) bool {
	if p == nil {
		return false
	}
	for _, a := range p.LifetimeActions {
		if a == nil || a.Action == nil || a.Action.Type == nil {
			continue
		}
		if *a.Action.Type == armkeyvault.KeyRotationPolicyActionTypeRotate {
			return true
		}
	}
	return false
}

func (c *CISKeyVaultChecks) certificateValidityPeriod() CheckResult {
	// A certificate's issuance policy lives on the Key Vault data plane, which
	// is reached at the vault's own hostname rather than through Azure
	// Resource Manager. The management SDK has no certificates client at all,
	// so there is nothing here to read - and a PASS asserted from that would
	// be exactly the defect this codebase keeps finding.
	return CheckResult{
		Control:     "CIS-8.3.11",
		Name:        "Certificate Validity Period at Most 12 Months",
		Status:      StatusManual,
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK: Confirm each certificate's issuance policy sets a validity period of 12 months or less. The issuance policy is only exposed on the Key Vault data plane, which this scanner does not reach",
		Remediation: "Set the validity period to 12 months or less on each certificate's issuance policy, then reissue",
		RemediationDetail: `az keyvault certificate get-default-policy > policy.json
# edit validity_in_months to 12 or less, then
az keyvault certificate create --vault-name <vault> --name <cert> --policy @policy.json

A longer validity means a compromised certificate stays trusted longer, and
reissuing it is the only revocation most clients honour.`,
		ScreenshotGuide: "Key vaults -> each vault -> Objects -> Certificates -> each certificate -> Issuance Policy -> Screenshot the validity period in months",
		ConsoleURL:      keyVaultConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.3.11", "SOC2": "CC6.1"},
	}
}
