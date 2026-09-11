package providers

import (
	"context"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/core"
)

// BaseProvider provides common functionality for all providers
type BaseProvider struct {
	name      string
	accountID string
}

// NewBaseProvider creates a new base provider
func NewBaseProvider(name string) *BaseProvider {
	return &BaseProvider{
		name: name,
	}
}

// Name returns the provider name
func (p *BaseProvider) Name() string {
	return p.name
}

// SetAccountID sets the account identifier
func (p *BaseProvider) SetAccountID(id string) {
	p.accountID = id
}

// GetAccountID returns the account identifier
func (p *BaseProvider) GetAccountID(ctx context.Context) string {
	return p.accountID
}

// Close is a no-op for most providers
func (p *BaseProvider) Close() error {
	return nil
}

// ProviderRegistry manages available providers
type ProviderRegistry struct {
	providers map[string]core.Provider
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]core.Provider),
	}
}

// Register adds a provider to the registry
func (r *ProviderRegistry) Register(provider core.Provider) {
	r.providers[provider.Name()] = provider
}

// Get retrieves a provider by name
func (r *ProviderRegistry) Get(name string) (core.Provider, bool) {
	provider, exists := r.providers[name]
	return provider, exists
}

// List returns all registered provider names
func (r *ProviderRegistry) List() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
