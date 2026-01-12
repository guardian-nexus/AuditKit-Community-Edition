package offline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CachedScan represents a cached scan result
type CachedScan struct {
	Timestamp       time.Time         `json:"timestamp"`
	Provider        string            `json:"provider"`
	Framework       string            `json:"framework"`
	AccountID       string            `json:"account_id"`
	Score           float64           `json:"score"`
	TotalControls   int               `json:"total_controls"`
	PassedControls  int               `json:"passed_controls"`
	FailedControls  int               `json:"failed_controls"`
	Controls        []CachedControl   `json:"controls"`
	Recommendations []string          `json:"recommendations"`
	Version         string            `json:"version"`
}

// CachedControl represents a cached control result
type CachedControl struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	Severity          string            `json:"severity,omitempty"`
	Status            string            `json:"status"`
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Priority          string            `json:"priority,omitempty"`
	Impact            string            `json:"impact,omitempty"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

// Cache manages offline scan data
type Cache struct {
	basePath string
}

// NewCache creates a new cache manager
func NewCache() (*Cache, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	basePath := filepath.Join(homeDir, ".auditkit", "cache")
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &Cache{basePath: basePath}, nil
}

// GetCachePath returns the path to the cache directory
func (c *Cache) GetCachePath() string {
	return c.basePath
}

// Save stores a scan result to cache
func (c *Cache) Save(scan CachedScan) error {
	filename := c.getScanFilename(scan.Provider, scan.AccountID, scan.Framework, scan.Timestamp)
	scanPath := filepath.Join(c.basePath, filename)

	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan data: %w", err)
	}

	if err := os.WriteFile(scanPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	// Also update the "latest" symlink/copy
	latestPath := filepath.Join(c.basePath, c.getLatestFilename(scan.Provider, scan.AccountID, scan.Framework))
	if err := os.WriteFile(latestPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write latest cache file: %w", err)
	}

	return nil
}

// LoadLatest loads the most recent scan for a provider/account/framework
func (c *Cache) LoadLatest(provider, accountID, framework string) (*CachedScan, error) {
	latestPath := filepath.Join(c.basePath, c.getLatestFilename(provider, accountID, framework))
	return c.loadFromFile(latestPath)
}

// LoadByTimestamp loads a specific scan by timestamp
func (c *Cache) LoadByTimestamp(provider, accountID, framework string, timestamp time.Time) (*CachedScan, error) {
	filename := c.getScanFilename(provider, accountID, framework, timestamp)
	scanPath := filepath.Join(c.basePath, filename)
	return c.loadFromFile(scanPath)
}

// LoadFromFile loads a scan from a specific file path
func (c *Cache) LoadFromFile(filePath string) (*CachedScan, error) {
	return c.loadFromFile(filePath)
}

func (c *Cache) loadFromFile(filePath string) (*CachedScan, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no cached scan found at %s", filePath)
		}
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	var scan CachedScan
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, fmt.Errorf("failed to parse cache file: %w", err)
	}

	return &scan, nil
}

// ListScans returns all cached scans matching the criteria
func (c *Cache) ListScans(provider, accountID, framework string) ([]CachedScan, error) {
	pattern := fmt.Sprintf("scan-%s-%s-%s-*.json", provider, accountID, framework)
	matches, err := filepath.Glob(filepath.Join(c.basePath, pattern))
	if err != nil {
		return nil, fmt.Errorf("failed to list cache files: %w", err)
	}

	scans := []CachedScan{}
	for _, match := range matches {
		scan, err := c.loadFromFile(match)
		if err != nil {
			continue
		}
		scans = append(scans, *scan)
	}

	return scans, nil
}

// HasCachedScan checks if a cached scan exists
func (c *Cache) HasCachedScan(provider, accountID, framework string) bool {
	latestPath := filepath.Join(c.basePath, c.getLatestFilename(provider, accountID, framework))
	_, err := os.Stat(latestPath)
	return err == nil
}

// GetCacheInfo returns information about cached data
func (c *Cache) GetCacheInfo() (map[string]interface{}, error) {
	entries, err := os.ReadDir(c.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %w", err)
	}

	info := map[string]interface{}{
		"cache_path":  c.basePath,
		"total_files": len(entries),
		"scans":       []map[string]interface{}{},
	}

	scans := []map[string]interface{}{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if entry.Name()[:6] == "latest" {
			continue
		}

		fileInfo, _ := entry.Info()
		scan, err := c.loadFromFile(filepath.Join(c.basePath, entry.Name()))
		if err != nil {
			continue
		}

		scans = append(scans, map[string]interface{}{
			"filename":  entry.Name(),
			"provider":  scan.Provider,
			"framework": scan.Framework,
			"account":   scan.AccountID,
			"timestamp": scan.Timestamp,
			"score":     scan.Score,
			"size":      fileInfo.Size(),
		})
	}

	info["scans"] = scans
	return info, nil
}

// Clear removes all cached scans
func (c *Cache) Clear() error {
	entries, err := os.ReadDir(c.basePath)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(c.basePath, entry.Name())); err != nil {
			return fmt.Errorf("failed to remove %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// ClearOlderThan removes cached scans older than the specified duration
func (c *Cache) ClearOlderThan(duration time.Duration) (int, error) {
	entries, err := os.ReadDir(c.basePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read cache directory: %w", err)
	}

	cutoff := time.Now().Add(-duration)
	removed := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if entry.Name()[:6] == "latest" {
			continue
		}

		scan, err := c.loadFromFile(filepath.Join(c.basePath, entry.Name()))
		if err != nil {
			continue
		}

		if scan.Timestamp.Before(cutoff) {
			if err := os.Remove(filepath.Join(c.basePath, entry.Name())); err == nil {
				removed++
			}
		}
	}

	return removed, nil
}

func (c *Cache) getScanFilename(provider, accountID, framework string, timestamp time.Time) string {
	return fmt.Sprintf("scan-%s-%s-%s-%s.json",
		provider,
		accountID,
		framework,
		timestamp.Format("20060102-150405"))
}

func (c *Cache) getLatestFilename(provider, accountID, framework string) string {
	return fmt.Sprintf("latest-%s-%s-%s.json", provider, accountID, framework)
}

// IsOfflineModeAvailable checks if offline mode can be used
func IsOfflineModeAvailable(provider, accountID, framework string) bool {
	cache, err := NewCache()
	if err != nil {
		return false
	}
	return cache.HasCachedScan(provider, accountID, framework)
}

// GetOfflineScanAge returns how old the cached scan is
func GetOfflineScanAge(provider, accountID, framework string) (time.Duration, error) {
	cache, err := NewCache()
	if err != nil {
		return 0, err
	}

	scan, err := cache.LoadLatest(provider, accountID, framework)
	if err != nil {
		return 0, err
	}

	return time.Since(scan.Timestamp), nil
}
