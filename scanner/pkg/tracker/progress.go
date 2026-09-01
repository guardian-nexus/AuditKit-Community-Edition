package tracker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ControlResult struct {
	Control string
	Name    string
	Status  string
}

type ProgressData struct {
	AccountID    string          `json:"account_id"`
	LastScan     time.Time       `json:"last_scan"`
	FirstScan    time.Time       `json:"first_scan"`
	ScanCount    int             `json:"scan_count"`
	ScoreHistory []ScorePoint    `json:"score_history"`
	FixedIssues  map[string]bool `json:"fixed_issues"`
}

type ScorePoint struct {
	Date  time.Time `json:"date"`
	Score float64   `json:"score"`
}

func SaveProgress(accountID string, score float64, controls []ControlResult) error {
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")

	// Create directory
	os.MkdirAll(filepath.Dir(dataPath), 0755)

	// Load existing or create new
	var progress ProgressData
	if data, err := os.ReadFile(dataPath); err == nil {
		json.Unmarshal(data, &progress)
	} else {
		progress = ProgressData{
			AccountID:    accountID,
			FirstScan:    time.Now(),
			FixedIssues:  make(map[string]bool),
			ScoreHistory: []ScorePoint{},
		}
	}

	// Update progress
	progress.LastScan = time.Now()
	progress.ScanCount++
	progress.ScoreHistory = append(progress.ScoreHistory, ScorePoint{
		Date:  time.Now(),
		Score: score,
	})

	// Track what's been fixed
	for _, control := range controls {
		if control.Status == "PASS" {
			progress.FixedIssues[control.Control] = true
		}
	}

	// Save
	data, _ := json.MarshalIndent(progress, "", "  ")
	return os.WriteFile(dataPath, data, 0644)
}

func ShowProgress(accountID string) {
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")

	data, err := os.ReadFile(dataPath)
	if err != nil {
		fmt.Println("No previous scans found. Run 'auditkit scan' first!")
		return
	}

	var progress ProgressData
	json.Unmarshal(data, &progress)

	fmt.Println("\n📊 Your SOC2 Journey Progress")
	fmt.Println("==============================")
	fmt.Printf("Account: %s\n", progress.AccountID)
	fmt.Printf("First scan: %s\n", progress.FirstScan.Format("Jan 2, 2006"))
	fmt.Printf("Total scans: %d\n", progress.ScanCount)
	fmt.Printf("Issues fixed: %d\n", len(progress.FixedIssues))

	if len(progress.ScoreHistory) > 1 {
		first := progress.ScoreHistory[0].Score
		last := progress.ScoreHistory[len(progress.ScoreHistory)-1].Score
		improvement := last - first

		if improvement > 0 {
			fmt.Printf("Score improvement: +%.1f%% (%.1f%% → %.1f%%)\n", improvement, first, last)
		}

		// Show trend
		fmt.Println("\nScore Trend:")
		for _, point := range progress.ScoreHistory[max(0, len(progress.ScoreHistory)-5):] {
			bars := int(point.Score / 5)
			fmt.Printf("%s: %s %.1f%%\n",
				point.Date.Format("Jan 02"),
				strings.Repeat("█", bars),
				point.Score)
		}
	}

	fmt.Println("\n Tip: Run 'auditkit scan -format pdf' to generate evidence for your auditor")
}
