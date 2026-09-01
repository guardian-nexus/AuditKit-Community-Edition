package tracker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type EvidenceItem struct {
	ControlID         string     `json:"control_id"`
	ControlName       string     `json:"control_name"`
	Status            string     `json:"status"`
	EvidenceCollected bool       `json:"evidence_collected"`
	CollectedDate     *time.Time `json:"collected_date,omitempty"`
	Notes             string     `json:"notes,omitempty"`
	ScreenshotPath    string     `json:"screenshot_path,omitempty"`
	CollectedBy       string     `json:"collected_by,omitempty"`
	// Required is false once a control stops appearing in scans. The item is
	// kept rather than deleted, because evidence already collected for it
	// remains part of the audit trail for the period it covered.
	Required bool `json:"required"`
}

type EvidenceTracker struct {
	AccountID     string                  `json:"account_id"`
	LastScan      time.Time               `json:"last_scan"`
	LastUpdate    time.Time               `json:"last_update"`
	Controls      map[string]EvidenceItem `json:"controls"`
	TotalControls int                     `json:"total_controls"`
	Collected     int                     `json:"collected"`
	FilePath      string                  `json:"-"`
}

// NewTracker creates or loads an existing evidence tracker
func NewTracker(accountID string) (*EvidenceTracker, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Create .auditkit directory if it doesn't exist
	configDir := filepath.Join(homeDir, ".auditkit")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, err
	}

	filePath := filepath.Join(configDir, fmt.Sprintf("evidence_%s.json", accountID))

	tracker := &EvidenceTracker{
		AccountID: accountID,
		Controls:  make(map[string]EvidenceItem),
		FilePath:  filePath,
	}

	// Try to load existing file
	if data, err := os.ReadFile(filePath); err == nil {
		if err := json.Unmarshal(data, tracker); err != nil {
			// If corrupt, start fresh
			tracker.Controls = make(map[string]EvidenceItem)
		}
	}

	return tracker, nil
}

// UpdateControl updates the status of a control
func (t *EvidenceTracker) UpdateControl(controlID, name, status string) {
	item, exists := t.Controls[controlID]
	if !exists {
		item = EvidenceItem{
			ControlID:   controlID,
			ControlName: name,
		}
	}

	item.Status = status
	t.Controls[controlID] = item
	t.LastUpdate = time.Now()
}

// MarkEvidenceCollected marks a control as having evidence collected
func (t *EvidenceTracker) MarkEvidenceCollected(controlID string, notes string) error {
	item, exists := t.Controls[controlID]
	if !exists {
		return fmt.Errorf("control %s not found", controlID)
	}

	now := time.Now()
	item.EvidenceCollected = true
	item.CollectedDate = &now
	item.Notes = notes

	t.Controls[controlID] = item
	t.Collected = t.countCollected()
	t.LastUpdate = now

	return t.Save()
}

// GetProgress returns current evidence collection progress
func (t *EvidenceTracker) GetProgress() (int, int) {
	total := len(t.Controls)
	collected := t.countCollected()
	return collected, total
}

func (t *EvidenceTracker) countCollected() int {
	count := 0
	for _, item := range t.Controls {
		if item.EvidenceCollected {
			count++
		}
	}
	return count
}

// Save persists the tracker to disk
func (t *EvidenceTracker) Save() error {
	t.TotalControls = len(t.Controls)
	t.Collected = t.countCollected()

	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(t.FilePath, data, 0644)
}

// GenerateChecklistHTML creates an interactive HTML checklist
func (t *EvidenceTracker) GenerateChecklistHTML(outputPath string) error {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>AuditKit Evidence Collection Tracker</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 40px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-width: 900px;
            margin: 0 auto;
        }
        h1 { color: #0366d6; }
        .progress {
            background: #e1e4e8;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }
        .progress-bar {
            background: #28a745;
            height: 100%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        .control {
            padding: 15px;
            margin: 10px 0;
            border: 1px solid #e1e4e8;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .control.pass { border-left: 4px solid #28a745; }
        .control.fail { border-left: 4px solid #dc3545; }
        .control.collected { background: #d4f4dd; }
        input[type="checkbox"] {
            width: 20px;
            height: 20px;
            cursor: pointer;
        }
        .control-info { flex: 1; }
        .control-id { font-weight: bold; color: #0366d6; }
        .control-name { color: #586069; }
        .notes {
            width: 100%;
            padding: 5px;
            margin-top: 5px;
            border: 1px solid #e1e4e8;
            border-radius: 3px;
            display: none;
        }
        .control.collected .notes { display: block; }
        button {
            background: #0366d6;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover { background: #0256c7; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📸 Evidence Collection Tracker</h1>
        <p>AWS Account: ` + t.AccountID + `</p>
        <p>Last Scan: ` + t.LastScan.Format("January 2, 2006 at 3:04 PM") + `</p>
        
        <div class="progress">
            <div class="progress-bar" id="progress-bar" style="width: ` + fmt.Sprintf("%.0f", float64(t.Collected)/float64(t.TotalControls)*100) + `%">
                ` + fmt.Sprintf("%d/%d Collected", t.Collected, t.TotalControls) + `
            </div>
        </div>
        
        <h2>Controls Checklist</h2>
        <div id="controls">`

	// Add each control
	for id, control := range t.Controls {
		checked := ""
		collected := ""
		statusClass := "fail"

		if control.Status == "PASS" {
			statusClass = "pass"
		}

		if control.EvidenceCollected {
			checked = "checked"
			collected = "collected"
		}

		notes := control.Notes
		if notes == "" {
			notes = "Add notes about evidence collected..."
		}

		html += fmt.Sprintf(`
        <div class="control %s %s" data-control="%s">
            <input type="checkbox" %s onchange="toggleEvidence(this, '%s')">
            <div class="control-info">
                <span class="control-id">%s</span> - 
                <span class="control-name">%s</span>
                <span class="control-status">(%s)</span>
                <input type="text" class="notes" placeholder="Notes..." value="%s" onblur="saveNotes(this, '%s')">
            </div>
        </div>`, statusClass, collected, id, checked, id, id, control.ControlName, control.Status, notes, id)
	}

	html += `
        </div>
        
        <button onclick="exportProgress()">Export Progress</button>
        
        <script>
        function toggleEvidence(checkbox, controlId) {
            const control = checkbox.closest('.control');
            if (checkbox.checked) {
                control.classList.add('collected');
            } else {
                control.classList.remove('collected');
            }
            updateProgress();
            saveToLocal();
        }
        
        function updateProgress() {
            const total = document.querySelectorAll('.control').length;
            const collected = document.querySelectorAll('.control.collected').length;
            const percentage = (collected / total * 100).toFixed(0);
            
            const bar = document.getElementById('progress-bar');
            bar.style.width = percentage + '%';
            bar.textContent = collected + '/' + total + ' Collected';
        }
        
        function saveNotes(input, controlId) {
            saveToLocal();
        }
        
        function saveToLocal() {
            const controls = {};
            document.querySelectorAll('.control').forEach(el => {
                const id = el.dataset.control;
                const collected = el.classList.contains('collected');
                const notes = el.querySelector('.notes').value;
                controls[id] = { collected, notes };
            });
            localStorage.setItem('auditkit_evidence', JSON.stringify(controls));
        }
        
        function loadFromLocal() {
            const saved = localStorage.getItem('auditkit_evidence');
            if (saved) {
                const controls = JSON.parse(saved);
                Object.keys(controls).forEach(id => {
                    const el = document.querySelector('[data-control="' + id + '"]');
                    if (el) {
                        const data = controls[id];
                        if (data.collected) {
                            el.classList.add('collected');
                            el.querySelector('input[type="checkbox"]').checked = true;
                        }
                        if (data.notes) {
                            el.querySelector('.notes').value = data.notes;
                        }
                    }
                });
                updateProgress();
            }
        }
        
        function exportProgress() {
            const data = {
                account: '` + t.AccountID + `',
                date: new Date().toISOString(),
                controls: {}
            };
            
            document.querySelectorAll('.control').forEach(el => {
                const id = el.dataset.control;
                data.controls[id] = {
                    collected: el.classList.contains('collected'),
                    notes: el.querySelector('.notes').value
                };
            });
            
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'evidence_progress.json';
            a.click();
        }
        
        // Load saved progress on page load
        loadFromLocal();
        </script>
    </div>
</body>
</html>`

	return os.WriteFile(outputPath, []byte(html), 0644)
}
