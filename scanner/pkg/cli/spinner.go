package cli

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Spinner provides a terminal spinner for long-running operations
type Spinner struct {
	message   string
	frames    []string
	interval  time.Duration
	stopCh    chan struct{}
	doneCh    chan struct{}
	mu        sync.Mutex
	running   bool
}

// Common spinner styles
var (
	SpinnerDots    = []string{"   ", ".  ", ".. ", "..."}
	SpinnerLine    = []string{"-", "\\", "|", "/"}
	SpinnerCircle  = []string{"◐", "◓", "◑", "◒"}
	SpinnerBraille = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	SpinnerArrow   = []string{"←", "↖", "↑", "↗", "→", "↘", "↓", "↙"}
	SpinnerBlock   = []string{"▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"}
)

// NewSpinner creates a new spinner with the given message
func NewSpinner(message string) *Spinner {
	return &Spinner{
		message:  message,
		frames:   SpinnerBraille,
		interval: 80 * time.Millisecond,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// SetStyle sets the spinner animation style
func (s *Spinner) SetStyle(frames []string) *Spinner {
	s.frames = frames
	return s
}

// SetInterval sets the animation interval
func (s *Spinner) SetInterval(d time.Duration) *Spinner {
	s.interval = d
	return s
}

// Start begins the spinner animation
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.mu.Unlock()

	// Only animate if stdout is a terminal
	if !IsColorEnabled() {
		fmt.Fprintf(os.Stderr, "%s...\n", s.message)
		return
	}

	go func() {
		defer close(s.doneCh)
		idx := 0
		for {
			select {
			case <-s.stopCh:
				// Clear the spinner line
				fmt.Fprintf(os.Stderr, "\r%s\r", "                                                  ")
				return
			default:
				frame := s.frames[idx%len(s.frames)]
				fmt.Fprintf(os.Stderr, "\r%s %s %s", Color(Cyan, frame), s.message, Color(Dim, ""))
				idx++
				time.Sleep(s.interval)
			}
		}
	}()
}

// Stop stops the spinner and shows the final message
func (s *Spinner) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	if IsColorEnabled() {
		close(s.stopCh)
		<-s.doneCh
	}
}

// StopWithSuccess stops and shows a success message
func (s *Spinner) StopWithSuccess(message string) {
	s.Stop()
	if IsColorEnabled() {
		fmt.Fprintf(os.Stderr, "%s %s\n", Color(Green, "OK"), message)
	}
}

// StopWithError stops and shows an error message
func (s *Spinner) StopWithError(message string) {
	s.Stop()
	if IsColorEnabled() {
		fmt.Fprintf(os.Stderr, "%s %s\n", Color(Red, "ERROR"), message)
	}
}

// StopWithMessage stops and shows a custom message
func (s *Spinner) StopWithMessage(message string) {
	s.Stop()
	fmt.Fprintf(os.Stderr, "%s\n", message)
}

// UpdateMessage updates the spinner message while running
func (s *Spinner) UpdateMessage(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// ProgressBar represents a simple progress bar
type ProgressBar struct {
	total     int
	current   int
	width     int
	message   string
	mu        sync.Mutex
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, message string) *ProgressBar {
	return &ProgressBar{
		total:   total,
		width:   40,
		message: message,
	}
}

// Increment increments the progress by 1
func (p *ProgressBar) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	p.render()
}

// Set sets the current progress
func (p *ProgressBar) Set(current int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = current
	p.render()
}

// SetMessage updates the progress bar message
func (p *ProgressBar) SetMessage(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.message = message
	p.render()
}

func (p *ProgressBar) render() {
	if !IsColorEnabled() {
		return
	}

	percent := float64(p.current) / float64(p.total)
	filled := int(percent * float64(p.width))
	empty := p.width - filled

	bar := Color(Green, "["+strings.Repeat("=", filled)) +
		Color(Dim, strings.Repeat("-", empty)+"]")

	fmt.Fprintf(os.Stderr, "\r%s %s %3.0f%% (%d/%d)",
		p.message, bar, percent*100, p.current, p.total)
}

// Finish completes the progress bar
func (p *ProgressBar) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = p.total
	p.render()
	fmt.Fprintln(os.Stderr)
}

