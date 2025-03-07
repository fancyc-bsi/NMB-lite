// internal/crash/reporter.go
package crash

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// CrashReport represents a structured crash report
type CrashReport struct {
	Timestamp    time.Time
	ErrorMessage string
	StackTrace   string
	Goroutine    string
	Component    string
	Extra        map[string]string
}

// Reporter handles crash reporting and recovery
type Reporter struct {
	reportsDir string
}

// NewReporter creates a new crash reporter
func NewReporter(reportsDir string) *Reporter {
	// Create reports directory if it doesn't exist
	if reportsDir == "" {
		reportsDir = "crash_reports"
	}

	os.MkdirAll(reportsDir, 0755)

	return &Reporter{
		reportsDir: reportsDir,
	}
}

// RecoverWithCrashReport recovers from panics and generates a crash report
func (r *Reporter) RecoverWithCrashReport(component string, extra map[string]string) {
	if err := recover(); err != nil {
		report := &CrashReport{
			Timestamp:    time.Now(),
			ErrorMessage: fmt.Sprintf("%v", err),
			StackTrace:   string(debug.Stack()),
			Component:    component,
			Goroutine:    getGoroutineID(),
			Extra:        extra,
		}

		// Write to crash report file
		filePath := r.writeCrashReport(report)

		// Also log to stdout
		fmt.Printf("CRASH in %s: %v\nCrash report written to: %s\n",
			component, err, filePath)
	}
}

// Helper function to get unique goroutine ID
func getGoroutineID() string {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	stack := string(buf[:n])
	lines := strings.Split(stack, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return "unknown-goroutine"
}

// Write crash report to file
func (r *Reporter) writeCrashReport(report *CrashReport) string {
	// Create a unique filename based on timestamp and component
	filename := fmt.Sprintf("crash_%s_%s.txt",
		report.Timestamp.Format("20060102_150405"),
		sanitizeFilename(report.Component))

	filePath := filepath.Join(r.reportsDir, filename)

	// Create the file
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Failed to create crash report file: %v\n", err)
		return ""
	}
	defer file.Close()

	// Write report content
	fmt.Fprintf(file, "Crash Report\n")
	fmt.Fprintf(file, "============\n")
	fmt.Fprintf(file, "Timestamp: %s\n", report.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(file, "Component: %s\n", report.Component)
	fmt.Fprintf(file, "Goroutine: %s\n", report.Goroutine)
	fmt.Fprintf(file, "Error: %s\n\n", report.ErrorMessage)

	// Write extra information if available
	if len(report.Extra) > 0 {
		fmt.Fprintf(file, "Additional Information\n")
		fmt.Fprintf(file, "=====================\n")
		for k, v := range report.Extra {
			fmt.Fprintf(file, "%s: %s\n", k, v)
		}
		fmt.Fprintf(file, "\n")
	}

	// Write stack trace
	fmt.Fprintf(file, "Stack Trace\n")
	fmt.Fprintf(file, "===========\n")
	fmt.Fprintf(file, "%s\n", report.StackTrace)

	return filePath
}

// Sanitize filename to avoid invalid characters
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	return name
}
