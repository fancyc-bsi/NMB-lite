package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ScanResult struct {
	PluginID   string
	Host       string
	Port       string
	Name       string
	Status     string
	OutputPath string
	Command    string
	Output     string
}

type Report struct {
	ProjectFolder    string
	SupportedPlugins []string
	MissingPlugins   []string
	ScanResults      []ScanResult
}

func (r *Report) Generate() error {
	filename := filepath.Join(r.ProjectFolder, "NMB_scan_report.md")
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("[x] Failed to create report file: %v", err)
	}
	defer file.Close()

	reportContent := r.generateReportContent()
	_, err = file.WriteString(reportContent)
	if err != nil {
		return fmt.Errorf("[x] Failed to write report content: %v", err)
	}

	return nil
}

func (r *Report) generateReportContent() string {
	var sb strings.Builder

	sb.WriteString("# NMB Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format(time.RFC1123)))

	sb.WriteString("## Supported Plugins\n")
	if len(r.SupportedPlugins) > 0 {
		for _, plugin := range r.SupportedPlugins {
			sb.WriteString(fmt.Sprintf("- %s\n", plugin))
		}
	} else {
		sb.WriteString("None\n")
	}

	sb.WriteString("\n## Missing Plugins\n")
	if len(r.MissingPlugins) > 0 {
		for _, plugin := range r.MissingPlugins {
			sb.WriteString(fmt.Sprintf("- %s\n", plugin))
		}
	} else {
		sb.WriteString("None\n")
	}

	sb.WriteString("\n## Scan Results\n")
	for _, result := range r.ScanResults {
		sb.WriteString(fmt.Sprintf("- **Plugin ID:** %s\n", result.PluginID))
		sb.WriteString(fmt.Sprintf("  - **Host:** %s\n", result.Host))
		sb.WriteString(fmt.Sprintf("  - **Port:** %s\n", result.Port))
		sb.WriteString(fmt.Sprintf("  - **Name:** %s\n", result.Name))
		sb.WriteString(fmt.Sprintf("  - **Status:** %s\n", result.Status))
		sb.WriteString(fmt.Sprintf("  - **Command:** `%s`\n", result.Command))
		sb.WriteString(fmt.Sprintf("  - **Output:**\n```\n%s\n```\n", result.Output))
		sb.WriteString("\n")
	}

	return sb.String()
}
