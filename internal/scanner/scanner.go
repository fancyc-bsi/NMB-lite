package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"NMB/internal/config"
	"NMB/internal/logging"
	"NMB/internal/nessus"
	"NMB/internal/remote"
	"NMB/internal/report"
	"NMB/internal/screenshot"
)

type Scanner struct {
	Config        config.Config
	Findings      []nessus.Finding
	PluginData    map[string]nessus.PluginData
	ProjectFolder string
	Report        *report.Report
	RemoteExec    *remote.RemoteExecutor
	mu            sync.Mutex
}

const (
	maxRetries   = 2
	scanTimeout  = 3 * time.Minute
	nmapScanType = "nmap -T4 --host-timeout 300s"
)

func (s *Scanner) RunScans(wg *sync.WaitGroup, jobs <-chan nessus.Finding) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logging.ErrorLogger.Printf("Recovered from panic: %v", r)
		}
	}()

	verifiedPlugins := sync.Map{}
	var scanWg sync.WaitGroup

	for finding := range jobs {
		if _, verified := verifiedPlugins.Load(finding.PluginID); verified || !s.isInPluginData(finding.PluginID) {
			continue
		}

		scanWg.Add(1)
		go func(f nessus.Finding) {
			defer scanWg.Done()

			for _, plugin := range s.Config.Plugins {
				if contains(plugin.IDs, f.PluginID) {
					if s.verifyFinding(plugin, f) {
						verifiedPlugins.Store(f.PluginID, true)
						break
					}
				}
			}
		}(finding)
	}

	scanWg.Wait()
}

func (s *Scanner) verifyFinding(plugin config.Plugin, finding nessus.Finding) bool {
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	resultChan := make(chan bool, 1)
	go func() {
		success := s.ExecuteScan(plugin, finding, false)
		if !success && plugin.ScanType == nmapScanType {
			logging.WarningLogger.Printf("Initial scan failed for %s, retrying with -Pn", finding.Name)
			success = s.ExecuteScan(plugin, finding, true)
		}
		resultChan <- success
	}()

	select {
	case success := <-resultChan:
		return success
	case <-ctx.Done():
		logging.ErrorLogger.Printf("Scan timed out for %s (%s:%s)", finding.Name, finding.Host, finding.Port)
		s.recordScanResult(finding, plugin, "", "Timeout", "")
		return false
	}
}

func (s *Scanner) ExecuteScan(plugin config.Plugin, hostFinding nessus.Finding, retry bool) bool {
	command := buildCommand(plugin, hostFinding, retry)
	logging.InfoLogger.Printf("Testing: %s:%s for %s", hostFinding.Host, hostFinding.Port, hostFinding.Name)

	output, err := executeCommand(command, s.RemoteExec)
	if err != nil {
		logging.ErrorLogger.Printf("Command failed: %v, Command: %s", err, command)
		s.recordScanResult(hostFinding, plugin, command, "Command Failed", output)
		return false
	}

	if plugin.ScanType == nmapScanType && !isPortOpen(output, hostFinding.Port) {
		logging.WarningLogger.Printf("Port %s closed: %s:%s for %s",
			hostFinding.Port, hostFinding.Host, hostFinding.Port, hostFinding.Name)
		s.recordScanResult(hostFinding, plugin, command, "Port Closed", output)
		return false
	}

	if verifyOutput(output, plugin.VerifyWords) {
		s.handleSuccessfulScan(hostFinding, plugin, command, output)
		return true
	}

	logging.ErrorLogger.Printf("Verification failed: %s (%s:%s)",
		hostFinding.Name, hostFinding.Host, hostFinding.Port)
	s.recordScanResult(hostFinding, plugin, command, "Verification Failed", output)
	return false
}

func (s *Scanner) handleSuccessfulScan(finding nessus.Finding, plugin config.Plugin, command, output string) {
	logging.SuccessLogger.Printf("Verified: %s (%s:%s)", finding.Name, finding.Host, finding.Port)

	pluginNameHash := md5.Sum([]byte(strings.ToLower(finding.Name)))
	screenshotPath := fmt.Sprintf("%s.png", fmt.Sprintf("%x", pluginNameHash))

	screenshot.Take(s.ProjectFolder, screenshotPath, output, plugin.VerifyWords, command)

	s.recordScanResult(finding, plugin, command, "Verified", output, filepath.Join(s.ProjectFolder, screenshotPath))
}

func (s *Scanner) recordScanResult(finding nessus.Finding, plugin config.Plugin, command, status, output string, paths ...string) {
	var outputPath string
	if len(paths) > 0 {
		outputPath = paths[0]
	}

	// Lock before modifying the report
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Report.ScanResults = append(s.Report.ScanResults, report.ScanResult{
		PluginID:   finding.PluginID,
		Host:       finding.Host,
		Port:       finding.Port,
		Name:       finding.Name,
		Status:     status,
		Command:    command,
		Output:     output,
		OutputPath: outputPath,
	})
}

func buildCommand(plugin config.Plugin, finding nessus.Finding, retry bool) string {
	command := fmt.Sprintf("%s %s", plugin.ScanType, strings.ReplaceAll(plugin.Parameters, "{host}", finding.Host))
	if retry && plugin.ScanType == nmapScanType {
		command = fmt.Sprintf("%s -Pn %s", plugin.ScanType, strings.ReplaceAll(plugin.Parameters, "{host}", finding.Host))
	}
	return strings.ReplaceAll(command, "{port}", finding.Port)
}

func executeCommand(command string, remoteExec *remote.RemoteExecutor) (string, error) {
	if remoteExec != nil {
		return remoteExec.ExecuteCommand(command)
	}

	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, string(output))
	}
	return string(output), nil
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

func verifyOutput(output string, words []string) bool {
	for _, word := range words {
		if strings.Contains(output, word) {
			return true
		}
	}
	return false
}

func isPortOpen(output, port string) bool {
	return strings.Contains(output, fmt.Sprintf("%s/tcp open", port))
}

func (s *Scanner) isInPluginData(pluginID string) bool {
	_, exists := s.PluginData[pluginID]
	return exists
}
