package scanner

import (
	"crypto/md5"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"NMB/internal/config"
	"NMB/internal/logging"
	"NMB/internal/nessus"
	"NMB/internal/report"
	"NMB/internal/screenshot"
)

type Scanner struct {
	Config        config.Config
	Findings      []nessus.Finding
	PluginData    map[string]nessus.PluginData
	ProjectFolder string
	Report        *report.Report
}

func (s *Scanner) RunScans(wg *sync.WaitGroup, jobs <-chan nessus.Finding) {
	defer wg.Done()
	verifiedPlugins := make(map[string]bool)

	for finding := range jobs {
		if verifiedPlugins[finding.PluginID] || !s.isInPluginData(finding.PluginID) {
			continue
		}

		for _, plugin := range s.Config.Plugins {
			if contains(plugin.IDs, finding.PluginID) {
				if s.verifyFinding(plugin, finding) {
					verifiedPlugins[finding.PluginID] = true
					break
				}
			}
		}
	}
}

func (s *Scanner) verifyFinding(plugin config.Plugin, finding nessus.Finding) bool {
	success := s.executeScan(plugin, finding, false)
	if !success && plugin.ScanType == "nmap -T4 --host-timeout 300s" {
		logging.WarningLogger.Printf("Initial scan failed for %s, retrying with -Pn", finding.Name)
		success = s.executeScan(plugin, finding, true)
	}
	return success
}

func (s *Scanner) executeScan(plugin config.Plugin, hostFinding nessus.Finding, retry bool) bool {
	command := fmt.Sprintf("%s %s", plugin.ScanType, strings.ReplaceAll(plugin.Parameters, "{host}", hostFinding.Host))
	if retry && plugin.ScanType == "nmap -T4 --host-timeout 300s" {
		command = fmt.Sprintf("%s -Pn %s", plugin.ScanType, strings.ReplaceAll(plugin.Parameters, "{host}", hostFinding.Host))
	}
	command = strings.ReplaceAll(command, "{port}", hostFinding.Port)
	logging.InfoLogger.Printf("Testing: %s:%s for %s", hostFinding.Host, hostFinding.Port, hostFinding.Name)
	output, err := executeCommand(command)
	if err != nil {
		logging.ErrorLogger.Printf("[x] Command failed: %v, Command: %s", err, command)
		s.Report.ScanResults = append(s.Report.ScanResults, report.ScanResult{
			PluginID: hostFinding.PluginID,
			Host:     hostFinding.Host,
			Port:     hostFinding.Port,
			Name:     hostFinding.Name,
			Status:   "Command Failed",
			Command:  command,
			Output:   output,
		})
		return false
	}

	if plugin.ScanType == "nmap -T4 --host-timeout 300s" && !isPortOpen(output, hostFinding.Port) {
		logging.WarningLogger.Printf("Port %s closed: %s:%s for %s", hostFinding.Port, hostFinding.Host, hostFinding.Port, hostFinding.Name)
		s.Report.ScanResults = append(s.Report.ScanResults, report.ScanResult{
			PluginID: hostFinding.PluginID,
			Host:     hostFinding.Host,
			Port:     hostFinding.Port,
			Name:     hostFinding.Name,
			Status:   "Port Closed",
			Command:  command,
			Output:   output,
		})
		return false
	}

	if verifyOutput(output, plugin.VerifyWords) {
		logging.SuccessLogger.Printf("Verified: %s (%s:%s)", hostFinding.Name, hostFinding.Host, hostFinding.Port)
		pluginNameHash := md5.Sum([]byte(strings.ToLower(hostFinding.Name)))
		pluginNameHashStr := fmt.Sprintf("%x", pluginNameHash)
		screenshotPath := fmt.Sprintf("%s.png", pluginNameHashStr)
		screenshot.Take(s.ProjectFolder, screenshotPath, output, plugin.VerifyWords)
		s.Report.ScanResults = append(s.Report.ScanResults, report.ScanResult{
			PluginID:   hostFinding.PluginID,
			Host:       hostFinding.Host,
			Port:       hostFinding.Port,
			Name:       hostFinding.Name,
			Status:     "Verified",
			OutputPath: filepath.Join(s.ProjectFolder, screenshotPath),
			Command:    command,
			Output:     output,
		})
		return true
	}

	logging.ErrorLogger.Printf("Verification failed: %s (%s:%s)", hostFinding.Name, hostFinding.Host, hostFinding.Port)
	s.Report.ScanResults = append(s.Report.ScanResults, report.ScanResult{
		PluginID: hostFinding.PluginID,
		Host:     hostFinding.Host,
		Port:     hostFinding.Port,
		Name:     hostFinding.Name,
		Status:   "Verification Failed",
		Command:  command,
		Output:   output,
	})
	return false
}

func executeCommand(command string) (string, error) {
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
