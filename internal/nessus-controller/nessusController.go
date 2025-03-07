package nessus

import (
	"NMB/internal/crash"
	"NMB/internal/logging"
	"NMB/internal/remote"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Nessus struct {
	remote       *remote.RemoteExecutor
	url          string
	username     string
	password     string
	projectName  string
	targetsList  string
	excludeFile  []string
	droneIP      string
	aliveHosts   string
	tokenKeys    map[string]string
	tokenAuth    map[string]string
	apiKeys      map[string]string
	apiAuth      map[string]string
	outputFolder string
	stopRefresh  chan struct{}
	mutex        sync.RWMutex
}

type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (n *Nessus) safeExecute(component string, operation func() error) error {
	reporter := crash.NewReporter("crash_reports")

	extra := map[string]string{
		"url":         n.url,
		"username":    n.username,
		"projectName": n.projectName,
	}

	if n.targetsList != "" {
		extra["targets"] = n.targetsList
	}

	// Execute the operation with panic recovery
	defer reporter.RecoverWithCrashReport("Nessus_"+component, extra)

	return operation()
}

func (n *Nessus) getTokens() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	auth := Auth{
		Username: n.username,
		Password: n.password,
	}

	authData, err := json.Marshal(auth)
	if err != nil {
		return err
	}

	client := createInsecureClient()

	resp, err := client.Post(n.url+"/session", "application/json", bytes.NewBuffer(authData))
	if err != nil {
		return fmt.Errorf("failed to get cookie token: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	n.tokenKeys = make(map[string]string)
	n.tokenKeys["cookie_token"] = result["token"].(string)

	// Get API token from nessus6.js
	resp, err = client.Get(n.url + "/nessus6.js")
	if err != nil {
		return fmt.Errorf("failed to get nessus6.js: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Extract API token
	apiTokenRe := regexp.MustCompile(`{key:"getApiToken",value:function\(\){return"(.*)"}},{key`)
	matches := apiTokenRe.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return fmt.Errorf("API token not found in response")
	}
	n.tokenKeys["api_token"] = matches[1]

	// Extract scan UUID
	scanUUIDRe := regexp.MustCompile(`CUSTOM_SCAN_TEMPLATE="(.*)",this\.CUSTOM_AGENT_TEMPLATE`)
	matches = scanUUIDRe.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return fmt.Errorf("scan UUID not found in response")
	}
	n.tokenKeys["scan_uuid"] = matches[1]

	// Set token auth headers
	n.tokenAuth = map[string]string{
		"X-Cookie":    fmt.Sprintf("token=%s", n.tokenKeys["cookie_token"]),
		"X-API-Token": n.tokenKeys["api_token"],
	}

	return nil
}

func (n *Nessus) startTokenRefresh() {
	n.stopRefresh = make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := n.getTokens(); err != nil {
					logging.ErrorLogger.Printf("Failed to refresh tokens: %v", err)
					// Try to re-authenticate completely if token refresh fails
					if err := n.authenticate(); err != nil {
						logging.ErrorLogger.Printf("Failed to re-authenticate: %v", err)
					}
				} else {
					logging.InfoLogger.Printf("Successfully refreshed authentication tokens")
				}
			case <-n.stopRefresh:
				return
			}
		}
	}()
}

var (
	ErrScanCanceled = fmt.Errorf("scan was canceled")
	ErrScanFailed   = fmt.Errorf("scan failed to complete")
)

func (n *Nessus) stopTokenRefresh() {
	if n.stopRefresh != nil {
		close(n.stopRefresh)
	}
}

func (n *Nessus) getAPIKeys() error {
	client := createInsecureClient()

	req, err := http.NewRequest(http.MethodPut, n.url+"/session/keys", nil)
	if err != nil {
		return err
	}

	// Add token auth headers
	for k, v := range n.tokenAuth {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	n.apiKeys = result
	n.apiAuth = map[string]string{
		"X-ApiKeys": fmt.Sprintf("accessKey=%s; secretKey=%s", n.apiKeys["accessKey"], n.apiKeys["secretKey"]),
	}

	return nil
}

func (n *Nessus) authenticate() error {
	logging.InfoLogger.Printf("Retrieving API tokens")

	// Get tokens (cookie token and API token)
	if err := n.getTokens(); err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve API tokens - check your login credentials")
		return err
	}

	// Get API keys
	if err := n.getAPIKeys(); err != nil {
		logging.ErrorLogger.Printf("Failed to retrieve API keys - check your login credentials")
		return err
	}

	// Start token refresh routine
	n.startTokenRefresh()

	logging.SuccessLogger.Printf("API tokens retrieved successfully")
	return nil
}

// Add this exported method to your nessus package

func (n *Nessus) GetScanFindings(scanID string) (map[string]int, error) {
	var findings map[string]int

	err := n.safeExecute("GetScanFindings", func() error {
		var err error
		findings = make(map[string]int)

		// First get the scan details
		resp, err := n.makeRequest(http.MethodGet, "/scans/"+scanID, nil)
		if err != nil {
			return fmt.Errorf("failed to get scan details: %v", err)
		}
		defer resp.Body.Close()

		var scanDetails map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&scanDetails); err != nil {
			return fmt.Errorf("failed to decode scan details: %v", err)
		}

		// Extract the vulnerabilities counts if available
		info, ok := scanDetails["info"].(map[string]interface{})
		if !ok {
			return nil // Return empty findings if no info section
		}

		// Try to get severity counts from different possible locations in the response

		// First try the vulnerabilities counts
		if vulns, ok := info["vulnerabilities"].([]interface{}); ok {
			for _, v := range vulns {
				if vuln, ok := v.(map[string]interface{}); ok {
					severity, _ := vuln["severity"].(float64)
					count, _ := vuln["count"].(float64)

					switch int(severity) {
					case 4:
						findings["critical"] += int(count)
					case 3:
						findings["high"] += int(count)
					case 2:
						findings["medium"] += int(count)
					case 1:
						findings["low"] += int(count)
					case 0:
						findings["info"] += int(count)
					}
				}
			}

			return nil
		}

		// If vulnerabilities counts not found, try the severities counts
		sevs, ok := info["severities"].([]interface{})
		if ok {
			for _, s := range sevs {
				if sev, ok := s.(map[string]interface{}); ok {
					severity, _ := sev["id"].(float64)
					count, _ := sev["count"].(float64)

					switch int(severity) {
					case 4:
						findings["critical"] = int(count)
					case 3:
						findings["high"] = int(count)
					case 2:
						findings["medium"] = int(count)
					case 1:
						findings["low"] = int(count)
					case 0:
						findings["info"] = int(count)
					}
				}
			}

			return nil
		}

		// Last resort: try to get the total vulnerability counts
		if hostCount, ok := info["hostcount"].(float64); ok && hostCount > 0 {
			if counts, ok := info["counts"].(map[string]interface{}); ok {
				if vulnsBySev, ok := counts["vulnerabilities"].(map[string]interface{}); ok {
					// Extract by severity
					criticalCount, _ := vulnsBySev["critical"].(float64)
					highCount, _ := vulnsBySev["high"].(float64)
					mediumCount, _ := vulnsBySev["medium"].(float64)
					lowCount, _ := vulnsBySev["low"].(float64)
					infoCount, _ := vulnsBySev["info"].(float64)

					findings["critical"] = int(criticalCount)
					findings["high"] = int(highCount)
					findings["medium"] = int(mediumCount)
					findings["low"] = int(lowCount)
					findings["info"] = int(infoCount)

					return nil
				}
			}
		}

		// If we couldn't get real findings, set defaults to prevent UI issues
		findings["critical"] = 0
		findings["high"] = 0
		findings["medium"] = 0
		findings["low"] = 0
		findings["info"] = 0

		return nil
	})

	// If err is nil, return the findings, otherwise return an error
	return findings, err
}

func (n *Nessus) MakeRequest(method, endpoint string, body []byte) (*http.Response, error) {
	return n.makeRequest(method, endpoint, body)
}

// GetScans returns a list of all scans from the Nessus API
func (n *Nessus) GetScans() ([]map[string]interface{}, error) {
	resp, err := n.makeRequest(http.MethodGet, "/scans", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get scans: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	scans, ok := result["scans"].([]interface{})
	if !ok {
		return []map[string]interface{}{}, nil
	}

	var scansList []map[string]interface{}
	for _, scan := range scans {
		if scanMap, ok := scan.(map[string]interface{}); ok {
			scansList = append(scansList, scanMap)
		}
	}

	return scansList, nil
}

// GetScanDetails returns detailed information about a specific scan
func (n *Nessus) GetScanDetails(scanID string) (map[string]interface{}, error) {
	resp, err := n.makeRequest(http.MethodGet, "/scans/"+scanID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan details: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return result, nil
}

// ExecuteScanAction performs an action (start, stop, pause, resume) on a scan
func (n *Nessus) ExecuteScanAction(scanID, action string) error {
	endpoint := fmt.Sprintf("/scans/%s/%s", scanID, action)
	resp, err := n.makeRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to execute scan action: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to %s scan: %s - %s", action, resp.Status, string(body))
	}

	return nil
}

// DeleteScan deletes a scan
func (n *Nessus) DeleteScan(scanID string) error {
	resp, err := n.makeRequest(http.MethodDelete, "/scans/"+scanID, nil)
	if err != nil {
		return fmt.Errorf("failed to delete scan: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete scan: %s - %s", resp.Status, string(body))
	}

	return nil
}

// ExportScanByID exports a specific scan by ID
func (n *Nessus) ExportScanByID(scanID string) error {
	// Get scan details to check status
	resp, err := n.makeRequest(http.MethodGet, "/scans/"+scanID, nil)
	if err != nil {
		return fmt.Errorf("failed to get scan details: %v", err)
	}

	var scanDetails map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&scanDetails); err != nil {
		resp.Body.Close()
		return fmt.Errorf("failed to decode scan details: %v", err)
	}
	resp.Body.Close()

	// Extract scan name and status
	info, ok := scanDetails["info"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid scan details format")
	}

	scanName, _ := info["name"].(string)
	if scanName == "" {
		scanName = fmt.Sprintf("scan_%s", scanID)
	}

	status, _ := info["status"].(string)
	if status == "running" || status == "pending" {
		logging.InfoLogger.Printf("Scan still running, will monitor until completion")
		// Wait for scan to complete
		n.projectName = scanName // Set project name so monitorScan can find it
		if err := n.monitorScan(); err != nil {
			return fmt.Errorf("monitoring scan failed: %v", err)
		}
	}

	// Create an evidence folder based on the scan name
	evidenceFolder := filepath.Join(n.outputFolder, "evidence", scanName)
	if err := os.MkdirAll(evidenceFolder, 0755); err != nil {
		return fmt.Errorf("failed to create evidence folder: %v", err)
	}
	logging.InfoLogger.Printf("Created evidence folder: %s", evidenceFolder)

	templateID, err := n.getHTMLTemplateID()
	if err != nil {
		return fmt.Errorf("failed to get HTML template ID: %v", err)
	}

	formats := map[string]ExportFormat{
		"csv": {
			Format: "csv",
			ReportContents: map[string]interface{}{
				"csvColumns": map[string]bool{
					"id": true, "cve": true, "cvss": true,
					"risk": true, "hostname": true, "protocol": true,
					"port": true, "plugin_name": true, "synopsis": true,
					"description": true, "solution": true, "see_also": true,
					"plugin_output": true, "stig_severity": true,
					"cvss3_base_score": true, "cvss_temporal_score": true,
					"cvss3_temporal_score": true, "risk_factor": true,
					"references": true, "plugin_information": true,
					"exploitable_with": true,
				},
			},
			ExtraFilters: map[string]interface{}{
				"host_ids":   []int{},
				"plugin_ids": []int{},
			},
		},
		"nessus": {
			Format: "nessus",
		},
		"html": {
			Format:     "html",
			TemplateID: templateID,
			ExtraFilters: map[string]interface{}{
				"host_ids":   []int{},
				"plugin_ids": []int{},
			},
		},
	}

	for format, config := range formats {
		logging.InfoLogger.Printf("Exporting %s file...", format)

		exportJSON, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to serialize export config: %v", err)
		}

		exportResp, err := n.makeRequest(http.MethodPost, fmt.Sprintf("/scans/%s/export", scanID), exportJSON)
		if err != nil {
			return fmt.Errorf("export request failed: %v", err)
		}

		defer exportResp.Body.Close()
		var result struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(exportResp.Body).Decode(&result); err != nil {
			return fmt.Errorf("failed to decode export token: %v", err)
		}

		if result.Token == "" {
			return fmt.Errorf("no export token received for %s format", format)
		}

		// Create the output file path within the evidence folder
		outputFile := filepath.Join(evidenceFolder, fmt.Sprintf("%s.%s", scanName, format))
		if err := n.waitForDownload(result.Token, outputFile); err != nil {
			return fmt.Errorf("failed to download %s file: %v", format, err)
		}

		logging.SuccessLogger.Printf("Exported %s file to %q", format, outputFile)
	}

	return nil
}

// Helper function to make authenticated requests with thread-safe token access
func (n *Nessus) makeRequest(method, endpoint string, body []byte) (*http.Response, error) {
	client := createInsecureClient()

	req, err := http.NewRequest(method, n.url+endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	// Thread-safe reading of auth headers
	n.mutex.RLock()
	for k, v := range n.tokenAuth {
		req.Header.Set(k, v)
	}
	for k, v := range n.apiAuth {
		req.Header.Set(k, v)
	}
	n.mutex.RUnlock()

	return client.Do(req)
}

// Clean up resources when done
func (n *Nessus) Close() {
	n.stopTokenRefresh()
}

func New(host, username, password, projectName, targetsFile string, excludeFile []string, discovery bool) (*Nessus, error) {
	reporter := crash.NewReporter("crash_reports")

	// Extra information for crash reports
	extra := map[string]string{
		"host":        host,
		"username":    username,
		"projectName": projectName,
		"targetsFile": targetsFile,
	}

	// Recover from panics during initialization
	defer reporter.RecoverWithCrashReport("NessusInitialization", extra)

	remote, err := remote.NewRemoteExecutor(host, username, password, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create remote executor: %v", err)
	}

	n := &Nessus{
		remote:       remote,
		url:          fmt.Sprintf("https://%s:8834", host),
		username:     username,
		password:     password,
		projectName:  projectName,
		excludeFile:  excludeFile,
		outputFolder: filepath.Dir(os.Args[0]),
	}

	// Process targets file
	if targetsFile != "" {
		content, err := os.ReadFile(targetsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read targets file: %v", err)
		}
		// Split on newlines and remove empty lines
		targets := []string{}
		for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				targets = append(targets, trimmed)
			}
		}
		n.targetsList = strings.Join(targets, ",")
		logging.InfoLogger.Printf("Loaded targets from file: %s", n.targetsList)
	}

	n.droneIP, err = n.getDroneIP()
	if err != nil {
		return nil, err
	}

	if discovery {
		n.aliveHosts, err = n.discoveryScan()
		if err != nil {
			return nil, err
		}
	}

	// Get authentication
	if err := n.authenticate(); err != nil {
		return nil, err
	}

	return n, nil
}

// Monitor scan progress
func (n *Nessus) monitorScan() error {
	logging.InfoLogger.Printf("Monitoring scan progress...")

	for {
		scan := n.getScanInfo()
		if scan == nil {
			return fmt.Errorf("scan not found")
		}

		status := fmt.Sprintf("%v", scan["status"])

		switch status {
		case "completed":
			logging.InfoLogger.Printf("Scan completed successfully")
			return nil
		case "canceled":
			logging.InfoLogger.Printf("Scan was canceled by user or system")
			return ErrScanCanceled
		case "failed":
			logging.ErrorLogger.Printf("Scan failed to complete")
			return ErrScanFailed
		case "running", "paused":
			progress, ok := scan["progress"].(float64)
			if ok {
				logging.InfoLogger.Printf("Scan progress: %.0f%%", progress)
			}
			time.Sleep(30 * time.Second)
		default:
			logging.InfoLogger.Printf("Scan status: %s", status)
			time.Sleep(30 * time.Second)
		}
	}
}

func (n *Nessus) createScan(launch bool) error {
	logging.InfoLogger.Printf("Creating new scan")

	// Check if scan already exists
	if scan := n.getScanInfo(); scan != nil {
		logging.InfoLogger.Printf("Scan already exists, aborting scan creation")
		return fmt.Errorf("scan name already exists")
	}

	// Get policy ID
	policies, err := n.getPolicies()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get policies: %v", err)
		return err
	}

	var policyID string
	var templateUUID string
	for _, policy := range policies {
		if policy["name"] == "Default Good Model Nessus Vulnerability Policy" {
			switch v := policy["id"].(type) {
			case string:
				policyID = v
			case float64:
				policyID = fmt.Sprintf("%v", v)
			default:
				return fmt.Errorf("unexpected type for policy ID: %T", v)
			}
			// Get the template UUID from the policy
			templateUUID = policy["template_uuid"].(string)
			break
		}
	}

	if policyID == "" {
		logging.ErrorLogger.Printf("Policy not found")
		return fmt.Errorf("policy not found")
	}

	// Use targetsList if no alive hosts (discovery scan wasn't run)
	targets := n.aliveHosts
	if targets == "" {
		targets = n.targetsList
	}

	if targets == "" {
		return fmt.Errorf("no targets specified")
	}

	logging.InfoLogger.Printf("Using targets: %s", targets)

	// Create scan data following Nessus documentation
	scanData := map[string]interface{}{
		"uuid": templateUUID,
		"settings": map[string]interface{}{
			"name":           n.projectName,
			"policy_id":      policyID,
			"enabled":        true,
			"launch":         "ON_DEMAND",
			"scanner_id":     "1",
			"folder_id":      3,
			"text_targets":   targets,
			"description":    "No host Discovery\nAll TCP port\nAll Service Discovery\nDefault passwords being tested\nGeneric Web Test\nNo compliance or local Check\nNo DOS plugins\n",
			"agent_group_id": []string{},
		},
	}

	// If launch is true, we'll start the scan immediately
	if launch {
		scanData["settings"].(map[string]interface{})["launch_now"] = true
	}

	// Debug print scan data
	scanDataJSON, err := json.Marshal(scanData)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to marshal scan data: %v", err)
		return err
	}
	logging.InfoLogger.Printf("Scan data JSON: %s", string(scanDataJSON))

	// Make the request
	resp, err := n.makeRequest(http.MethodPost, "/scans", scanDataJSON)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to send HTTP request: %v", err)
		return err
	}
	defer resp.Body.Close()

	// Log response status code and body
	logging.InfoLogger.Printf("Received response: %s", resp.Status)

	// If response is not 200, read and log the error body
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logging.ErrorLogger.Printf("Failed to create scan. Status code: %d, Response body: %s", resp.StatusCode, string(body))
		return fmt.Errorf("failed to create scan: %s - %s", resp.Status, string(body))
	}

	logging.InfoLogger.Printf("Scan created successfully")
	return nil
}

func (n *Nessus) excludeTargets() error {
	if len(n.excludeFile) == 0 {
		return nil
	}

	var excludeHosts []string
	for _, file := range n.excludeFile {
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read exclude file %s: %v", file, err)
		}
		hosts := strings.Split(strings.TrimSpace(string(content)), "\n")
		excludeHosts = append(excludeHosts, hosts...)
	}

	excludeMap := make(map[string]bool)
	for _, host := range excludeHosts {
		excludeMap[strings.TrimSpace(host)] = true
	}

	// Filter out excluded hosts from aliveHosts
	var filteredHosts []string
	for _, host := range strings.Split(n.aliveHosts, ",") {
		if !excludeMap[strings.TrimSpace(host)] {
			filteredHosts = append(filteredHosts, host)
		}
	}

	if len(filteredHosts) == 0 {
		return fmt.Errorf("no targets remaining after exclusion")
	}

	n.aliveHosts = strings.Join(filteredHosts, ",")
	return nil
}

func (n *Nessus) getScanInfo() map[string]interface{} {
	resp, err := n.makeRequest(http.MethodGet, "/scans", nil)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get scans: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logging.ErrorLogger.Printf("Failed to decode response: %v", err)
		return nil
	}

	scans, ok := result["scans"].([]interface{})
	if !ok {
		return nil
	}

	for _, scan := range scans {
		scanMap, ok := scan.(map[string]interface{})
		if !ok {
			continue
		}
		if scanMap["name"] == n.projectName {
			return scanMap
		}
	}

	return nil
}

func (n *Nessus) getPolicies() ([]map[string]interface{}, error) {
	resp, err := n.makeRequest(http.MethodGet, "/policies", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Extract policies from the response
	policies, ok := result["policies"].([]interface{})
	if !ok {
		prettyJSON, err := json.MarshalIndent(result, "", "    ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response: %v", err)
		}
		log.Printf("Invalid policies response:\n%s", string(prettyJSON))
		return nil, fmt.Errorf("invalid policies response")
	}

	var policyList []map[string]interface{}
	for _, policy := range policies {
		if policyMap, ok := policy.(map[string]interface{}); ok {
			policyList = append(policyList, policyMap)
		}
	}

	return policyList, nil
}

func (n *Nessus) scanAction(action string) error {
	scan := n.getScanInfo()
	if scan == nil {
		return fmt.Errorf("scan not found")
	}

	scanID := fmt.Sprintf("%v", scan["id"])
	endpoint := fmt.Sprintf("/scans/%s/%s", scanID, action)

	resp, err := n.makeRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to %s scan: %s", action, resp.Status)
	}

	logging.InfoLogger.Printf("Scan %s successful", action)
	return nil
}

type ExportFormat struct {
	Format            string                 `json:"format"`
	TemplateID        string                 `json:"template_id,omitempty"`
	ReportContents    map[string]interface{} `json:"reportContents,omitempty"`
	ExtraFilters      map[string]interface{} `json:"extraFilters,omitempty"`
	FormattingOptions map[string]interface{} `json:"formattingOptions,omitempty"`
}

func (n *Nessus) waitForDownload(token, outputFile string) error {
	startTime := time.Now()
	maxDuration := 10 * time.Minute // Maximum wait time

	for {
		// Check the elapsed time
		elapsed := time.Since(startTime)
		if elapsed > maxDuration {
			return fmt.Errorf("timed out after %v while waiting for file to be ready", maxDuration)
		}

		resp, err := n.makeRequest(http.MethodGet, fmt.Sprintf("/tokens/%s/download", token), nil)
		if err != nil {
			return fmt.Errorf("error checking download status: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		// Check for readiness in both status code and response body
		if resp.StatusCode == http.StatusOK && !strings.Contains(string(body), "not ready") {
			// File is genuinely ready, download it
			out, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}
			_, err = io.Copy(out, bytes.NewReader(body)) // Use the already-read body
			out.Close()
			if err != nil {
				return fmt.Errorf("failed to write downloaded file: %v", err)
			}

			logging.InfoLogger.Printf("File downloaded successfully: %s", outputFile)
			return nil
		}

		// Handle "not ready" response or other cases
		time.Sleep(5 * time.Second)
	}
}

func (n *Nessus) exportScan() (string, error) {
	logging.InfoLogger.Printf("Exporting scan results...")

	scanInfo := n.getScanInfo()
	if scanInfo == nil {
		return "", fmt.Errorf("scan not found")
	}
	scanID := fmt.Sprintf("%v", scanInfo["id"])
	scanName := fmt.Sprintf("%v", scanInfo["name"])
	status := fmt.Sprintf("%v", scanInfo["status"])

	if status == "running" || status == "pending" {
		logging.ErrorLogger.Printf("Scan still running, waiting for it to finish...")
		if err := n.monitorScan(); err != nil {
			return "", fmt.Errorf("monitoring scan failed: %v", err)
		}
	}

	// Create an evidence folder based on the scan name
	evidenceFolder := filepath.Join(n.outputFolder, "evidence", scanName)
	if err := os.MkdirAll(evidenceFolder, 0755); err != nil {
		return "", fmt.Errorf("failed to create evidence folder: %v", err)
	}
	logging.InfoLogger.Printf("Created evidence folder: %s", evidenceFolder)

	templateID, err := n.getHTMLTemplateID()
	if err != nil {
		return "", fmt.Errorf("failed to get HTML template ID: %v", err)
	}

	formats := map[string]ExportFormat{
		"csv": {
			Format: "csv",
			ReportContents: map[string]interface{}{
				"csvColumns": map[string]bool{
					"id": true, "cve": true, "cvss": true,
					"risk": true, "hostname": true, "protocol": true,
					"port": true, "plugin_name": true, "synopsis": true,
					"description": true, "solution": true, "see_also": true,
					"plugin_output": true, "stig_severity": true,
					"cvss3_base_score": true, "cvss_temporal_score": true,
					"cvss3_temporal_score": true, "risk_factor": true,
					"references": true, "plugin_information": true,
					"exploitable_with": true,
				},
			},
			ExtraFilters: map[string]interface{}{
				"host_ids":   []int{},
				"plugin_ids": []int{},
			},
		},
		"nessus": {
			Format: "nessus",
		},
		"html": {
			Format:     "html",
			TemplateID: templateID,
			ExtraFilters: map[string]interface{}{
				"host_ids":   []int{},
				"plugin_ids": []int{},
			},
		},
	}

	for format, config := range formats {
		logging.InfoLogger.Printf("Exporting %s file...", format)

		exportJSON, err := json.Marshal(config)
		if err != nil {
			return "", fmt.Errorf("failed to serialize export config: %v", err)
		}

		resp, err := n.makeRequest(http.MethodPost, fmt.Sprintf("/scans/%s/export", scanID), exportJSON)
		if err != nil {
			return "", fmt.Errorf("export request failed: %v", err)
		}

		defer resp.Body.Close()
		var result struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", fmt.Errorf("failed to decode export token: %v", err)
		}

		if result.Token == "" {
			return "", fmt.Errorf("no export token received for %s format", format)
		}

		// Create the output file path within the evidence folder
		outputFile := filepath.Join(evidenceFolder, fmt.Sprintf("%s.%s", scanName, format))
		if err := n.waitForDownload(result.Token, outputFile); err != nil {
			return "", fmt.Errorf("failed to download %s file: %v", format, err)
		}

		logging.SuccessLogger.Printf("Exported %s file to %q", format, outputFile)
	}

	return filepath.Join(evidenceFolder, fmt.Sprintf("%s.nessus", scanName)), nil
}

func (n *Nessus) getHTMLTemplateID() (string, error) {
	resp, err := n.makeRequest(http.MethodGet, "/reports/custom/templates", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var templates []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&templates); err != nil {
		return "", err
	}

	for _, template := range templates {
		name, ok := template["name"].(string)
		if !ok || name != "Detailed Vulnerabilities By Plugin" {
			continue
		}

		id := template["id"]
		switch v := id.(type) {
		case float64:
			return fmt.Sprintf("%.0f", v), nil
		case string:
			return v, nil
		default:
			return "", fmt.Errorf("unexpected type for template ID: %T", v)
		}

	}
	return "", fmt.Errorf("template 'Detailed Vulnerabilities By Plugin' not found")
}

func createInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12, // Ensures compatibility with modern TLS
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				},
			},
		},
		Timeout: 10 * time.Second,
	}
}

func (n *Nessus) getDroneIP() (string, error) {
	output, err := n.remote.ExecuteCommand("ip -4 addr show eth0 | grep -oP '(?<=inet )[\\d.]+'")
	if err != nil || output == "" {
		output, err = n.remote.ExecuteCommand("ifconfig eth0 | grep -oP '(?<=inet )[0-9.]+'")
		if err != nil {
			return "", fmt.Errorf("failed to get drone IP: %v", err)
		}
	}
	return strings.TrimSpace(output), nil
}

func (n *Nessus) discoveryScan() (string, error) {
	logging.InfoLogger.Printf("Running discovery scan")

	cmd := fmt.Sprintf("sudo nmap --exclude %s -T4 -n -sn %s -PE -PP -PM -PO --min-parallelism 100 --max-parallelism 256 -oG -",
		n.droneIP, n.targetsList)

	output, err := n.remote.ExecuteCommand(cmd)
	if err != nil {
		return "", fmt.Errorf("discovery scan failed: %v", err)
	}

	var aliveHosts []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Up") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				aliveHosts = append(aliveHosts, fields[1])
			}
		}
	}

	if len(aliveHosts) == 0 {
		return "", fmt.Errorf("no hosts are up")
	}

	return strings.Join(aliveHosts, ","), nil
}

func (n *Nessus) Deploy() error {
	return n.safeExecute("Deploy", func() error {
		if err := n.excludeTargets(); err != nil {
			return err
		}
		if err := n.createScan(true); err != nil {
			return err
		}

		err := n.monitorScan()
		if err == ErrScanCanceled {
			logging.InfoLogger.Printf("Scan was canceled, skipping export")
			return nil // Return nil to prevent crash reporting
		} else if err != nil {
			return err
		}

		_, err = n.exportScan()
		return err
	})
}

func (n *Nessus) Create() error {
	return n.safeExecute("Create", func() error {
		if err := n.excludeTargets(); err != nil {
			return err
		}
		return n.createScan(false)
	})
}

func (n *Nessus) Launch() error {
	return n.safeExecute("Launch", func() error {
		if err := n.scanAction("launch"); err != nil {
			return err
		}

		err := n.monitorScan()
		if err == ErrScanCanceled {
			logging.InfoLogger.Printf("Scan was canceled, skipping export")
			return nil // Return nil to prevent crash reporting
		} else if err != nil {
			return err
		}

		_, err = n.exportScan()
		return err
	})
}

func (n *Nessus) Pause() error {
	return n.safeExecute("Pause", func() error {
		return n.scanAction("pause")
	})
}

func (n *Nessus) Resume() error {
	return n.safeExecute("Resume", func() error {
		if err := n.scanAction("resume"); err != nil {
			return err
		}

		err := n.monitorScan()
		if err == ErrScanCanceled {
			logging.InfoLogger.Printf("Scan was canceled, skipping export")
			return nil // Return nil to prevent crash reporting
		} else if err != nil {
			return err
		}

		_, err = n.exportScan()
		return err
	})
}

func (n *Nessus) Monitor() error {
	return n.safeExecute("Monitor", func() error {
		err := n.monitorScan()
		if err == ErrScanCanceled {
			logging.InfoLogger.Printf("Scan was canceled, skipping export")
			return nil // Return nil to prevent crash reporting
		} else if err != nil {
			return err
		}

		_, err = n.exportScan()
		return err
	})
}

func (n *Nessus) Export() error {
	return n.safeExecute("Export", func() error {
		_, err := n.exportScan()
		return err
	})
}
