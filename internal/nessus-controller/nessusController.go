package nessus

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"NMB/internal/remote"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

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
}

type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (n *Nessus) getTokens() error {
	auth := Auth{
		Username: n.username,
		Password: n.password,
	}

	authData, err := json.Marshal(auth)
	if err != nil {
		return err
	}

	client := createInsecureClient()

	// Get cookie token
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
	log.Info("Retrieving API tokens")

	// Get tokens (cookie token and API token)
	if err := n.getTokens(); err != nil {
		log.Error("Failed to retrieve API tokens - check your login credentials")
		return err
	}

	// Get API keys
	if err := n.getAPIKeys(); err != nil {
		log.Error("Failed to retrieve API keys - check your login credentials")
		return err
	}

	log.Info("API tokens retrieved successfully")
	return nil
}

// Helper function to make authenticated requests
func (n *Nessus) makeRequest(method, endpoint string, body []byte) (*http.Response, error) {
	client := createInsecureClient()

	req, err := http.NewRequest(method, n.url+endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	// Add all authentication headers
	for k, v := range n.tokenAuth {
		req.Header.Set(k, v)
	}
	for k, v := range n.apiAuth {
		req.Header.Set(k, v)
	}

	return client.Do(req)
}

// Update the New function to use authenticate() instead of the old getAuth()
func New(host, username, password, projectName, targetsFile string, excludeFile []string, discovery bool) (*Nessus, error) {
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
		n.targetsList = strings.TrimSpace(string(content))
	}

	// Get drone IP and run discovery if needed
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

	// Authenticate with Nessus
	if err := n.authenticate(); err != nil {
		return nil, err
	}

	return n, nil
}

func (n *Nessus) createScan(launch bool) error {
	log.Info("Creating new scan")

	// Check if scan already exists
	if scan := n.getScanInfo(); scan != nil {
		log.Info("Scan already exists, aborting scan creation")
		return fmt.Errorf("scan name already exists")
	}

	// Get policy ID
	policies, err := n.getPolicies()
	if err != nil {
		log.Errorf("Failed to get policies: %v", err)
		return err
	}

	var policyID string
	for _, policy := range policies {
		log.Infof("Checking policy: %v", policy) // Debug print the policy object
		if policy["name"] == "Default Good Model Nessus Vulnerability Policy" {
			// Safely check if the id is a string or float64
			switch v := policy["id"].(type) {
			case string:
				policyID = v
				log.Infof("Found policy ID as string: %s", policyID)
			case float64:
				policyID = fmt.Sprintf("%v", v) // Convert float64 to string
				log.Infof("Found policy ID as float64 and converted: %s", policyID)
			default:
				return fmt.Errorf("unexpected type for policy ID: %T", v)
			}
			break
		}
	}

	if policyID == "" {
		log.Error("Policy not found")
		return fmt.Errorf("policy not found")
	}

	// Debug print before creating scan data
	log.Infof("Creating scan with policy ID: %s", policyID)

	// Create scan data
	scanData := map[string]interface{}{
		"settings": map[string]interface{}{
			"name":         n.projectName,
			"policy_id":    policyID,
			"launch_now":   launch,
			"enabled":      false,
			"scanner_id":   "1",
			"folder_id":    3,
			"text_targets": n.aliveHosts,
			"description":  "No host Discovery\nAll TCP port\nAll Service Discovery\nDefault passwords being tested\nGeneric Web Test\nNo compliance or local Check\nNo DOS plugins\n",
		},
	}

	// Debug print scan data
	scanDataJSON, err := json.Marshal(scanData)
	if err != nil {
		log.Errorf("Failed to marshal scan data: %v", err)
		return err
	}
	log.Infof("Scan data JSON: %s", string(scanDataJSON))

	// Make the request using our helper function
	resp, err := n.makeRequest(http.MethodPost, "/scans", scanDataJSON)
	if err != nil {
		log.Errorf("Failed to send HTTP request: %v", err)
		return err
	}
	defer resp.Body.Close()

	// Log response status code and body
	log.Infof("Received response: %s", resp.Status)
	if resp.StatusCode != http.StatusOK {
		log.Errorf("Failed to create scan, status code: %d", resp.StatusCode)
		return fmt.Errorf("failed to create scan: %s", resp.Status)
	}

	log.Info("Scan created successfully")
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

	// Create a map of hosts to exclude for O(1) lookup
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
		log.Error("Failed to get scans:", err)
		return nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Error("Failed to decode response:", err)
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

	log.Infof("Scan %s successful", action)
	return nil
}

// Monitor scan progress
func (n *Nessus) monitorScan() error {
	log.Info("Monitoring scan progress...")

	for {
		scan := n.getScanInfo()
		if scan == nil {
			return fmt.Errorf("scan not found")
		}

		status := fmt.Sprintf("%v", scan["status"])

		switch status {
		case "completed":
			log.Info("Scan completed successfully")
			return nil
		case "canceled", "failed":
			return fmt.Errorf("scan %s", status)
		case "running", "paused":
			progress, ok := scan["progress"].(float64)
			if ok {
				log.Infof("Scan progress: %.0f%%", progress)
			}
			time.Sleep(30 * time.Second)
		default:
			log.Infof("Scan status: %s", status)
			time.Sleep(30 * time.Second)
		}
	}
}

func (n *Nessus) exportScan() error {
	log.Info("Exporting scan results...")

	scan := n.getScanInfo()
	if scan == nil {
		return fmt.Errorf("scan not found")
	}

	scanID := fmt.Sprintf("%v", scan["id"])

	// Request export
	exportData := map[string]interface{}{
		"format":   "nessus",
		"chapters": "vuln_hosts_summary",
	}

	exportJSON, err := json.Marshal(exportData)
	if err != nil {
		return err
	}

	// Request the export
	resp, err := n.makeRequest(http.MethodPost, fmt.Sprintf("/scans/%s/export", scanID), exportJSON)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	fileID := fmt.Sprintf("%v", result["file"])
	if fileID == "" {
		return fmt.Errorf("export file ID not found")
	}

	// Monitor export status
	for {
		resp, err := n.makeRequest(http.MethodGet, fmt.Sprintf("/scans/%s/export/%s/status", scanID, fileID), nil)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			break
		}

		time.Sleep(5 * time.Second)
	}

	// Download the exported scan file
	resp, err = n.makeRequest(http.MethodGet, fmt.Sprintf("/scans/%s/export/%s/download", scanID, fileID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	outputFile := filepath.Join(n.outputFolder, fmt.Sprintf("%s.nessus", n.projectName))
	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	log.Infof("Scan results exported to: %s", outputFile)
	return nil
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
	output, err := n.remote.ExecuteCommand("hostname -i | cut -d' ' -f1")
	if err != nil {
		return "", fmt.Errorf("failed to get drone IP: %v", err)
	}
	return strings.TrimSpace(output), nil
}

func (n *Nessus) discoveryScan() (string, error) {
	log.Info("Running discovery scan")

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
	if err := n.excludeTargets(); err != nil {
		return err
	}
	if err := n.createScan(true); err != nil {
		return err
	}
	if err := n.monitorScan(); err != nil {
		return err
	}
	return n.exportScan()
}

func (n *Nessus) Create() error {
	if err := n.excludeTargets(); err != nil {
		return err
	}
	return n.createScan(false)
}

func (n *Nessus) Launch() error {
	if err := n.scanAction("launch"); err != nil {
		return err
	}
	if err := n.monitorScan(); err != nil {
		return err
	}
	return n.exportScan()
}

func (n *Nessus) Pause() error {
	return n.scanAction("pause")
}

func (n *Nessus) Resume() error {
	if err := n.scanAction("resume"); err != nil {
		return err
	}
	if err := n.monitorScan(); err != nil {
		return err
	}
	return n.exportScan()
}

func (n *Nessus) Monitor() error {
	if err := n.monitorScan(); err != nil {
		return err
	}
	return n.exportScan()
}

func (n *Nessus) Export() error {
	return n.exportScan()
}
