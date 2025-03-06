// Package converter provides functionality to convert Nessus CSV files to Plextrac format
package converter

import (
	"crypto/md5"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// NessusToPlextracConverter handles conversion of Nessus scan results to Plextrac format
type NessusToPlextracConverter struct {
	NessusDirectory       string
	Args                  map[string]interface{}
	Mode                  string
	Config                map[string]interface{}
	PluginCategories      map[string]string
	MergedFindings        map[string]map[string]interface{}
	IndividualFindings    []map[string]string
	MergedPluginIDs       map[string]bool
	OrganizedDescriptions map[string]string
	TagMap                map[string]string
}

// NewNessusToPlextracConverter creates a new converter instance
func NewNessusToPlextracConverter(nessusDirectory string, config map[string]interface{}, mode string, args map[string]interface{}) *NessusToPlextracConverter {
	return &NessusToPlextracConverter{
		NessusDirectory:       nessusDirectory,
		Args:                  args,
		Mode:                  mode,
		Config:                config,
		PluginCategories:      make(map[string]string),
		MergedFindings:        make(map[string]map[string]interface{}),
		IndividualFindings:    []map[string]string{},
		MergedPluginIDs:       make(map[string]bool),
		OrganizedDescriptions: make(map[string]string),
		TagMap: map[string]string{
			"internal":     "internal_finding",
			"external":     "external_finding",
			"surveillance": "surveillance_finding",
			"web":          "webapp_finding",
			"mobile":       "mobileapp_finding",
		},
	}
}

// BuildPluginCategories builds a mapping of plugin IDs to their categories
func (c *NessusToPlextracConverter) BuildPluginCategories() error {
	plugins, ok := c.Config["plugins"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("plugins section not found in configuration")
	}

	for category, details := range plugins {
		categoryDetails, ok := details.(map[string]interface{})
		if !ok {
			continue
		}

		ids, ok := categoryDetails["ids"].([]interface{})
		if !ok {
			continue
		}

		for _, id := range ids {
			pluginID, ok := id.(string)
			if !ok {
				continue
			}
			c.PluginCategories[pluginID] = category
		}
	}

	return nil
}

// ProcessNessusCSV processes all CSV files in the Nessus directory
func (c *NessusToPlextracConverter) ProcessNessusCSV() error {
	csvFound := false

	files, err := ioutil.ReadDir(c.NessusDirectory)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".csv") {
			csvFound = true
			if err := c.ProcessCSVFile(file.Name()); err != nil {
				return fmt.Errorf("failed to process CSV file %s: %w", file.Name(), err)
			}
		}
	}

	if !csvFound {
		return fmt.Errorf("no CSV files found in the provided directory: %s", c.NessusDirectory)
	}

	return nil
}

// ProcessCSVFile processes a single CSV file
func (c *NessusToPlextracConverter) ProcessCSVFile(fileName string) error {
	filePath := filepath.Join(c.NessusDirectory, fileName)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // Allow variable number of fields

	// Read header
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Process rows
	for {
		record, err := reader.Read()
		if err != nil {
			break // End of file or error
		}

		row := make(map[string]string)
		for i, value := range record {
			if i < len(header) {
				row[header[i]] = value
			}
		}

		c.ProcessCSVRow(row)
	}

	return nil
}

// ProcessCSVRow processes a single row from a CSV file
func (c *NessusToPlextracConverter) ProcessCSVRow(row map[string]string) {
	// Skip "None" risk findings
	if row["Risk"] == "None" {
		return
	}

	pluginID := row["Plugin ID"]
	if pluginID == "11213" { // Ignore "Track/Trace" plugin
		return
	}

	if category, ok := c.PluginCategories[pluginID]; ok {
		c.AddMergedFinding(row, pluginID, category)
	} else {
		c.IndividualFindings = append(c.IndividualFindings, row)
	}
}

// AddMergedFinding adds a finding to the merged findings
func (c *NessusToPlextracConverter) AddMergedFinding(row map[string]string, pluginID string, category string) {
	if _, ok := c.MergedFindings[category]; !ok {
		c.MergedFindings[category] = map[string]interface{}{
			"findings":        []map[string]string{},
			"affected_assets": map[string]bool{},
		}
	}

	findings := c.MergedFindings[category]["findings"].([]map[string]string)
	c.MergedFindings[category]["findings"] = append(findings, row)

	assetKey := fmt.Sprintf("%s:%s", row["Host"], row["Port"])
	affectedAssets := c.MergedFindings[category]["affected_assets"].(map[string]bool)
	affectedAssets[assetKey] = true
	c.MergedFindings[category]["affected_assets"] = affectedAssets

	c.MergedPluginIDs[pluginID] = true
}

// WriteToPlextracCSV writes findings to a CSV file in Plextrac format
func (c *NessusToPlextracConverter) WriteToPlextracCSV(outputCSVPath string) error {
	file, err := os.Create(outputCSVPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"title", "severity", "status", "description", "recommendations",
		"references", "affected_assets", "tags", "cvss_temporal",
		"cwe", "cve", "category",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write merged findings
	if err := c.WriteMergedFindings(writer); err != nil {
		return fmt.Errorf("failed to write merged findings: %w", err)
	}

	// Write individual findings
	if err := c.WriteIndividualFindings(writer); err != nil {
		return fmt.Errorf("failed to write individual findings: %w", err)
	}

	return nil
}

// WriteMergedFindings writes merged findings to the CSV writer
func (c *NessusToPlextracConverter) WriteMergedFindings(writer *csv.Writer) error {
	titlePrefix := c.GetTitlePrefix()
	tag := c.GetTag()

	plugins, ok := c.Config["plugins"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("plugins section not found in configuration")
	}

	for category, details := range c.MergedFindings {
		categoryConfig, ok := plugins[category].(map[string]interface{})
		if !ok {
			continue
		}

		writeupName, ok := categoryConfig["writeup_name"].(string)
		if !ok {
			continue
		}

		findings := details["findings"].([]map[string]string)
		if len(findings) == 0 {
			continue
		}

		// Group findings by name
		findingGroups := c.GroupFindingsByName(findings, category)

		// Get highest severity
		highestSeverity := c.GetHighestSeverity(findings)

		// Get final tags
		finalTags := c.GetFinalTags(tag, highestSeverity)

		// Generate full description for the category
		fullDescription := c.GetFullDescription(findingGroups, category)
		c.OrganizedDescriptions[category] = fullDescription

		// Generate references (MD5 hashes)
		references := c.GetReferences(findings)

		// Get affected assets string
		affectedAssets := c.GetAffectedAssetsString(details["affected_assets"].(map[string]bool))

		// Write to CSV
		record := []string{
			titlePrefix + writeupName,
			highestSeverity,
			"Open",
			"FIXME", // Will be updated later
			"FIXME", // Will be updated later
			references,
			affectedAssets,
			finalTags,
			"", // cvss_temporal
			"", // cwe
			"", // cve
			"", // category
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	return nil
}

// WriteIndividualFindings writes individual findings to the CSV writer
func (c *NessusToPlextracConverter) WriteIndividualFindings(writer *csv.Writer) error {
	titlePrefix := c.GetTitlePrefix()
	tag := c.GetTag()

	for _, finding := range c.IndividualFindings {
		severity := finding["Risk"]
		finalTags := c.GetFinalTags(tag, severity)
		description := c.FormatText(finding["Description"])
		recommendations := c.FormatText(finding["Solution"])

		// Create MD5 hash of the finding name
		hash := md5.Sum([]byte(strings.ToLower(finding["Name"])))
		md5Hash := hex.EncodeToString(hash[:])

		affectedAssets := fmt.Sprintf("%s (%s %s)", finding["Host"], finding["Protocol"], finding["Port"])

		record := []string{
			titlePrefix + finding["Name"],
			severity,
			"Open",
			description,
			recommendations,
			md5Hash + " " + finding["See Also"],
			affectedAssets,
			finalTags,
			"",             // cvss_temporal
			"",             // cwe
			finding["CVE"], // cve
			"",             // category
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	return nil
}

// GroupFindingsByName groups findings by their name
func (c *NessusToPlextracConverter) GroupFindingsByName(findings []map[string]string, category string) map[string][]map[string]string {
	groups := make(map[string][]map[string]string)

	for _, finding := range findings {
		name := finding["Name"]
		var groupName string

		if category == "Software Components Out of Date and Vulnerable" {
			// Extract main category using regex
			re := regexp.MustCompile(`([a-zA-Z\s]+)`)
			match := re.FindStringSubmatch(name)
			if len(match) > 1 {
				groupName = strings.TrimSpace(match[1])
			} else {
				groupName = name
			}
		} else {
			groupName = name
		}

		if _, ok := groups[groupName]; !ok {
			groups[groupName] = []map[string]string{}
		}
		groups[groupName] = append(groups[groupName], finding)
	}

	return groups
}

// GetHighestSeverity returns the highest severity level among findings
func (c *NessusToPlextracConverter) GetHighestSeverity(findings []map[string]string) string {
	severityMap := map[string]int{
		"Critical":      5,
		"High":          4,
		"Medium":        3,
		"Low":           2,
		"Informational": 1,
	}

	highestValue := 0
	for _, finding := range findings {
		if value, ok := severityMap[finding["Risk"]]; ok && value > highestValue {
			highestValue = value
		}
	}

	for severity, value := range severityMap {
		if value == highestValue {
			return severity
		}
	}

	return "Low" // Default
}

// GetFinalTags returns the final tags based on severity
func (c *NessusToPlextracConverter) GetFinalTags(tag string, severity string) string {
	severityTag, complexityTag := c.MapSeverityToTags(severity)
	return fmt.Sprintf("%s,%s,%s", tag, severityTag, complexityTag)
}

// MapSeverityToTags maps severity to priority and complexity tags
func (c *NessusToPlextracConverter) MapSeverityToTags(severity string) (string, string) {
	severityMap := map[string]string{
		"Low":           "priority_low",
		"Medium":        "priority_medium",
		"High":          "priority_high",
		"Critical":      "priority_high",
		"Informational": "priority_low",
	}

	complexityMap := map[string]string{
		"Low":           "complexity_easy",
		"Medium":        "complexity_intermediate",
		"High":          "complexity_complex",
		"Critical":      "complexity_complex",
		"Informational": "complexity_easy",
	}

	return severityMap[severity], complexityMap[severity]
}

// GetTag returns the appropriate tag based on the mode
func (c *NessusToPlextracConverter) GetTag() string {
	tag, ok := c.TagMap[c.Mode]
	if !ok {
		return "internal_finding" // Default
	}
	return tag
}

// GetTitlePrefix returns the appropriate title prefix based on the mode
func (c *NessusToPlextracConverter) GetTitlePrefix() string {
	prefixMap := map[string]string{
		"external":     "(External) ",
		"web":          "(Web) ",
		"surveillance": "(Surveillance) ",
		"mobile":       "(Mobile) ",
		"internal":     "",
	}

	prefix, ok := prefixMap[c.Mode]
	if !ok {
		return ""
	}
	return prefix
}

// GetFullDescription generates the full description for grouped findings
func (c *NessusToPlextracConverter) GetFullDescription(findingGroups map[string][]map[string]string, category string) string {
	var descriptions []string

	for groupName, findings := range findingGroups {
		highestSeverity := c.GetHighestSeverity(findings)
		assets := c.GetAffectedAssetsString(c.ExtractAssetsFromFindings(findings))

		var descriptionChunk string
		if category == "Software Components Out of Date and Vulnerable" {
			descriptionChunk = fmt.Sprintf("<p><b>%s Lack of Updates (severity: %s)</b></p><ul>%s</ul>",
				groupName,
				strings.ToLower(highestSeverity),
				c.FormatAssetsList(assets),
			)
		} else {
			descriptionChunk = fmt.Sprintf("<p><b>%s (severity: %s)</b></p><ul>%s</ul>",
				groupName,
				strings.ToLower(highestSeverity),
				c.FormatAssetsList(assets),
			)
		}

		descriptions = append(descriptions, descriptionChunk)
	}

	return strings.Join(descriptions, "\n\n")
}

// FormatAssetsList formats a list of assets as HTML list items
func (c *NessusToPlextracConverter) FormatAssetsList(assetsStr string) string {
	assets := strings.Split(assetsStr, ",")
	var items []string
	for _, asset := range assets {
		items = append(items, fmt.Sprintf("<li>%s</li>", strings.TrimSpace(asset)))
	}
	return strings.Join(items, "")
}

// ExtractAssetsFromFindings extracts unique assets from findings
func (c *NessusToPlextracConverter) ExtractAssetsFromFindings(findings []map[string]string) map[string]bool {
	assets := make(map[string]bool)
	for _, finding := range findings {
		key := fmt.Sprintf("%s:%s", finding["Host"], finding["Port"])
		assets[key] = true
	}
	return assets
}

// GetReferences generates references based on MD5 hashes
func (c *NessusToPlextracConverter) GetReferences(findings []map[string]string) string {
	hashSet := make(map[string]bool)
	for _, finding := range findings {
		hash := md5.Sum([]byte(strings.ToLower(finding["Name"])))
		hashSet[hex.EncodeToString(hash[:])] = true
	}

	var hashes []string
	for hash := range hashSet {
		hashes = append(hashes, hash)
	}

	return strings.Join(hashes, ";")
}

// GetAffectedAssetsString generates a string representing the affected assets
func (c *NessusToPlextracConverter) GetAffectedAssetsString(assets map[string]bool) string {
	// Group by host and protocol
	hostProtocolPorts := make(map[string][]string)
	for asset := range assets {
		parts := strings.Split(asset, ":")
		if len(parts) != 2 {
			continue
		}

		host := parts[0]
		port := parts[1]

		// Default to TCP if protocol is not available
		protocol := "tcp"
		key := fmt.Sprintf("%s (%s", host, protocol)

		if _, ok := hostProtocolPorts[key]; !ok {
			hostProtocolPorts[key] = []string{}
		}
		hostProtocolPorts[key] = append(hostProtocolPorts[key], port)
	}

	var assetStrings []string
	for hostProtocol, ports := range hostProtocolPorts {
		uniquePorts := make(map[string]bool)
		for _, port := range ports {
			uniquePorts[port] = true
		}

		var portList []string
		for port := range uniquePorts {
			portList = append(portList, port)
		}

		assetStrings = append(assetStrings, fmt.Sprintf("%s %s)", hostProtocol, strings.Join(portList, "; ")))
	}

	return strings.Join(assetStrings, ", ")
}

// FormatText removes carriage returns and newlines
func (c *NessusToPlextracConverter) FormatText(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r", ""), "\n", " ")
}

// Convert processes Nessus CSV files and writes the findings to Plextrac format
func (c *NessusToPlextracConverter) Convert(outputCSVPath string) error {
	// Build plugin categories
	if err := c.BuildPluginCategories(); err != nil {
		return fmt.Errorf("failed to build plugin categories: %w", err)
	}

	// Process Nessus CSV files
	if err := c.ProcessNessusCSV(); err != nil {
		return fmt.Errorf("failed to process Nessus CSV: %w", err)
	}

	// Write to Plextrac CSV
	if err := c.WriteToPlextracCSV(outputCSVPath); err != nil {
		return fmt.Errorf("failed to write to Plextrac CSV: %w", err)
	}

	return nil
}

func (c *NessusToPlextracConverter) GetOrganizedDescriptions() map[string]string {
	return c.OrganizedDescriptions
}

// GetConfig returns the configuration
func (c *NessusToPlextracConverter) GetConfig() map[string]interface{} {
	return c.Config
}

// GetMode returns the mode
func (c *NessusToPlextracConverter) GetMode() string {
	return c.Mode
}
