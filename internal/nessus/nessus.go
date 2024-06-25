package nessus

import (
	"NMB/internal/config"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
)

type Finding struct {
	PluginID    string
	Host        string
	Port        string
	Protocol    string
	Name        string
	Risk        string
	Description string
	Remedy      string
}

type PluginData struct {
	Host string
	Port string
	Name string
}

func ParseCSV(filePath string) ([]Finding, map[string]PluginData, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	reader := csv.NewReader(file)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, err
	}

	var findings []Finding
	pluginData := make(map[string]PluginData)

	for i, record := range records[1:] {
		if len(record) < 26 {
			return nil, nil, fmt.Errorf("record on line %d: wrong number of fields (got %d, expected at least 26)", i+2, len(record))
		}
		finding := Finding{
			PluginID:    record[0],  // Plugin ID
			Host:        record[4],  // Host
			Protocol:    record[5],  // Protocol
			Port:        record[6],  // Port
			Name:        record[7],  // Name
			Description: record[9],  // Description
			Remedy:      record[10], // Solution
			Risk:        record[3],  // Risk
		}
		findings = append(findings, finding)
		pluginData[finding.PluginID] = PluginData{
			Host: finding.Host,
			Port: finding.Port,
			Name: finding.Name,
		}
	}

	return findings, pluginData, nil
}

func GetSupportedAndMissingPlugins(findings []Finding, plugins map[string]config.Plugin) ([]string, []string) {
	var supportedPlugins []string
	var missingPlugins []string

	pluginNames := make(map[string]string)
	riskFactors := make(map[string]string)

	for _, finding := range findings {
		pluginNames[finding.PluginID] = finding.Name
		riskFactors[finding.PluginID] = finding.Risk
	}

	allPluginIDs := getAllPluginIDs(plugins)

	matchingPluginIDs := intersect(allPluginIDs, pluginNames)

	for pluginID, pluginName := range pluginNames {
		if _, found := matchingPluginIDs[pluginID]; found && riskFactors[pluginID] != "None" {
			supportedPlugins = append(supportedPlugins, pluginName)
		} else {
			missingPlugins = append(missingPlugins, pluginName)
		}
	}

	sort.Strings(supportedPlugins)
	sort.Strings(missingPlugins)

	return supportedPlugins, missingPlugins
}

func getAllPluginIDs(plugins map[string]config.Plugin) map[string]struct{} {
	pluginIDs := make(map[string]struct{})
	for _, plugin := range plugins {
		for _, id := range plugin.IDs {
			pluginIDs[id] = struct{}{}
		}
	}
	return pluginIDs
}

func intersect(a map[string]struct{}, b map[string]string) map[string]struct{} {
	result := make(map[string]struct{})
	for k := range b {
		if _, found := a[k]; found {
			result[k] = struct{}{}
		}
	}
	return result
}
