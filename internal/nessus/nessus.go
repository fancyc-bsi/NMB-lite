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
    defer file.Close()

    reader := csv.NewReader(file)
    reader.LazyQuotes = true
    reader.FieldsPerRecord = -1

    records, err := reader.ReadAll()
    if err != nil {
        return nil, nil, err
    }

    var findings []Finding
    pluginData := make(map[string]PluginData)
    uniqueFindings := make(map[string]struct{})

    for i, record := range records[1:] {
        if len(record) < 26 {
            return nil, nil, fmt.Errorf("record on line %d: wrong number of fields (got %d, expected at least 26)", i+2, len(record))
        }

        if record[3] == "None" { // Skip findings with "None" severity
            continue
        }

        pluginID := record[0]
        if _, exists := uniqueFindings[pluginID]; exists {
            continue // Skip duplicates
        }

        finding := Finding{
            PluginID:    pluginID,
            Host:        record[4],
            Protocol:    record[5],
            Port:        record[6],
            Name:        record[7],
            Description: record[9],
            Remedy:      record[10],
            Risk:        record[3],
        }
        
        findings = append(findings, finding)
        pluginData[pluginID] = PluginData{
            Host: finding.Host,
            Port: finding.Port,
            Name: finding.Name,
        }

        uniqueFindings[pluginID] = struct{}{}
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
