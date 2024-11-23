// internal/plugin/manager.go
package plugin

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	TempFile            = "temp.json"
	IgnorePlugin        = "11213"
	IgnoreInformational = "None"
)

type Config struct {
	Plugins map[string]PluginCategory `json:"plugins"`
}

type PluginCategory struct {
	IDs []string `json:"ids"`
}

type Finding struct {
	PluginID string
	Name     string
	Risk     string
}

type Manager struct {
	configPath  string
	csvPath     string
	config      *Config
	findings    []Finding
	TempChanges map[string][]string
}

func NewManager(configPath, csvPath string) (*Manager, error) {
	m := &Manager{
		configPath:  configPath,
		csvPath:     csvPath,
		TempChanges: make(map[string][]string),
	}

	var err error
	m.config, err = m.readJSONFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	m.findings, err = m.readFindingsCSV(csvPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read findings CSV: %w", err)
	}

	return m, nil
}

func (m *Manager) readJSONFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (m *Manager) writeJSONFile(path string, data interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(data)
}

func (m *Manager) readFindingsCSV(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	headers, err := reader.Read()
	if err != nil {
		return nil, err
	}

	// Find column indices
	var pluginIDIdx, nameIdx, riskIdx int
	for i, header := range headers {
		switch header {
		case "Plugin ID":
			pluginIDIdx = i
		case "Name":
			nameIdx = i
		case "Risk":
			riskIdx = i
		}
	}

	var findings []Finding
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if record[riskIdx] != "" {
			findings = append(findings, Finding{
				PluginID: record[pluginIDIdx],
				Name:     record[nameIdx],
				Risk:     record[riskIdx],
			})
		}
	}

	return findings, nil
}

func (m *Manager) IdentifyMergedFindings() (map[string][]string, []string) {
	mergedFindings := make(map[string][]string)
	var individualFindings []string

	pluginCategories := m.buildPluginCategories()

	for _, finding := range m.findings {
		if finding.Risk == IgnoreInformational || finding.PluginID == IgnorePlugin {
			continue
		}

		if category, exists := pluginCategories[finding.PluginID]; exists {
			pluginInfo := fmt.Sprintf("Plugin ID: %s, Name: %s", finding.PluginID, finding.Name)
			mergedFindings[category] = append(mergedFindings[category], pluginInfo)
		} else {
			individualFindings = append(individualFindings,
				fmt.Sprintf("Plugin ID: %s, Name: %s", finding.PluginID, finding.Name))
		}
	}

	return mergedFindings, individualFindings
}

func (m *Manager) buildPluginCategories() map[string]string {
	categories := make(map[string]string)
	for category, details := range m.config.Plugins {
		for _, id := range details.IDs {
			categories[id] = category
		}
	}
	return categories
}

func (m *Manager) RemovePlugin(category string, pluginID string) error {
	if _, exists := m.config.Plugins[category]; !exists {
		return fmt.Errorf("category %s does not exist", category)
	}

	ids := m.config.Plugins[category].IDs
	for i, id := range ids {
		if id == pluginID {
			updatedIDs := append(ids[:i], ids[i+1:]...)
			categoryConfig := m.config.Plugins[category]
			categoryConfig.IDs = updatedIDs
			m.config.Plugins[category] = categoryConfig
			m.TempChanges[category] = m.config.Plugins[category].IDs
			return nil
		}
	}

	return fmt.Errorf("plugin %s not found in category %s", pluginID, category)
}

func (m *Manager) AddPlugin(category string, pluginID string) error {
	if _, exists := m.config.Plugins[category]; !exists {
		return fmt.Errorf("category %s does not exist", category)
	}

	// Check if plugin already exists in category
	for _, id := range m.config.Plugins[category].IDs {
		if id == pluginID {
			return fmt.Errorf("plugin %s already exists in category %s", pluginID, category)
		}
	}

	categoryConfig := m.config.Plugins[category]
	categoryConfig.IDs = append(categoryConfig.IDs, pluginID)
	m.config.Plugins[category] = categoryConfig
	m.TempChanges[category] = categoryConfig.IDs
	return nil
}

func (m *Manager) WriteChanges() error {
	if len(m.TempChanges) == 0 {
		return fmt.Errorf("no changes to write")
	}

	for category, ids := range m.TempChanges {
		categoryConfig := m.config.Plugins[category]
		categoryConfig.IDs = ids
		m.config.Plugins[category] = categoryConfig
	}

	if err := m.writeJSONFile(m.configPath, m.config); err != nil {
		return fmt.Errorf("failed to write changes: %w", err)
	}

	m.TempChanges = make(map[string][]string)
	return nil
}

func (m *Manager) ClearChanges() {
	m.TempChanges = make(map[string][]string)
}

func (m *Manager) ViewChanges() {
	if len(m.TempChanges) == 0 {
		fmt.Println("No pending changes")
		return
	}

	fmt.Println("\nPending Changes:")
	categories := make([]string, 0, len(m.TempChanges))
	for category := range m.TempChanges {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	for _, category := range categories {
		fmt.Printf("\n• %s:\n", category)
		for _, id := range m.TempChanges[category] {
			fmt.Printf("  └── %s\n", id)
		}
	}
}

func (m *Manager) SimulateFindings() {
	merged, individual := m.IdentifyMergedFindings()

	divider := strings.Repeat("=", 50)
	fmt.Printf("\n%s\n     Simulated Merged and Individual Findings\n%s\n", divider, divider)

	// Print Merged Findings
	fmt.Println("\nMerged Findings:")
	categories := make([]string, 0, len(merged))
	for category := range merged {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	for _, category := range categories {
		fmt.Printf("\n• %s:\n", category)
		for _, finding := range merged[category] {
			fmt.Printf("  └── %s\n", finding)
		}
	}

	// Print Individual Findings
	fmt.Println("\nIndividual Findings:")
	for _, finding := range individual {
		fmt.Printf("  • %s\n", finding)
	}

	fmt.Printf("\n%s\n", divider)
}

func (m *Manager) GetCategories() []string {
	categories := make([]string, 0, len(m.config.Plugins))
	for category := range m.config.Plugins {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	return categories
}

func (m *Manager) GetPluginNames() map[string]string {
	names := make(map[string]string)
	for _, finding := range m.findings {
		names[finding.PluginID] = finding.Name
	}
	return names
}
