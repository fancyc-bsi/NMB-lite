package plugin

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// Constants
const (
	TempFile            = "temp.json"
	IgnorePlugin        = "11213"
	IgnoreInformational = "None"
)

// Config represents the overall configuration structure
type Config struct {
	Plugins map[string]PluginCategory `json:"plugins"`
}

// PluginCategory represents a category of plugins in the config
type PluginCategory struct {
	IDs         []string `json:"ids"`
	WriteupDBID string   `json:"writeup_db_id"`
	WriteupName string   `json:"writeup_name"`
}

// Finding represents a finding from the CSV file
type Finding struct {
	PluginID string
	Name     string
	Risk     string
}

// PluginInfo represents a plugin with its ID and name
type PluginInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CategoryInfo represents category information
type CategoryInfo struct {
	Name        string       `json:"name"`
	WriteupDBID string       `json:"writeup_db_id"`
	WriteupName string       `json:"writeup_name"`
	PluginCount int          `json:"plugin_count"`
	Plugins     []PluginInfo `json:"plugins,omitempty"`
}

// Manager handles operations on plugins
type Manager struct {
	ConfigPath  string
	CSVPath     string
	Config      Config
	Findings    []Finding
	TempChanges map[string][]string
	PluginNames map[string]string
	mu          sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager(configPath, csvPath string) (*Manager, error) {
	pm := &Manager{
		ConfigPath:  configPath,
		CSVPath:     csvPath,
		TempChanges: make(map[string][]string),
		PluginNames: make(map[string]string),
	}

	// Load the configuration
	err := pm.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Load the findings if CSV path is provided
	if csvPath != "" {
		err = pm.LoadFindings()
		if err != nil {
			return nil, fmt.Errorf("failed to load findings: %w", err)
		}

		// Load plugin names
		pm.LoadPluginNames()
	}

	return pm, nil
}

// LoadConfig loads the configuration from the file
func (pm *Manager) LoadConfig() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	file, err := os.Open(pm.ConfigPath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&pm.Config)
	if err != nil {
		return err
	}

	return nil
}

// SaveConfig saves the configuration to the file
func (pm *Manager) SaveConfig() error {
	// Note: This method assumes the caller has already acquired the lock if needed

	// Create a temporary file first
	tempPath := pm.ConfigPath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		fmt.Printf("Error creating temp file: %v\n", err)
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	// Use defer with a named return value to handle file closure properly
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("error closing file: %w", closeErr)
		}
	}()

	// Encode the config to the temp file
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	encodeErr := encoder.Encode(pm.Config)
	if encodeErr != nil {
		fmt.Printf("Error encoding config: %v\n", encodeErr)
		return fmt.Errorf("failed to encode config: %w", encodeErr)
	}

	// Make sure changes are written to disk
	if err := file.Sync(); err != nil {
		fmt.Printf("Error syncing file: %v\n", err)
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Close the file before renaming
	if err := file.Close(); err != nil {
		fmt.Printf("Error closing file: %v\n", err)
		return fmt.Errorf("failed to close file: %w", err)
	}

	// Rename the temp file to the final config file (atomic operation)
	if err := os.Rename(tempPath, pm.ConfigPath); err != nil {
		fmt.Printf("Error renaming temp file: %v\n", err)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	fmt.Println("Config saved successfully to", pm.ConfigPath)
	return nil
}

// LoadFindings loads the findings from the CSV file
func (pm *Manager) LoadFindings() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.CSVPath == "" {
		return errors.New("CSV path not set")
	}

	// Open the CSV file
	file, err := os.Open(pm.CSVPath)
	if err != nil {
		return fmt.Errorf("error opening CSV file: %w", err)
	}
	defer file.Close()

	// Create a CSV reader
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable number of fields

	// Read all records
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("error reading CSV file: %w", err)
	}

	if len(records) == 0 {
		return fmt.Errorf("empty CSV file")
	}

	// Get header row
	headerRow := records[0]

	// Find column indices
	pluginIDIdx := -1
	nameIdx := -1
	riskIdx := -1

	// Look for exact column names
	for i, col := range headerRow {
		col = strings.TrimSpace(col)
		switch strings.ToLower(col) {
		case "plugin id":
			pluginIDIdx = i
		case "name":
			nameIdx = i
		case "risk":
			riskIdx = i
		}
	}

	// If columns not found, use defaults for standard Nessus format
	if pluginIDIdx == -1 {
		pluginIDIdx = 0 // First column is usually Plugin ID
	}
	if nameIdx == -1 && len(headerRow) > 1 {
		nameIdx = 1 // Second column is usually Name
	}
	if riskIdx == -1 && len(headerRow) > 2 {
		riskIdx = 2 // Third column is usually Risk
	}

	// Clear existing findings
	pm.Findings = []Finding{}
	pm.PluginNames = make(map[string]string)

	// Process data rows
	for i := 1; i < len(records); i++ {
		row := records[i]

		// Skip if not enough fields
		if len(row) <= pluginIDIdx || (nameIdx >= 0 && len(row) <= nameIdx) {
			continue
		}

		// Get Plugin ID and Name
		pluginID := strings.TrimSpace(row[pluginIDIdx])

		// Skip if plugin ID is empty
		if pluginID == "" {
			continue
		}

		// Get name
		var name string
		if nameIdx >= 0 && len(row) > nameIdx {
			name = strings.TrimSpace(row[nameIdx])
		}

		// If name is empty, use plugin ID
		if name == "" {
			name = "Plugin " + pluginID
		}

		// Get risk if available
		risk := "Medium" // Default
		if riskIdx >= 0 && len(row) > riskIdx {
			risk = strings.TrimSpace(row[riskIdx])
			if risk == "" {
				risk = "Medium" // Default
			}
		}

		// Skip specific plugins
		if pluginID == IgnorePlugin {
			continue
		}

		// Skip informational findings
		if risk == IgnoreInformational {
			continue
		}

		// Add to findings
		pm.Findings = append(pm.Findings, Finding{
			PluginID: pluginID,
			Name:     name,
			Risk:     risk,
		})

		// Add to plugin names
		pm.PluginNames[pluginID] = name
	}

	return nil
}

// LoadPluginNames loads all plugin names from the CSV file
func (pm *Manager) LoadPluginNames() error {
	// If we already have loaded findings, use those to populate plugin names
	if len(pm.Findings) > 0 {
		pm.mu.Lock()
		pm.PluginNames = make(map[string]string)
		for _, finding := range pm.Findings {
			pm.PluginNames[finding.PluginID] = finding.Name
		}
		pm.mu.Unlock()
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.CSVPath == "" {
		return errors.New("CSV path not set")
	}

	file, err := os.Open(pm.CSVPath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Make the reader more permissive
	reader.FieldsPerRecord = -1    // Allow variable number of fields
	reader.LazyQuotes = true       // Allow lazy quotes
	reader.TrimLeadingSpace = true // Trim leading space

	// Read header
	header, err := reader.Read()
	if err != nil {
		return err
	}

	// Trim and normalize header fields
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}

	// Try different possible header names
	var pluginIDIdx, nameIdx int = -1, -1

	// Possible column names for Plugin ID
	pluginIDNames := []string{"Plugin ID", "PluginID", "Plugin Id", "plugin id", "plugin_id", "ID", "id"}
	// Possible column names for Name
	nameNames := []string{"Name", "name", "Plugin Name", "plugin name", "plugin_name", "Title", "title"}

	// Find indices using case-insensitive matching
	for i, col := range header {
		colLower := strings.ToLower(col)

		// Check for Plugin ID
		for _, name := range pluginIDNames {
			if strings.ToLower(name) == colLower {
				pluginIDIdx = i
				break
			}
		}

		// Check for Name
		for _, name := range nameNames {
			if strings.ToLower(name) == colLower {
				nameIdx = i
				break
			}
		}
	}

	// If we couldn't find the columns by name, try to guess by position for common formats
	if pluginIDIdx == -1 && len(header) > 0 {
		pluginIDIdx = 0 // First column is often Plugin ID
	}

	if nameIdx == -1 && len(header) > 1 {
		nameIdx = 1 // Second column is often Name
	}

	// If we still couldn't identify columns, return an error
	if pluginIDIdx == -1 || nameIdx == -1 {
		return errors.New("couldn't identify required columns in the CSV file")
	}

	// Clear existing plugin names
	pm.PluginNames = make(map[string]string)

	// Use a map to ensure uniqueness
	uniquePlugins := make(map[string]string)

	// Read the rest of the records
	lineNumber := 1 // Start at line 1 for the header
	for {
		lineNumber++
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Log the error but continue processing
			fmt.Printf("Warning: error reading CSV line %d: %v\n", lineNumber, err)
			continue
		}

		// Skip if we don't have enough fields
		if len(record) <= pluginIDIdx || len(record) <= nameIdx {
			continue
		}

		// Get Plugin ID and Name, trim whitespace
		pluginID := strings.TrimSpace(record[pluginIDIdx])
		name := strings.TrimSpace(record[nameIdx])

		// Skip if plugin ID is empty
		if pluginID == "" {
			continue
		}

		// Store in map to ensure uniqueness
		uniquePlugins[pluginID] = name
	}

	// Set plugin names
	for pluginID, name := range uniquePlugins {
		pm.PluginNames[pluginID] = name
	}

	return nil
}

// GetPluginNames returns a map of plugin IDs to names
func (pm *Manager) GetPluginNames() map[string]string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Create a copy to avoid race conditions
	names := make(map[string]string)
	for id, name := range pm.PluginNames {
		names[id] = name
	}

	return names
}

// BuildPluginCategories creates a map of plugin IDs to categories
func (pm *Manager) BuildPluginCategories() map[string]string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	categories := make(map[string]string)
	for category, details := range pm.Config.Plugins {
		for _, pluginID := range details.IDs {
			categories[pluginID] = category
		}
	}
	return categories
}

// GetCategories returns all available categories
func (pm *Manager) GetCategories() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	categories := make([]string, 0, len(pm.Config.Plugins))
	for category := range pm.Config.Plugins {
		categories = append(categories, category)
	}

	// Sort categories alphabetically
	sort.Strings(categories)

	return categories
}

// GetCategoryDetails returns detailed information about all categories
func (pm *Manager) GetCategoryDetails() []CategoryInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	categories := make([]CategoryInfo, 0, len(pm.Config.Plugins))
	for name, category := range pm.Config.Plugins {
		categories = append(categories, CategoryInfo{
			Name:        name,
			WriteupDBID: category.WriteupDBID,
			WriteupName: category.WriteupName,
			PluginCount: len(category.IDs),
		})
	}

	// Sort categories alphabetically by name
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	return categories
}

// GetCategoryInfo returns detailed information about a specific category
func (pm *Manager) GetCategoryInfo(category string) (*CategoryInfo, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if _, exists := pm.Config.Plugins[category]; !exists {
		return nil, fmt.Errorf("category %s does not exist", category)
	}

	cat := pm.Config.Plugins[category]
	plugins := make([]PluginInfo, 0, len(cat.IDs))

	for _, id := range cat.IDs {
		name, exists := pm.PluginNames[id]
		if !exists {
			name = "Unknown"
		}
		plugins = append(plugins, PluginInfo{
			ID:   id,
			Name: name,
		})
	}

	return &CategoryInfo{
		Name:        category,
		WriteupDBID: cat.WriteupDBID,
		WriteupName: cat.WriteupName,
		PluginCount: len(cat.IDs),
		Plugins:     plugins,
	}, nil
}

// GetPluginsByCategory gets all plugins in a category
func (pm *Manager) GetPluginsByCategory(category string) ([]PluginInfo, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if _, exists := pm.Config.Plugins[category]; !exists {
		return nil, fmt.Errorf("category %s does not exist", category)
	}

	plugins := make([]PluginInfo, 0)
	for _, id := range pm.Config.Plugins[category].IDs {
		name, exists := pm.PluginNames[id]
		if !exists {
			name = "Unknown"
		}
		plugins = append(plugins, PluginInfo{
			ID:   id,
			Name: name,
		})
	}

	// Sort plugins by name
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Name < plugins[j].Name
	})

	return plugins, nil
}

// FilterPluginsByName filters plugins in a category by name
func (pm *Manager) FilterPluginsByName(category string, filterStr string) ([]PluginInfo, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if _, exists := pm.Config.Plugins[category]; !exists {
		return nil, fmt.Errorf("category %s does not exist", category)
	}

	if filterStr == "" {
		return pm.GetPluginsByCategory(category)
	}

	plugins := make([]PluginInfo, 0)
	filterLower := strings.ToLower(filterStr)

	for _, id := range pm.Config.Plugins[category].IDs {
		name, exists := pm.PluginNames[id]
		if !exists {
			name = "Unknown"
		}

		if strings.Contains(strings.ToLower(name), filterLower) ||
			strings.Contains(strings.ToLower(id), filterLower) {
			plugins = append(plugins, PluginInfo{
				ID:   id,
				Name: name,
			})
		}
	}

	// Sort plugins by name
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Name < plugins[j].Name
	})

	return plugins, nil
}

// IdentifyMergedFindings identifies merged and individual findings
func (pm *Manager) IdentifyMergedFindings() (map[string][]PluginInfo, []PluginInfo) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	mergedFindings := make(map[string][]PluginInfo)
	individualFindings := make([]PluginInfo, 0)
	pluginCategories := pm.BuildPluginCategories()

	for _, finding := range pm.Findings {
		pluginID := finding.PluginID
		name := finding.Name

		if finding.Risk == IgnoreInformational {
			continue
		}
		if pluginID == IgnorePlugin {
			continue
		}

		if category, exists := pluginCategories[pluginID]; exists {
			mergedFindings[category] = append(mergedFindings[category], PluginInfo{
				ID:   pluginID,
				Name: name,
			})
		} else {
			individualFindings = append(individualFindings, PluginInfo{
				ID:   pluginID,
				Name: name,
			})
		}
	}

	return mergedFindings, individualFindings
}

// GetNonMergedPlugins returns a list of plugins that are not merged
func (pm *Manager) GetNonMergedPlugins() []PluginInfo {
	// Check if findings are loaded
	if len(pm.Findings) == 0 {
		err := pm.LoadFindings()
		if err != nil {
			return []PluginInfo{}
		}
	}

	// Get the plugin categories from the config
	pluginCategories := pm.BuildPluginCategories()

	// Initialize result
	var nonMergedPlugins []PluginInfo

	// Find all plugins that are not in any category
	for _, finding := range pm.Findings {
		pluginID := finding.PluginID
		name := finding.Name

		// Skip special ignore plugins
		if pluginID == IgnorePlugin {
			continue
		}

		// Check if this plugin is already categorized
		if _, exists := pluginCategories[pluginID]; !exists {
			// Not categorized - add to non-merged plugins
			nonMergedPlugins = append(nonMergedPlugins, PluginInfo{
				ID:   pluginID,
				Name: name,
			})
		}
	}

	// Deduplicate by plugin ID
	uniquePlugins := make(map[string]PluginInfo)
	for _, plugin := range nonMergedPlugins {
		uniquePlugins[plugin.ID] = plugin
	}

	// Convert back to slice
	result := make([]PluginInfo, 0, len(uniquePlugins))
	for _, plugin := range uniquePlugins {
		result = append(result, plugin)
	}

	// Sort by name for better display
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

// RemovePlugin removes a plugin from a category
func (pm *Manager) RemovePlugin(category string, pluginID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.Config.Plugins[category]; !exists {
		return fmt.Errorf("category %s does not exist", category)
	}

	// Find the plugin in the category
	found := false
	categoryData := pm.Config.Plugins[category]
	ids := categoryData.IDs
	for i, id := range ids {
		if id == pluginID {
			// Remove the plugin from the list
			categoryData.IDs = append(ids[:i], ids[i+1:]...)
			pm.Config.Plugins[category] = categoryData
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("plugin %s not found in category %s", pluginID, category)
	}

	return nil
}

// ClearChanges clears all temporary changes
func (pm *Manager) ClearChanges() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.TempChanges = make(map[string][]string)
}

// HasPendingChanges checks if there are any pending changes
func (pm *Manager) HasPendingChanges() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return len(pm.TempChanges) > 0
}

// ViewChanges returns a string representation of the current changes
func (pm *Manager) ViewChanges() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.TempChanges) == 0 {
		return "No pending changes"
	}

	var sb strings.Builder
	sb.WriteString("Current Changes:\n")

	for category, plugins := range pm.TempChanges {
		sb.WriteString(fmt.Sprintf("\n• %s:\n", category))
		for _, plugin := range plugins {
			name, exists := pm.PluginNames[plugin]
			if !exists {
				name = "Unknown"
			}
			sb.WriteString(fmt.Sprintf("  └── %s (%s)\n", plugin, name))
		}
	}

	return sb.String()
}

// CreateCategory creates a new plugin category
func (pm *Manager) CreateCategory(name string, writeupDBID string, writeupName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.Config.Plugins[name]; exists {
		return fmt.Errorf("category %s already exists", name)
	}

	pm.Config.Plugins[name] = PluginCategory{
		IDs:         make([]string, 0),
		WriteupDBID: writeupDBID,
		WriteupName: writeupName,
	}

	return pm.SaveConfig()
}

// UpdateCategory updates a category's metadata
func (pm *Manager) UpdateCategory(name string, writeupDBID string, writeupName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.Config.Plugins[name]; !exists {
		return fmt.Errorf("category %s does not exist", name)
	}

	// Create a temporary copy of the category
	category := pm.Config.Plugins[name]
	// Update the copy
	category.WriteupDBID = writeupDBID
	category.WriteupName = writeupName
	// Assign the modified copy back to the map
	pm.Config.Plugins[name] = category

	return pm.SaveConfig()
}

// DeleteCategory deletes a plugin category
func (pm *Manager) DeleteCategory(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.Config.Plugins[name]; !exists {
		return fmt.Errorf("category %s does not exist", name)
	}

	delete(pm.Config.Plugins, name)

	return pm.SaveConfig()
}

func (pm *Manager) SimulateFindings() (map[string][]PluginInfo, []PluginInfo, error) {
	fmt.Println("SimulateFindings called")

	// Make sure findings are loaded
	if len(pm.Findings) == 0 {
		fmt.Println("No findings loaded, loading findings")
		err := pm.LoadFindings()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load findings: %w", err)
		}
	}

	// Make sure plugin names are loaded
	if len(pm.PluginNames) == 0 {
		fmt.Println("Plugin names not loaded, loading from findings")
		// Use findings to build plugin names map
		pm.mu.Lock()
		pm.PluginNames = make(map[string]string)
		for _, finding := range pm.Findings {
			pm.PluginNames[finding.PluginID] = finding.Name
		}
		pm.mu.Unlock()
	}

	// Build categories map
	pluginCategories := pm.BuildPluginCategories()
	fmt.Printf("Found %d plugin categories\n", len(pluginCategories))

	// Initialize result structures
	mergedFindings := make(map[string][]PluginInfo)
	var individualFindings []PluginInfo

	// Process all findings
	for _, finding := range pm.Findings {
		pluginID := finding.PluginID
		name := finding.Name

		// Skip certain plugins
		if pluginID == IgnorePlugin {
			continue
		}

		// Skip informational findings
		if finding.Risk == IgnoreInformational {
			continue
		}

		// Check if this plugin belongs to a category
		if category, exists := pluginCategories[pluginID]; exists {
			// This is a merged finding
			mergedFindings[category] = append(mergedFindings[category], PluginInfo{
				ID:   pluginID,
				Name: name,
			})
		} else {
			// This is an individual finding
			individualFindings = append(individualFindings, PluginInfo{
				ID:   pluginID,
				Name: name,
			})
		}
	}

	fmt.Printf("Found %d merged categories and %d individual findings\n",
		len(mergedFindings), len(individualFindings))

	// Deduplicate merged findings
	for category, plugins := range mergedFindings {
		uniqueMap := make(map[string]PluginInfo)
		for _, plugin := range plugins {
			uniqueMap[plugin.ID] = plugin
		}

		// Convert back to slice
		uniqueList := make([]PluginInfo, 0, len(uniqueMap))
		for _, plugin := range uniqueMap {
			uniqueList = append(uniqueList, plugin)
		}

		mergedFindings[category] = uniqueList
	}

	// Deduplicate individual findings
	uniqueMap := make(map[string]PluginInfo)
	for _, plugin := range individualFindings {
		uniqueMap[plugin.ID] = plugin
	}

	// Convert back to slice
	uniqueIndividual := make([]PluginInfo, 0, len(uniqueMap))
	for _, plugin := range uniqueMap {
		uniqueIndividual = append(uniqueIndividual, plugin)
	}

	// Debug log some data
	for category, plugins := range mergedFindings {
		fmt.Printf("Category %s has %d plugins\n", category, len(plugins))
		for i, plugin := range plugins {
			if i < 2 {
				fmt.Printf("  %s - %s\n", plugin.ID, plugin.Name)
			} else if i == 2 {
				fmt.Printf("  ... and %d more\n", len(plugins)-2)
				break
			}
		}
	}

	fmt.Printf("Individual findings: %d\n", len(uniqueIndividual))
	for i, plugin := range uniqueIndividual {
		if i < 2 {
			fmt.Printf("  %s - %s\n", plugin.ID, plugin.Name)
		} else if i == 2 && len(uniqueIndividual) > 2 {
			fmt.Printf("  ... and %d more\n", len(uniqueIndividual)-2)
			break
		}
	}

	return mergedFindings, uniqueIndividual, nil
}

func (pm *Manager) WriteChanges() error {
	fmt.Println("WriteChanges called")

	// First check if there are changes without holding the lock
	if !pm.HasPendingChanges() {
		fmt.Println("No changes to write")
		return errors.New("no changes to write")
	}

	// Acquire lock for processing changes
	pm.mu.Lock()

	// Make a copy of the temporary changes to work with
	tempChanges := make(map[string][]string)
	for category, pluginIDs := range pm.TempChanges {
		tempChanges[category] = make([]string, len(pluginIDs))
		copy(tempChanges[category], pluginIDs)
	}

	fmt.Printf("Found %d categories with changes\n", len(tempChanges))

	// Process all changes
	for category, pluginIDs := range tempChanges {
		fmt.Printf("Category %s has %d plugins to add\n", category, len(pluginIDs))

		if _, exists := pm.Config.Plugins[category]; !exists {
			pm.mu.Unlock() // Release lock before returning
			return fmt.Errorf("category %s does not exist", category)
		}

		// Add any new plugin IDs to the category
		for _, pluginID := range pluginIDs {
			found := false
			for _, id := range pm.Config.Plugins[category].IDs {
				if id == pluginID {
					found = true
					break
				}
			}

			if !found {
				fmt.Printf("Adding plugin %s to category %s\n", pluginID, category)
				// Create a temporary copy of the category
				categoryData := pm.Config.Plugins[category]
				// Modify the copy
				categoryData.IDs = append(categoryData.IDs, pluginID)
				// Assign the modified copy back to the map
				pm.Config.Plugins[category] = categoryData
			} else {
				fmt.Printf("Plugin %s already in category %s\n", pluginID, category)
			}
		}
	}

	// Write the updated config to file while still holding the lock
	fmt.Println("Saving config to file:", pm.ConfigPath)
	err := pm.SaveConfig() // SaveConfig no longer acquires locks

	if err != nil {
		fmt.Printf("Error saving config: %v\n", err)
		pm.mu.Unlock() // Release lock before returning error
		return err
	}

	fmt.Println("Config saved successfully, clearing temp changes")
	// Clear the temporary changes
	pm.TempChanges = make(map[string][]string)

	// Release the lock
	pm.mu.Unlock()

	fmt.Println("WriteChanges completed successfully")
	return nil
}

// AddPlugin adds a plugin to a category
func (pm *Manager) AddPlugin(category string, pluginID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	fmt.Printf("AddPlugin called: category=%s, pluginID=%s\n", category, pluginID)

	if _, exists := pm.Config.Plugins[category]; !exists {
		return fmt.Errorf("category %s does not exist", category)
	}

	// Check if the plugin is already in the category
	for _, id := range pm.Config.Plugins[category].IDs {
		if id == pluginID {
			fmt.Printf("Plugin %s already in category %s\n", pluginID, category)
			return fmt.Errorf("plugin %s is already in category %s", pluginID, category)
		}
	}

	// Add to temporary changes
	if pm.TempChanges[category] == nil {
		pm.TempChanges[category] = make([]string, 0)
	}

	// Check if it's already in temp changes
	for _, id := range pm.TempChanges[category] {
		if id == pluginID {
			fmt.Printf("Plugin %s already in temp changes for category %s\n", pluginID, category)
			return nil
		}
	}

	fmt.Printf("Adding plugin %s to temp changes for category %s\n", pluginID, category)
	pm.TempChanges[category] = append(pm.TempChanges[category], pluginID)

	return nil
}

// UpdateCSVPath updates the CSV path and reloads findings
func (pm *Manager) UpdateCSVPath(path string) error {
	pm.CSVPath = path

	if path == "" {
		return nil
	}

	// Try to load findings
	err := pm.LoadFindings()
	if err != nil {
		// Even if there's an error, continue
		// We've implemented fallbacks in the LoadFindings method
	}

	// Ensure we have plugin names for all findings
	pm.mu.Lock()
	for _, finding := range pm.Findings {
		if _, exists := pm.PluginNames[finding.PluginID]; !exists {
			pm.PluginNames[finding.PluginID] = finding.Name
		}
	}
	pm.mu.Unlock()

	return nil
}

// GetCSVPath returns the current CSV path
func (pm *Manager) GetCSVPath() string {
	return pm.CSVPath
}

// GetConfigPath returns the current config path
func (pm *Manager) GetConfigPath() string {
	return pm.ConfigPath
}
