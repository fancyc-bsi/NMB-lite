// Package config provides configuration loading and management functionality
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// LoadConfig loads a JSON configuration file and returns its contents
func LoadConfig(configPath string) (map[string]interface{}, error) {
	// Check if the file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", configPath)
	}

	// Read the file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Parse the JSON
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration JSON: %w", err)
	}

	return config, nil
}

// GetPluginCategories returns all plugin categories from the config
func GetPluginCategories(config map[string]interface{}) (map[string]interface{}, error) {
	plugins, ok := config["plugins"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("plugins section not found in configuration")
	}
	return plugins, nil
}

// GetPluginCategory returns a specific plugin category from the config
func GetPluginCategory(config map[string]interface{}, category string) (map[string]interface{}, error) {
	plugins, err := GetPluginCategories(config)
	if err != nil {
		return nil, err
	}

	categoryConfig, ok := plugins[category].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("category not found: %s", category)
	}

	return categoryConfig, nil
}

// GetPluginIDs returns the plugin IDs for a specific category
func GetPluginIDs(config map[string]interface{}, category string) ([]string, error) {
	categoryConfig, err := GetPluginCategory(config, category)
	if err != nil {
		return nil, err
	}

	idsInterface, ok := categoryConfig["ids"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("ids not found for category: %s", category)
	}

	ids := make([]string, len(idsInterface))
	for i, id := range idsInterface {
		ids[i], ok = id.(string)
		if !ok {
			return nil, fmt.Errorf("invalid plugin ID format")
		}
	}

	return ids, nil
}

// GetWriteupDBID returns the writeup DB ID for a specific category
func GetWriteupDBID(config map[string]interface{}, category string) (string, error) {
	categoryConfig, err := GetPluginCategory(config, category)
	if err != nil {
		return "", err
	}

	writeupDBID, ok := categoryConfig["writeup_db_id"].(string)
	if !ok {
		return "", fmt.Errorf("writeup_db_id not found for category: %s", category)
	}

	return writeupDBID, nil
}

// GetWriteupName returns the writeup name for a specific category
func GetWriteupName(config map[string]interface{}, category string) (string, error) {
	categoryConfig, err := GetPluginCategory(config, category)
	if err != nil {
		return "", err
	}

	writeupName, ok := categoryConfig["writeup_name"].(string)
	if !ok {
		return "", fmt.Errorf("writeup_name not found for category: %s", category)
	}

	return writeupName, nil
}

// SaveConfig saves a configuration to a JSON file
func SaveConfig(config map[string]interface{}, configPath string) error {
	// Convert to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to convert configuration to JSON: %w", err)
	}

	// Write to file
	if err := ioutil.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	return nil
}
