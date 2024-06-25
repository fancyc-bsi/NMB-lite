package config

import (
	"embed"
	"encoding/json"
	"log"
	"os"
)

//go:embed config.json
var configFile embed.FS

type Plugin struct {
	IDs         []string `json:"ids"`
	ScanType    string   `json:"scan_type"`
	Parameters  string   `json:"parameters"`
	VerifyWords []string `json:"verify_words"`
}

type Config struct {
	Plugins map[string]Plugin `json:"plugins"`
}

func LoadEmbeddedConfig() Config {
	var config Config
	data, err := configFile.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read embedded config: %v", err)
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Failed to parse embedded config: %v", err)
	}
	return config
}

func LoadConfigFromFile(filePath string) Config {
	var config Config
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}
	return config
}
