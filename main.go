package main

import (
	"NMB/internal/api"
	"NMB/internal/args"
	"NMB/internal/editor"
	"NMB/internal/engine"
	"NMB/internal/logging"
	"NMB/internal/n2p"
	"NMB/internal/n2p/client"
	"NMB/internal/plugin"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:ui-core/build
var assets embed.FS

// N2PConfig represents the configuration for the N2P process
type N2PConfig struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	ClientID       string `json:"clientId"`
	ReportID       string `json:"reportId"`
	Scope          string `json:"scope"`
	Directory      string `json:"directory"`
	TargetPlextrac string `json:"targetPlextrac"`
	ScreenshotDir  string `json:"screenshotDir"`
	NonCore        bool   `json:"nonCore"`
	ClientConfig   string `json:"clientConfig"`
	Overwrite      bool   `json:"overwrite"`
}

// N2PStatus represents the status of the N2P process
type N2PStatus struct {
	Success      bool    `json:"success"`
	ErrorMessage string  `json:"errorMessage,omitempty"`
	ElapsedTime  float64 `json:"elapsedTime,omitempty"`
}

type App struct {
	ctx               context.Context
	screenshotManager *editor.ScreenshotManager
	pluginManager     *plugin.Manager
	logger            *logrus.Logger
}

func NewApp() *App {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})
	logger.SetLevel(logrus.InfoLevel)

	return &App{
		pluginManager: &plugin.Manager{},
		logger:        logger,
	}
}

func init() {
	// Initialize the logging system
	logging.Init()
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.screenshotManager = editor.NewScreenshotManager(ctx)

	// Get config directory path from environment or use default
	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "config"
	}

	// Define paths for the plugin manager
	// configPath := filepath.Join(configDir, "N2P_config.json")
	configPath := "N2P_config.json"

	// Initialize plugin manager with empty CSV path (will be set by user)
	var err error
	a.pluginManager, err = plugin.NewManager(configPath, "")
	if err != nil {
		log.Printf("Failed to initialize plugin manager: %v", err)
	}

	os.Setenv("GOGC", "50")
	go func() {
		server := api.NewServer()
		errChan := make(chan error, 10) // Buffered channel
		go func() {
			errChan <- server.Run()
		}()
		if err := <-errChan; err != nil {
			log.Printf("API server error: %v", err)
		}
	}()
}

// SelectFile opens a file selection dialog
func (a *App) SelectFile(filter string) (string, error) {
	var dialogOptions runtime.OpenDialogOptions
	if filter == "SSH Key" {
		dialogOptions = runtime.OpenDialogOptions{
			Title: "Select SSH Key File",
			Filters: []runtime.FileFilter{
				{
					DisplayName: "SSH Key Files",
					Pattern:     "*.pem;*.key;*.pub",
				},
			},
		}
	} else {
		dialogOptions = runtime.OpenDialogOptions{
			Title: "Select File",
			Filters: []runtime.FileFilter{
				{
					DisplayName: filter,
					Pattern:     "*.*",
				},
			},
		}
	}
	return runtime.OpenFileDialog(a.ctx, dialogOptions)
}

// SelectDirectory opens a directory selection dialog
func (a *App) SelectDirectory() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Directory",
	})
}

// OpenDirectoryDialog opens a directory selection dialog for screenshots
func (a *App) OpenDirectoryDialog() (string, error) {
	return a.screenshotManager.OpenDirectoryDialog()
}

// ListImageFilesInDirectory returns a list of image files in the given directory
func (a *App) ListImageFilesInDirectory(dirPath string) ([]string, error) {
	return a.screenshotManager.ListImageFilesInDirectory(dirPath)
}

// ReadImageFile reads an image file and returns its content as base64
func (a *App) ReadImageFile(filePath string) (string, error) {
	return a.screenshotManager.ReadImageFile(filePath)
}

// SaveImageFile saves a base64-encoded image to the specified path
func (a *App) SaveImageFile(filePath string, base64Data string) error {
	return a.screenshotManager.SaveImageFile(filePath, base64Data)
}

func (a *App) GetPluginNames() map[string]string {
	if a.pluginManager == nil {
		return nil
	}
	return a.pluginManager.GetPluginNames()
}

// GetCategories returns all plugin categories
func (a *App) GetCategories() []string {
	if a.pluginManager == nil {
		return nil
	}
	return a.pluginManager.GetCategories()
}

// GetCategoryDetails returns detailed information about all categories
func (a *App) GetCategoryDetails() []plugin.CategoryInfo {
	if a.pluginManager == nil {
		return nil
	}
	return a.pluginManager.GetCategoryDetails()
}

// GetCategoryInfo returns detailed information about a specific category
func (a *App) GetCategoryInfo(category string) (*plugin.CategoryInfo, error) {
	if a.pluginManager == nil {
		return nil, fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.GetCategoryInfo(category)
}

// GetPluginsByCategory returns all plugins in a category
func (a *App) GetPluginsByCategory(category string) ([]plugin.PluginInfo, error) {
	if a.pluginManager == nil {
		return nil, fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.GetPluginsByCategory(category)
}

// FilterPluginsByName filters plugins in a category by name
func (a *App) FilterPluginsByName(category string, filterStr string) ([]plugin.PluginInfo, error) {
	if a.pluginManager == nil {
		return nil, fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.FilterPluginsByName(category, filterStr)
}

// GetNonMergedPlugins returns plugins that are not in any category
func (a *App) GetNonMergedPlugins() []plugin.PluginInfo {
	if a.pluginManager == nil {
		return nil
	}
	return a.pluginManager.GetNonMergedPlugins()
}

// AddPlugin adds a plugin to a category
func (a *App) AddPlugin(category string, pluginID string) error {
	if a.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.AddPlugin(category, pluginID)
}

// RemovePlugin removes a plugin from a category
func (a *App) RemovePlugin(category string, pluginID string) error {
	if a.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.RemovePlugin(category, pluginID)
}

// WriteChanges writes temporary changes to the config file
func (a *App) WriteChanges() error {
	if a.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.WriteChanges()
}

// ClearChanges clears all temporary changes
func (a *App) ClearChanges() {
	if a.pluginManager != nil {
		a.pluginManager.ClearChanges()
	}
}

// ViewChanges returns a string representation of the current changes
func (a *App) ViewChanges() string {
	if a.pluginManager == nil {
		return "Plugin manager not initialized"
	}
	return a.pluginManager.ViewChanges()
}

// HasPendingChanges checks if there are any pending changes
func (a *App) HasPendingChanges() bool {
	if a.pluginManager == nil {
		return false
	}
	return a.pluginManager.HasPendingChanges()
}

// CreateCategory creates a new plugin category
func (a *App) CreateCategory(name string, writeupDBID string, writeupName string) error {
	if a.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.CreateCategory(name, writeupDBID, writeupName)
}

// UpdateCategory updates a category's metadata
func (a *App) UpdateCategory(name string, writeupDBID string, writeupName string) error {
	if a.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.UpdateCategory(name, writeupDBID, writeupName)
}

// DeleteCategory deletes a plugin category
func (a *App) DeleteCategory(name string) error {
	if a.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.DeleteCategory(name)
}

// SimulateFindings simulates findings based on current configuration
func (a *App) SimulateFindings() (map[string][]plugin.PluginInfo, []plugin.PluginInfo, error) {
	if a.pluginManager == nil {
		return nil, nil, fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.SimulateFindings()
}

// UpdateCSVPath updates the CSV path and reloads findings
func (a *App) UpdateCSVPath(path string) error {
	if a.pluginManager == nil {
		return fmt.Errorf("plugin manager not initialized")
	}
	return a.pluginManager.UpdateCSVPath(path)
}

// GetCSVPath returns the current CSV path
func (a *App) GetCSVPath() string {
	if a.pluginManager == nil {
		return ""
	}
	return a.pluginManager.GetCSVPath()
}

// SelectCSVFile opens a file dialog to select a CSV file
func (a *App) SelectCSVFile() (string, error) {
	dialogOptions := runtime.OpenDialogOptions{
		Title: "Select CSV File",
		Filters: []runtime.FileFilter{
			{
				DisplayName: "CSV Files",
				Pattern:     "*.csv",
			},
		},
	}
	return runtime.OpenFileDialog(a.ctx, dialogOptions)
}

// GetConfigPath returns the current config path
func (a *App) GetConfigPath() string {
	if a.pluginManager == nil {
		return ""
	}
	return a.pluginManager.GetConfigPath()
}

// SelectConfigFile opens a file dialog to select a config file
func (a *App) SelectConfigFile() (string, error) {
	dialogOptions := runtime.OpenDialogOptions{
		Title: "Select N2P_config.json File",
		Filters: []runtime.FileFilter{
			{
				DisplayName: "JSON Files",
				Pattern:     "*.json",
			},
		},
	}

	path, err := runtime.OpenFileDialog(a.ctx, dialogOptions)
	if err != nil {
		return "", err
	}

	// Reinitialize the plugin manager with the new config path
	if path != "" {
		// Keep the current CSV path when reinitializing
		csvPath := a.pluginManager.GetCSVPath()
		a.pluginManager, err = plugin.NewManager(path, csvPath)
		if err != nil {
			return "", fmt.Errorf("failed to initialize plugin manager with new config: %w", err)
		}
	}

	return path, nil
}

// WriteSimulationResultsToFile writes simulation results to a temporary JSON file
func (a *App) WriteSimulationResultsToFile() (string, error) {
	if a.pluginManager == nil {
		return "", fmt.Errorf("plugin manager not initialized")
	}

	// Get simulation results
	merged, individual, err := a.pluginManager.SimulateFindings()
	if err != nil {
		return "", err
	}

	// Create result structure
	result := map[string]interface{}{
		"merged":     merged,
		"individual": individual,
	}

	// Create temp file path
	tempDir := os.TempDir()
	filePath := filepath.Join(tempDir, "simulation_results.json")

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal simulation results: %w", err)
	}

	// Write to file
	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write simulation results file: %w", err)
	}

	return filePath, nil
}

// ReadSimulationResultsFile reads the simulation results from file
func (a *App) ReadSimulationResultsFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read simulation results file: %w", err)
	}

	return string(data), nil
}

// NEW N2P FUNCTIONS START HERE

// RunN2P runs the N2P process with the given configuration
// Update this function in main.go
func (a *App) RunN2P(config N2PConfig) map[string]string {
	// Log the received configuration for debugging
	a.logger.WithField("config", config).Info("Received N2P configuration")

	// Start timing
	startTime := time.Now()

	// Send an initial event to update the UI
	runtime.EventsEmit(a.ctx, "n2p:status", "Initializing N2P process...")

	// Convert the config to the format expected by n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        config.Username,
		"password":        config.Password,
		"client_id":       config.ClientID,       // Note: snake_case key to match n2p code
		"report_id":       config.ReportID,       // Note: snake_case key to match n2p code
		"target_plextrac": config.TargetPlextrac, // Note: snake_case key to match n2p code
		"directory":       config.Directory,
		"screenshot_dir":  config.ScreenshotDir, // Note: snake_case key to match n2p code
		"non_core":        config.NonCore,       // Note: snake_case key to match n2p code
		"client_config":   config.ClientConfig,  // Note: snake_case key to match n2p code
		"overwrite":       config.Overwrite,
		"scope":           config.Scope,
		"verbosity":       1, // Default verbosity
	}

	// Create a custom logger that emits events
	customLogger := a.createEventLogger()

	// Add logger to the engine args
	engineArgs["logger"] = customLogger

	// Create the engine - passing the flat map directly
	engine := n2p.NewEngine(engineArgs)

	// Run the entire process
	if err := engine.Run(); err != nil {
		errorMsg := fmt.Sprintf("N2P process failed: %v", err)
		a.logger.WithError(err).Error(errorMsg)
		return map[string]string{
			"success":      "false",
			"errorMessage": errorMsg,
			"errorDetails": fmt.Sprintf("%+v", err),
		}
	}

	// Calculate elapsed time
	elapsedTime := time.Since(startTime).Seconds()

	return map[string]string{
		"success":     "true",
		"elapsedTime": fmt.Sprintf("%.2f", elapsedTime),
	}
}

// CreateN2PClient creates a new client and report
func (a *App) CreateN2PClient(config N2PConfig) map[string]string {
	// Send an initial event to update the UI
	runtime.EventsEmit(a.ctx, "n2p:status", "Creating client and report...")

	// Log the received configuration for debugging
	a.logger.WithField("config", config).Info("Received config for client creation")

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        config.Username,
		"password":        config.Password,
		"target_plextrac": config.TargetPlextrac,
		"create":          true,
		"verbosity":       2, // Default verbosity
	}

	// Create a custom logger that emits events
	customLogger := a.createEventLogger()

	// Add logger to the engine args
	engineArgs["logger"] = customLogger

	// Create the engine with the flat map structure
	engine := n2p.NewEngine(engineArgs)

	// Run the engine (will only do client creation since Create = true)
	if err := engine.Run(); err != nil {
		customLogger.WithError(err).Error("Client creation failed")
		return map[string]string{
			"success": "false",
			"error":   fmt.Sprintf("Client creation failed: %v", err),
		}
	}

	// Read the report_info.txt file to get the client and report IDs
	reportInfo, err := a.readReportInfo()
	if err != nil {
		customLogger.WithError(err).Error("Failed to read report info")
		return map[string]string{
			"success": "false",
			"error":   fmt.Sprintf("Failed to read report info: %v", err),
		}
	}

	// Make sure to set success flag
	reportInfo["success"] = "true"

	// Log successful creation with IDs
	customLogger.WithFields(logrus.Fields{
		"clientId": reportInfo["clientId"],
		"reportId": reportInfo["reportId"],
	}).Info("Successfully created client and report")

	return reportInfo
}

// readReportInfo reads the report_info.txt file
func (a *App) readReportInfo() (map[string]string, error) {
	// Read the report_info.txt file
	data, err := os.ReadFile("report_info.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to read report_info.txt: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	result := map[string]string{
		"success": "true",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Client ID":
			result["clientId"] = value
		case "Report ID":
			result["reportId"] = value
		}
	}

	// Add report URL
	if clientID, ok := result["clientId"]; ok {
		if reportID, ok := result["reportId"]; ok {
			result["reportUrl"] = fmt.Sprintf("https://report.kevlar.bulletproofsi.net/client/%s/report/%s", clientID, reportID)
		}
	}

	return result, nil
}

// createEventLogger creates a custom logger that emits events
func (a *App) createEventLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})
	logger.SetLevel(logrus.InfoLevel)

	// Add a hook to emit events
	logger.AddHook(&eventHook{ctx: a.ctx})

	return logger
}

// eventHook is a logrus hook that emits events
type eventHook struct {
	ctx context.Context
}

// Levels returns the levels this hook should be called for
func (h *eventHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.DebugLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
		logrus.ErrorLevel,
	}
}

// Fire is called when a log event occurs
func (h *eventHook) Fire(entry *logrus.Entry) error {
	// Emit the log entry as an event
	runtime.EventsEmit(h.ctx, "n2p:log", map[string]interface{}{
		"level":   entry.Level.String(),
		"message": entry.Message,
		"time":    entry.Time.Format(time.RFC3339),
	})

	return nil
}

// BrowseForNessusDirectory shows a directory selection dialog for Nessus files
func (a *App) BrowseForNessusDirectory() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Directory with Nessus Files",
	})
}

// BrowseForScreenshotDirectory shows a directory selection dialog for screenshots
func (a *App) BrowseForScreenshotDirectory() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Directory with Screenshots",
	})
}

// BrowseForClientConfig shows a file selection dialog for client configuration
func (a *App) BrowseForClientConfig() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Client Configuration File",
		Filters: []runtime.FileFilter{
			{
				DisplayName: "TOML Files",
				Pattern:     "*.toml",
			},
		},
	})
}

// GetPlextracServers returns a list of available Plextrac servers
func (a *App) GetPlextracServers() []string {
	// In a real implementation, this might come from a configuration file or API
	return []string{"report"}
}

// GetScopes returns a list of available scopes
func (a *App) GetScopes() []map[string]string {
	return []map[string]string{
		{"value": "internal", "label": "Internal"},
		{"value": "external", "label": "External"},
		{"value": "web", "label": "Web Application"},
		{"value": "mobile", "label": "Mobile Application"},
		{"value": "surveillance", "label": "Surveillance"},
	}
}

// ClientDetailedConfig represents the configuration for creating a client with more details
type ClientDetailedConfig struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	TargetPlextrac string `json:"targetPlextrac"`
	ClientName     string `json:"clientName"`
	SnPsCode       string `json:"snPsCode"`
	StateCode      string `json:"stateCode"`
}

// ReportDetailedConfig represents the configuration for creating a report with more details
type ReportDetailedConfig struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	TargetPlextrac      string `json:"targetPlextrac"`
	ClientId            string `json:"clientId"`
	ReportName          string `json:"reportName"`
	ReportTemplate      string `json:"reportTemplate"`
	CustomFieldTemplate string `json:"customFieldTemplate"`
}

// GetReportTemplates returns available report templates using the provided credentials
func (a *App) GetReportTemplates(userCreds map[string]string) ([]map[string]string, error) {
	// Send a log event
	runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
		"level":   "info",
		"message": "Fetching report templates",
		"time":    time.Now().Format(time.RFC3339),
	})

	// Get the credentials from the UI
	username := userCreds["username"]
	password := userCreds["password"]
	targetPlextrac := userCreds["targetPlextrac"]

	if username == "" || password == "" {
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": "Username and password are required to fetch templates",
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("username and password are required to fetch templates")
	}

	if targetPlextrac == "" {
		targetPlextrac = "report" // Default value
	}

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        username,
		"password":        password,
		"target_plextrac": targetPlextrac,
		"verbosity":       1,
	}

	// Create a custom logger that emits events
	customLogger := a.createEventLogger()
	engineArgs["logger"] = customLogger

	// Log what we're going to do
	customLogger.Info("Creating n2p engine for template retrieval")

	// Create the engine - using only basic initialization
	engine := n2p.NewEngine(engineArgs)
	customLogger.Info("Initializing engine...")

	if err := engine.InitializeEngine(); err != nil {
		customLogger.WithError(err).Error("Failed to initialize engine")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Engine initialization failed: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to initialize engine: %w", err)
	}

	customLogger.Info("Engine initialized successfully")

	// Create a ClientReportGen instance with the URL manager
	generator := client.NewClientReportGen(engine.URLManager, engine.RequestHandler)
	generator.Logger = customLogger

	// Get URL for report templates
	url := engine.URLManager.GetReportTemplateURL()
	customLogger.Infof("Report template URL: %s", url)

	// Make the request using RequestHandler
	customLogger.Info("Sending request for report templates...")
	response, err := engine.RequestHandler.Get(url, nil, nil)
	if err != nil {
		customLogger.WithError(err).Error("Failed to get report templates")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Template request failed: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to get report templates: %w", err)
	}

	// Process the response
	statusCode := response.GetStatusCode()
	customLogger.Infof("Got response with status code: %d", statusCode)

	if statusCode != 200 {
		bodyBytes := response.GetBody()
		bodyStr := string(bodyBytes)
		customLogger.WithFields(logrus.Fields{
			"status_code": statusCode,
			"body":        bodyStr,
		}).Error("Failed to get report templates")

		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Failed with status code: %d, body: %s", statusCode, bodyStr),
			"time":    time.Now().Format(time.RFC3339),
		})

		return nil, fmt.Errorf("failed to get report templates: status code %d, body: %s", statusCode, bodyStr)
	}

	var reportTemplatesResponse []interface{}
	if err := response.DecodeJSON(&reportTemplatesResponse); err != nil {
		customLogger.WithError(err).Error("Failed to decode report templates response")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("JSON decode error: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to decode report templates response: %w", err)
	}

	customLogger.Infof("Successfully parsed response, found %d templates", len(reportTemplatesResponse))

	// Parse the templates
	reportTemplates, err := generator.ParseTemplates(reportTemplatesResponse)
	if err != nil {
		customLogger.WithError(err).Error("Failed to parse report templates")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Template parsing error: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to parse report templates: %w", err)
	}

	customLogger.Infof("Successfully retrieved %d report templates", len(reportTemplates))
	return reportTemplates, nil
}

// GetFieldTemplates returns available field templates using the provided credentials
func (a *App) GetFieldTemplates(userCreds map[string]string) ([]map[string]string, error) {
	// Send a log event
	runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
		"level":   "info",
		"message": "Fetching field templates",
		"time":    time.Now().Format(time.RFC3339),
	})

	// Get the credentials from the UI
	username := userCreds["username"]
	password := userCreds["password"]
	targetPlextrac := userCreds["targetPlextrac"]

	if username == "" || password == "" {
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": "Username and password are required to fetch templates",
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("username and password are required to fetch templates")
	}

	if targetPlextrac == "" {
		targetPlextrac = "report" // Default value
	}

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        username,
		"password":        password,
		"target_plextrac": targetPlextrac,
		"verbosity":       1,
	}

	// Create a custom logger that emits events
	customLogger := a.createEventLogger()
	engineArgs["logger"] = customLogger

	// Log what we're going to do
	customLogger.Info("Creating n2p engine for field template retrieval")

	// Create the engine - using only basic initialization
	engine := n2p.NewEngine(engineArgs)
	customLogger.Info("Initializing engine...")

	if err := engine.InitializeEngine(); err != nil {
		customLogger.WithError(err).Error("Failed to initialize engine")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Engine initialization failed: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to initialize engine: %w", err)
	}

	customLogger.Info("Engine initialized successfully")

	// Create a ClientReportGen instance with the URL manager
	generator := client.NewClientReportGen(engine.URLManager, engine.RequestHandler)
	generator.Logger = customLogger

	// Get URL for field templates
	url := engine.URLManager.GetFieldTemplateURL()
	customLogger.Infof("Field template URL: %s", url)

	// Make the request using RequestHandler
	customLogger.Info("Sending request for field templates...")
	response, err := engine.RequestHandler.Get(url, nil, nil)
	if err != nil {
		customLogger.WithError(err).Error("Failed to get field templates")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Template request failed: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to get field templates: %w", err)
	}

	// Process the response
	statusCode := response.GetStatusCode()
	customLogger.Infof("Got response with status code: %d", statusCode)

	if statusCode != 200 {
		bodyBytes := response.GetBody()
		bodyStr := string(bodyBytes)
		customLogger.WithFields(logrus.Fields{
			"status_code": statusCode,
			"body":        bodyStr,
		}).Error("Failed to get field templates")

		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Failed with status code: %d, body: %s", statusCode, bodyStr),
			"time":    time.Now().Format(time.RFC3339),
		})

		return nil, fmt.Errorf("failed to get field templates: status code %d, body: %s", statusCode, bodyStr)
	}

	var fieldTemplatesResponse []interface{}
	if err := response.DecodeJSON(&fieldTemplatesResponse); err != nil {
		customLogger.WithError(err).Error("Failed to decode field templates response")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("JSON decode error: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to decode field templates response: %w", err)
	}

	customLogger.Infof("Successfully parsed response, found %d templates", len(fieldTemplatesResponse))

	// Parse the templates
	fieldTemplates, err := generator.ParseTemplates(fieldTemplatesResponse)
	if err != nil {
		customLogger.WithError(err).Error("Failed to parse field templates")
		runtime.EventsEmit(a.ctx, "n2p:log", map[string]interface{}{
			"level":   "error",
			"message": fmt.Sprintf("Template parsing error: %v", err),
			"time":    time.Now().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("failed to parse field templates: %w", err)
	}

	customLogger.Infof("Successfully retrieved %d field templates", len(fieldTemplates))
	return fieldTemplates, nil
}

// CreateClientDetailed creates a client with detailed information
func (a *App) CreateClientDetailed(config ClientDetailedConfig) map[string]string {
	// Send an initial event to update the UI
	runtime.EventsEmit(a.ctx, "n2p:status", "Creating client...")

	// Log the received configuration for debugging
	a.logger.WithField("config", config).Info("Received config for detailed client creation")

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        config.Username,
		"password":        config.Password,
		"target_plextrac": config.TargetPlextrac,
		"verbosity":       2,
	}

	// Create a custom logger that emits events
	customLogger := a.createEventLogger()
	engineArgs["logger"] = customLogger

	// Create the engine - using only basic initialization
	engine := n2p.NewEngine(engineArgs)
	if err := engine.InitializeEngine(); err != nil {
		customLogger.WithError(err).Error("Failed to initialize engine")
		return map[string]string{
			"success": "false",
			"error":   fmt.Sprintf("Failed to initialize engine: %v", err),
		}
	}

	// Create a ClientReportGen instance with the URL manager
	generator := client.NewClientReportGen(engine.URLManager, engine.RequestHandler)
	generator.Logger = customLogger

	// Emit debug info
	customLogger.WithFields(logrus.Fields{
		"clientName": config.ClientName,
		"snPsCode":   config.SnPsCode,
	}).Info("Attempting to create client")

	// Create the client using the provided name and project code
	clientID, err := generator.CreateClient(config.ClientName, config.SnPsCode, config.StateCode)
	if err != nil {
		customLogger.WithError(err).Error("Failed to create client")
		return map[string]string{
			"success": "false",
			"error":   fmt.Sprintf("Failed to create client: %v", err),
		}
	}

	customLogger.Infof("Client created successfully with ID: %s", clientID)

	return map[string]string{
		"success":  "true",
		"clientId": clientID,
	}
}

// CreateReportDetailed creates a report with detailed information
func (a *App) CreateReportDetailed(config ReportDetailedConfig) map[string]string {
	// Send an initial event to update the UI
	runtime.EventsEmit(a.ctx, "n2p:status", "Creating report...")

	// Log the received configuration for debugging
	a.logger.WithField("config", config).Info("Received config for detailed report creation")

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        config.Username,
		"password":        config.Password,
		"target_plextrac": config.TargetPlextrac,
		"verbosity":       2,
	}

	// Create a custom logger that emits events
	customLogger := a.createEventLogger()
	engineArgs["logger"] = customLogger

	// Create the engine - using only basic initialization
	engine := n2p.NewEngine(engineArgs)
	if err := engine.InitializeEngine(); err != nil {
		return map[string]string{
			"success": "false",
			"error":   fmt.Sprintf("Failed to initialize engine: %v", err),
		}
	}

	// Create a ClientReportGen instance with the URL manager
	generator := client.NewClientReportGen(engine.URLManager, engine.RequestHandler)
	generator.Logger = customLogger

	customLogger.WithFields(logrus.Fields{
		"reportName":          config.ReportName,
		"clientId":            config.ClientId,
		"reportTemplate":      config.ReportTemplate,
		"customFieldTemplate": config.CustomFieldTemplate,
	}).Info("Attempting to create report with these parameters")

	// Create the report
	reportID, err := generator.CreateReport(config.ReportName, config.ClientId, config.ReportTemplate, config.CustomFieldTemplate)
	if err != nil {
		customLogger.WithError(err).Error("Failed to create report")
		return map[string]string{
			"success": "false",
			"error":   fmt.Sprintf("Failed to create report: %v", err),
		}
	}

	customLogger.Infof("Report created successfully with ID: %s", reportID)

	// Generate report URL
	reportUrl := fmt.Sprintf("https://report.kevlar.bulletproofsi.net/client/%s/report/%s", config.ClientId, reportID)

	return map[string]string{
		"success":   "true",
		"reportId":  reportID,
		"reportUrl": reportUrl,
	}
}

func main() {
	// Command line handling
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		parsedArgs := args.ParseArgs()
		if parsedArgs.NessusMode != "" {
			engine.HandleNessusController(parsedArgs)
			return
		}
		engine.RunNMB(parsedArgs)
		return
	}

	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "NMB",
		Width:            1200,
		Height:           800,
		Assets:           assets,
		BackgroundColour: &options.RGBA{R: 10, G: 25, B: 41, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
		Linux: &linux.Options{
			WindowIsTranslucent: false,
			WebviewGpuPolicy:    linux.WebviewGpuPolicyNever,
			ProgramName:         "NMB",
			Icon:                nil,
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: true,
		},
		CSSDragProperty: "--wails-draggable",
		CSSDragValue:    "drag",
	})
	if err != nil {
		log.Fatal(err)
	}
}
