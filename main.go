package main

import (
	"NMB/internal/api"
	"NMB/internal/args"
	"NMB/internal/crash"
	"NMB/internal/editor"
	"NMB/internal/engine"
	"NMB/internal/logging"
	"NMB/internal/n2p"
	"NMB/internal/n2p/client"
	"NMB/internal/n2p/plextrac"
	"NMB/internal/plugin"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	other_runtime "runtime"
	"strconv"
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

func setupGlobalPanicHandler() {
	// Create a crash reporter
	reporter := crash.NewReporter("crash_reports")

	// Set up a global panic handler for the main goroutine
	go func() {
		if err := recover(); err != nil {
			sysInfo := map[string]string{
				"goVersion":     other_runtime.Version(),
				"numCPU":        fmt.Sprintf("%d", other_runtime.NumCPU()),
				"numGoroutines": fmt.Sprintf("%d", other_runtime.NumGoroutine()),
				"osArch":        other_runtime.GOARCH,
				"osType":        other_runtime.GOOS,
			}

			reporter.RecoverWithCrashReport("MainApplication", sysInfo)

			// Exit the application after a crash in the main goroutine
			os.Exit(1)
		}
	}()
}

func (a *App) startup(ctx context.Context) {
	// Create a crash reporter
	reporter := crash.NewReporter("crash_reports")

	// Setup panic recovery for the UI startup
	defer func() {
		if err := recover(); err != nil {
			extra := map[string]string{
				"component": "UIStartup",
				"timestamp": time.Now().Format(time.RFC3339),
			}

			if a.pluginManager != nil {
				extra["pluginManagerInitialized"] = "true"
				extra["configPath"] = a.pluginManager.GetConfigPath()
			} else {
				extra["pluginManagerInitialized"] = "false"
			}

			reporter.RecoverWithCrashReport("UIStartup", extra)

			// Re-panic to allow wails to handle it
			panic(err)
		}
	}()

	a.ctx = ctx
	a.screenshotManager = editor.NewScreenshotManager(ctx)

	// Get config directory path from environment or use default
	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "config"
	}

	configPath := "N2P_config.json"

	// Initialize plugin manager with empty CSV path (will be set by user)
	var err error
	a.pluginManager, err = plugin.NewManager(configPath, "")
	if err != nil {
		log.Printf("Failed to initialize plugin manager: %v", err)
	}

	os.Setenv("GOGC", "50")

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

// FindingsRequest represents the request for fetching findings
type FindingsRequest struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	TargetPlextrac string `json:"targetPlextrac"`
	ClientId       string `json:"clientId"`
	ReportId       string `json:"reportId"`
}

// Finding represents a finding in Plextrac
type Finding struct {
	FlawID          string       `json:"flaw_id"`
	Title           string       `json:"title"`
	Severity        string       `json:"severity"`
	Status          string       `json:"status"`
	Description     string       `json:"description"`
	Recommendations string       `json:"recommendations"`
	Tags            []string     `json:"tags"`
	Fields          []FieldValue `json:"fields"`
}

// FieldValue represents a custom field value
type FieldValue struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// FindingsResponse represents the response for fetching findings
type FindingsResponse struct {
	Success  bool      `json:"success"`
	Findings []Finding `json:"findings,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// UpdateFindingRequest represents the request for updating a finding
type UpdateFindingRequest struct {
	Username       string      `json:"username"`
	Password       string      `json:"password"`
	TargetPlextrac string      `json:"targetPlextrac"`
	ClientId       string      `json:"clientId"`
	ReportId       string      `json:"reportId"`
	FindingId      string      `json:"findingId"`
	UpdateType     string      `json:"updateType"` // 'severity', 'status', 'customFields', etc.
	Severity       string      `json:"severity,omitempty"`
	Status         string      `json:"status,omitempty"`
	CustomFields   *FieldValue `json:"customFields,omitempty"`
}

// BulkUpdateRequest represents the request for bulk updating findings
type BulkUpdateRequest struct {
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	TargetPlextrac string   `json:"targetPlextrac"`
	ClientId       string   `json:"clientId"`
	ReportId       string   `json:"reportId"`
	FindingIds     []string `json:"findingIds"`
	UpdateType     string   `json:"updateType"` // 'tags', 'status', etc.
	Tags           []string `json:"tags,omitempty"`
	Status         string   `json:"status,omitempty"`
}

// UpdateResponse represents the response for updating findings
type UpdateResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// GetFindings fetches findings from Plextrac
func (a *App) GetFindings(request FindingsRequest) FindingsResponse {
	// Create a custom logger that emits events
	customLogger := a.createEventLogger()
	customLogger.Info("Fetching findings from Plextrac")

	// Send status event
	runtime.EventsEmit(a.ctx, "n2p:status", "Fetching findings...")

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        request.Username,
		"password":        request.Password,
		"target_plextrac": request.TargetPlextrac,
		"client_id":       request.ClientId,
		"report_id":       request.ReportId,
		"verbosity":       1,
		"logger":          customLogger,
	}

	// Create the engine
	engine := n2p.NewEngine(engineArgs)

	// Initialize the engine
	if err := engine.InitializeEngine(); err != nil {
		customLogger.WithError(err).Error("Failed to initialize engine")
		return FindingsResponse{
			Success:  false,
			Error:    fmt.Sprintf("Failed to initialize engine: %v", err),
			Findings: []Finding{}, // Return empty array to avoid null checks in frontend
		}
	}

	// Get the flaws URL
	url := engine.URLManager.GetFlawsURL()
	if url == "" {
		customLogger.Error("Failed to get flaws URL")
		return FindingsResponse{
			Success:  false,
			Error:    "Failed to get flaws URL",
			Findings: []Finding{}, // Return empty array to avoid null checks in frontend
		}
	}

	customLogger.Infof("Fetching findings from URL: %s", url)

	// Make the request
	response, err := engine.RequestHandler.Get(url, nil, nil)
	if err != nil {
		customLogger.WithError(err).Error("Failed to fetch findings")
		return FindingsResponse{
			Success:  false,
			Error:    fmt.Sprintf("Failed to fetch findings: %v", err),
			Findings: []Finding{}, // Return empty array to avoid null checks in frontend
		}
	}

	// Check response status
	if response.GetStatusCode() != 200 {
		customLogger.Errorf("Failed to fetch findings: status code %d", response.GetStatusCode())
		return FindingsResponse{
			Success:  false,
			Error:    fmt.Sprintf("Failed to fetch findings: status code %d", response.GetStatusCode()),
			Findings: []Finding{}, // Return empty array to avoid null checks in frontend
		}
	}

	// Log raw response for debugging
	bodyBytes := response.GetBody()
	if len(bodyBytes) > 0 {
		customLogger.Debugf("Raw response body: %s", string(bodyBytes[:min(1000, len(bodyBytes))]))
	}

	// Decode the response using the new function with better error handling
	flawsResponse, err := a.decodeFlawsResponse(response, customLogger)
	if err != nil {
		customLogger.WithError(err).Error("Failed to decode findings response")
		return FindingsResponse{
			Success:  false,
			Error:    fmt.Sprintf("Failed to decode findings response: %v", err),
			Findings: []Finding{}, // Return empty array to avoid null checks in frontend
		}
	}

	// Send debug event with the number of flaws
	runtime.EventsEmit(a.ctx, "n2p:debug", map[string]interface{}{
		"response": fmt.Sprintf("Found %d findings in response", len(flawsResponse)),
	})

	// Transform the response into our Finding struct
	findings := make([]Finding, 0)

	// Get existing findings using a more direct approach
	for _, flawData := range flawsResponse {
		// Log each flaw data for debugging
		customLogger.Debugf("Processing flaw data: %+v", flawData)

		// Extract finding ID
		var flawID string
		if id, ok := flawData["id"]; ok {
			flawID = fmt.Sprintf("%v", id)
		} else if data, ok := flawData["data"].([]interface{}); ok && len(data) > 0 {
			flawID = fmt.Sprintf("%v", data[0])
		} else {
			customLogger.Warnf("Could not extract flaw ID from data: %+v", flawData)
			continue
		}

		customLogger.Infof("Processing flaw ID: %s", flawID)

		// Fetch detailed information for each flaw
		detailedFlaw, err := a.getDetailedFinding(engine, flawID)
		if err != nil {
			customLogger.WithError(err).Warnf("Failed to get detailed information for flaw %s", flawID)
			continue
		}

		// Map the detailed flaw data to our Finding struct
		finding := Finding{
			FlawID:          flawID,
			Title:           getStringValue(detailedFlaw, "title"),
			Severity:        getStringValue(detailedFlaw, "severity"),
			Status:          getStringValue(detailedFlaw, "status"),
			Description:     getStringValue(detailedFlaw, "description"),
			Recommendations: getStringValue(detailedFlaw, "recommendations"),
		}

		// Extract tags
		if tags, ok := detailedFlaw["tags"].([]interface{}); ok {
			finding.Tags = make([]string, len(tags))
			for i, tag := range tags {
				finding.Tags[i] = fmt.Sprintf("%v", tag)
			}
		}

		// Extract custom fields, handling both array and map formats
		if fields, ok := detailedFlaw["fields"].([]interface{}); ok {
			finding.Fields = make([]FieldValue, 0)
			for _, field := range fields {
				if fieldMap, ok := field.(map[string]interface{}); ok {
					fieldValue := FieldValue{
						Key:   getStringValue(fieldMap, "key"),
						Label: getStringValue(fieldMap, "label"),
						Value: getStringValue(fieldMap, "value"),
					}
					finding.Fields = append(finding.Fields, fieldValue)
				}
			}
		} else if fields, ok := detailedFlaw["fields"].(map[string]interface{}); ok {
			// Handle fields as a map
			finding.Fields = make([]FieldValue, 0, len(fields))
			for key, field := range fields {
				if fieldMap, ok := field.(map[string]interface{}); ok {
					fieldValue := FieldValue{
						Key:   key,
						Label: getStringValue(fieldMap, "label"),
						Value: getStringValue(fieldMap, "value"),
					}
					finding.Fields = append(finding.Fields, fieldValue)
				}
			}
		}

		findings = append(findings, finding)
	}

	customLogger.Infof("Successfully fetched %d findings", len(findings))

	// Send completion status
	runtime.EventsEmit(a.ctx, "n2p:status", fmt.Sprintf("Fetched %d findings", len(findings)))

	return FindingsResponse{
		Success:  true,
		Findings: findings,
	}
}

// Helper function to get min of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper function to decode flaws response with better error handling
func (a *App) decodeFlawsResponse(response *plextrac.Response, logger *logrus.Logger) ([]map[string]interface{}, error) {
	// First try to decode as array of maps
	var flawsArray []map[string]interface{}
	if err := response.DecodeJSON(&flawsArray); err == nil {
		logger.Infof("Successfully decoded response as array with %d items", len(flawsArray))
		return flawsArray, nil
	}

	// If that fails, try decoding as a map with data field
	var flawsMap map[string]interface{}
	if err := response.DecodeJSON(&flawsMap); err != nil {
		return nil, fmt.Errorf("failed to decode as array or map: %v", err)
	}

	// Try to extract data array from map
	if data, ok := flawsMap["data"].([]interface{}); ok {
		result := make([]map[string]interface{}, 0, len(data))
		for _, item := range data {
			if itemMap, ok := item.(map[string]interface{}); ok {
				result = append(result, itemMap)
			}
		}
		logger.Infof("Extracted %d items from data field", len(result))
		return result, nil
	}

	// If we get here, we found a map but couldn't extract array data
	logger.Warnf("Response decoded as map but couldn't extract findings array. Keys: %v", getMapKeys(flawsMap))

	// Return single item array with the map itself
	return []map[string]interface{}{flawsMap}, nil
}

// Helper function to get map keys for logging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Helper function to get string value from map
func getStringValue(data map[string]interface{}, key string) string {
	if value, ok := data[key]; ok {
		return fmt.Sprintf("%v", value)
	}
	return ""
}

// Get detailed information for a single finding
// Get detailed information for a single finding
func (a *App) getDetailedFinding(engine *n2p.Engine, flawID string) (map[string]interface{}, error) {
	// Extract the actual flaw ID from the formatted string
	// Format appears to be: flaw_[clientId]-[reportId]-[actualFlawId]
	actualFlawID := flawID

	// Check if it matches the pattern
	if strings.HasPrefix(flawID, "flaw_") {
		parts := strings.Split(flawID, "-")
		if len(parts) >= 3 {
			// The last part is the actual flawID we need
			actualFlawID = parts[len(parts)-1]
		}
	}

	// Log what we're doing
	engine.Logger.Infof("Getting detailed info for flaw - Original ID: %s, Extracted ID: %s", flawID, actualFlawID)

	// Get the URL for fetching finding details
	url := engine.URLManager.GetUpdateFindingURL(actualFlawID)
	if url == "" {
		engine.Logger.Errorf("Failed to get update finding URL for flaw ID %s", actualFlawID)
		return nil, fmt.Errorf("failed to get update finding URL for flaw ID %s", actualFlawID)
	}

	engine.Logger.Infof("Fetching detailed info from URL: %s", url)

	// Make the request with explicit headers
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	response, err := engine.RequestHandler.Get(url, headers, nil)
	if err != nil {
		engine.Logger.Errorf("Request failed for flaw ID %s: %v", actualFlawID, err)
		return nil, fmt.Errorf("failed to get detailed finding: %w", err)
	}

	// Log the response status
	statusCode := response.GetStatusCode()
	engine.Logger.Infof("Response status code: %d for flaw ID %s", statusCode, actualFlawID)

	if statusCode != 200 {
		// Get the response body for more detailed error logging
		bodyBytes := response.GetBody()
		bodyStr := string(bodyBytes)
		engine.Logger.Errorf("Failed to get detailed finding with status code %d: %s", statusCode, bodyStr)
		return nil, fmt.Errorf("failed to get detailed finding: status code %d, response: %s", statusCode, bodyStr)
	}

	// Log the first part of the response for debugging
	bodyBytes := response.GetBody()
	if len(bodyBytes) > 0 {
		previewLen := min(500, len(bodyBytes))
		engine.Logger.Debugf("First %d bytes of response: %s", previewLen, string(bodyBytes[:previewLen]))
	}

	// Decode the response
	var detailedFlaw map[string]interface{}
	if err := response.DecodeJSON(&detailedFlaw); err != nil {
		engine.Logger.Errorf("Failed to decode detailed finding response: %v", err)
		return nil, fmt.Errorf("failed to decode detailed finding: %w", err)
	}

	// Add the original flaw_id to the result
	detailedFlaw["flaw_id"] = flawID

	// Log the keys found in the response
	keys := make([]string, 0, len(detailedFlaw))
	for k := range detailedFlaw {
		keys = append(keys, k)
	}
	engine.Logger.Debugf("Found keys in response for flaw ID %s: %v", actualFlawID, keys)

	return detailedFlaw, nil
}

// UpdateFinding updates a single finding
func (a *App) UpdateFinding(request UpdateFindingRequest) UpdateResponse {
	// Create a custom logger that emits events
	customLogger := a.createEventLogger()
	customLogger.Infof("Updating finding %s", request.FindingId)

	// Send status event
	runtime.EventsEmit(a.ctx, "n2p:status", fmt.Sprintf("Updating finding %s...", request.FindingId))

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        request.Username,
		"password":        request.Password,
		"target_plextrac": request.TargetPlextrac,
		"client_id":       request.ClientId,
		"report_id":       request.ReportId,
		"verbosity":       1,
		"logger":          customLogger,
	}

	// Create the engine
	engine := n2p.NewEngine(engineArgs)

	// Initialize the engine
	if err := engine.InitializeEngine(); err != nil {
		customLogger.WithError(err).Error("Failed to initialize engine")
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to initialize engine: %v", err),
		}
	}

	// First get the current finding data
	url := engine.URLManager.GetUpdateFindingURL(request.FindingId)
	if url == "" {
		customLogger.Error("Failed to get update finding URL")
		return UpdateResponse{
			Success: false,
			Error:   "Failed to get update finding URL",
		}
	}

	response, err := engine.RequestHandler.Get(url, nil, nil)
	if err != nil {
		customLogger.WithError(err).Error("Failed to get finding details")
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get finding details: %v", err),
		}
	}

	if response.GetStatusCode() != 200 {
		customLogger.Errorf("Failed to get finding details: status code %d", response.GetStatusCode())
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get finding details: status code %d", response.GetStatusCode()),
		}
	}

	var detailedFlaw map[string]interface{}
	if err := response.DecodeJSON(&detailedFlaw); err != nil {
		customLogger.WithError(err).Error("Failed to decode finding details")
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to decode finding details: %v", err),
		}
	}

	// Update the finding based on the update type
	switch request.UpdateType {
	case "severity":
		detailedFlaw["severity"] = request.Severity
	case "status":
		detailedFlaw["status"] = request.Status
	case "customFields":
		if request.CustomFields != nil {
			// First get the existing fields
			var fields []map[string]interface{}

			// Handle fields as an array or a map
			if fieldsData, ok := detailedFlaw["fields"].([]interface{}); ok {
				for _, fieldData := range fieldsData {
					if field, ok := fieldData.(map[string]interface{}); ok {
						fields = append(fields, field)
					}
				}
			} else if fieldsMap, ok := detailedFlaw["fields"].(map[string]interface{}); ok {
				// Convert map to array
				for key, fieldData := range fieldsMap {
					if field, ok := fieldData.(map[string]interface{}); ok {
						field["key"] = key // Ensure key is in the field object
						fields = append(fields, field)
					}
				}
			}

			// Find and update the field with the matching key, or add it if not found
			found := false
			for i, field := range fields {
				if key, ok := field["key"].(string); ok && key == request.CustomFields.Key {
					fields[i]["value"] = request.CustomFields.Value
					found = true
					break
				}
			}

			if !found {
				// Add new field
				fields = append(fields, map[string]interface{}{
					"key":   request.CustomFields.Key,
					"label": request.CustomFields.Label,
					"value": request.CustomFields.Value,
				})
			}

			detailedFlaw["fields"] = fields
		}
	default:
		customLogger.Warnf("Unknown update type: %s", request.UpdateType)
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown update type: %s", request.UpdateType),
		}
	}

	// Update the finding
	customLogger.Infof("Sending PUT request to update finding %s", request.FindingId)
	putResponse, err := engine.RequestHandler.Put(url, nil, nil, detailedFlaw)
	if err != nil {
		customLogger.WithError(err).Error("Failed to update finding")
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to update finding: %v", err),
		}
	}

	// Check response status
	if putResponse.GetStatusCode() != 200 {
		customLogger.Errorf("Failed to update finding: status code %d", putResponse.GetStatusCode())
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to update finding: status code %d", putResponse.GetStatusCode()),
		}
	}

	customLogger.Infof("Successfully updated finding %s", request.FindingId)

	return UpdateResponse{
		Success: true,
	}
}

// BulkUpdateFindings performs a bulk update of findings
func (a *App) BulkUpdateFindings(request BulkUpdateRequest) UpdateResponse {
	// Create a custom logger that emits events
	customLogger := a.createEventLogger()
	customLogger.Infof("Bulk updating %d findings", len(request.FindingIds))

	// Send status event
	runtime.EventsEmit(a.ctx, "n2p:status", fmt.Sprintf("Bulk updating %d findings...", len(request.FindingIds)))

	// Create a properly formatted map for the n2p.Engine
	engineArgs := map[string]interface{}{
		"username":        request.Username,
		"password":        request.Password,
		"target_plextrac": request.TargetPlextrac,
		"client_id":       request.ClientId,
		"report_id":       request.ReportId,
		"verbosity":       1,
		"logger":          customLogger,
	}

	// Create the engine
	engine := n2p.NewEngine(engineArgs)

	// Initialize the engine
	if err := engine.InitializeEngine(); err != nil {
		customLogger.WithError(err).Error("Failed to initialize engine")
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to initialize engine: %v", err),
		}
	}

	// Prepare URL for bulk update
	baseURL := fmt.Sprintf("https://%s.kevlar.bulletproofsi.net", request.TargetPlextrac)
	url := fmt.Sprintf("%s/api/v2/clients/%s/reports/%s/findings", baseURL, request.ClientId, request.ReportId)

	// Debug log the URL
	customLogger.Infof("Bulk update URL: %s", url)

	// Prepare data object based on update type
	data := map[string]interface{}{}

	switch request.UpdateType {
	case "tags":
		data["tags"] = request.Tags
	case "status":
		data["status"] = request.Status
	default:
		customLogger.Warnf("Unknown bulk update type: %s", request.UpdateType)
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown bulk update type: %s", request.UpdateType),
		}
	}

	// Extract numeric IDs from string IDs
	numericIds := make([]int, 0, len(request.FindingIds))
	for _, findingId := range request.FindingIds {
		// For IDs in the format "flaw_clientId-reportId-actualId"
		if strings.HasPrefix(findingId, "flaw_") {
			parts := strings.Split(findingId, "-")
			if len(parts) >= 3 {
				// The last part is the actual flawID we need
				actualId := parts[len(parts)-1]
				numId, err := strconv.Atoi(actualId)
				if err != nil {
					customLogger.Warnf("Failed to parse numeric ID from %s: %v", findingId, err)
					continue
				}
				numericIds = append(numericIds, numId)
			} else {
				customLogger.Warnf("Finding ID %s does not match expected format", findingId)
			}
		} else {
			// Try to parse the ID directly as a number
			numId, err := strconv.Atoi(findingId)
			if err != nil {
				customLogger.Warnf("Failed to parse numeric ID from %s: %v", findingId, err)
				continue
			}
			numericIds = append(numericIds, numId)
		}
	}

	if len(numericIds) == 0 {
		return UpdateResponse{
			Success: false,
			Error:   "Failed to extract any valid numeric finding IDs",
		}
	}

	// Format the payload with numeric finding IDs
	payload := map[string]interface{}{
		"findings": numericIds,
		"data":     data,
	}

	// Log the payload for debugging
	payloadBytes, _ := json.MarshalIndent(payload, "", "  ")
	customLogger.Infof("Payload for bulk update: %s", string(payloadBytes))

	// Add authorization header
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	// Make the request using PUT method
	response, err := engine.RequestHandler.Put(url, headers, nil, payload)
	if err != nil {
		customLogger.WithError(err).Error("Failed to perform bulk update")
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to perform bulk update: %v", err),
		}
	}

	// Check response status
	statusCode := response.GetStatusCode()
	bodyBytes := response.GetBody()
	bodyStr := string(bodyBytes)

	customLogger.Infof("Response status: %d", statusCode)
	customLogger.Infof("Response body: %s", bodyStr)

	if statusCode != 200 {
		customLogger.Errorf("Failed to perform bulk update: status code %d, body: %s", statusCode, bodyStr)
		return UpdateResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to perform bulk update: status code %d", statusCode),
		}
	}

	customLogger.Infof("Successfully performed bulk update for %d findings", len(numericIds))

	return UpdateResponse{
		Success: true,
	}
}

func main() {
	// Setup global panic handler for uncaught exceptions
	setupGlobalPanicHandler()

	// Command line handling
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		parsedArgs := args.ParseArgs()
		if parsedArgs.NessusMode != "" {
			// Add crash reporting to Nessus controller command-line mode
			reporter := crash.NewReporter("crash_reports")
			func() {
				defer reporter.RecoverWithCrashReport("NessusControllerCLI", map[string]string{
					"mode":    parsedArgs.NessusMode,
					"host":    parsedArgs.RemoteHost,
					"project": parsedArgs.ProjectName,
				})
				engine.HandleNessusController(parsedArgs)
			}()
			return
		}

		// Add crash reporting to normal NMB command-line mode
		reporter := crash.NewReporter("crash_reports")
		func() {
			defer reporter.RecoverWithCrashReport("NMBCLI", map[string]string{
				"nessusFile": parsedArgs.NessusFilePath,
				"projectDir": parsedArgs.ProjectFolder,
				"numWorkers": fmt.Sprintf("%d", parsedArgs.NumWorkers),
				"configFile": parsedArgs.ConfigFilePath,
			})
			engine.RunNMB(parsedArgs)
		}()
		return
	}

	app := NewApp()

	// Start API server with crash reporting
	go func() {
		reporter := crash.NewReporter("crash_reports")
		defer reporter.RecoverWithCrashReport("APIServer", nil)

		server := api.NewServer()
		if err := server.Run(); err != nil {
			log.Printf("API server error: %v", err)
		}
	}()

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
