package main

import (
	"NMB/internal/api"
	"NMB/internal/args"
	"NMB/internal/editor"
	"NMB/internal/engine"
	"NMB/internal/logging"
	"NMB/internal/plugin"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:ui-core/build
var assets embed.FS

type App struct {
	ctx               context.Context
	screenshotManager *editor.ScreenshotManager
	pluginManager     *plugin.Manager
}

func NewApp() *App {
	return &App{
		pluginManager: &plugin.Manager{},
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
	configPath := filepath.Join(configDir, "N2P_config.json")

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
