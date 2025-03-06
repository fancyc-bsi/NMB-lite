// internal/n2p/n2p.go - Main engine

package n2p

import (
	"fmt"
	"os"
	"path/filepath"

	"NMB/internal/n2p/client"
	"NMB/internal/n2p/config"
	"NMB/internal/n2p/converter"
	"NMB/internal/n2p/findings"
	"NMB/internal/n2p/plextrac"

	"github.com/sirupsen/logrus"
)

// Engine orchestrates various operations for the Plextrac integration
type Engine struct {
	Args                  map[string]interface{}
	PlextracFormatFile    string
	ConfigFile            string
	ProcessedFindingsFile string
	Logger                *logrus.Logger
	URLManager            *plextrac.URLManager
	RequestHandler        *plextrac.RequestHandler
	PlextracHandler       *plextrac.Handler
	Config                map[string]interface{}
	Converter             *converter.NessusToPlextracConverter
	NonCoreUpdater        *findings.NonCoreUpdater
	ScreenshotUpdater     *findings.FlawUpdater
	DescProcessor         *findings.DescriptionProcessor
	FlawLister            interface{} // Changed from *findings.FlawLister to interface{}
	AccessToken           string
	Mode                  string
}

// NewEngine creates a new Engine instance
func NewEngine(args map[string]interface{}) *Engine {
	// Set default values
	plextracFormatFile := "plextrac_format.csv"
	configFile := "N2P_config.json"
	processedFindingsFile := "_processed_findings.json"

	// Create logger or use the provided one
	var logger *logrus.Logger
	if loggerArg, ok := args["logger"].(*logrus.Logger); ok {
		logger = loggerArg
	} else {
		logger = logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	return &Engine{
		Args:                  args,
		PlextracFormatFile:    plextracFormatFile,
		ConfigFile:            configFile,
		ProcessedFindingsFile: processedFindingsFile,
		Logger:                logger,
	}
}

// Run executes the main operations of the engine
func (e *Engine) Run() error {
	// Initialize engine and addons
	if err := e.InitializeEngine(); err != nil {
		return fmt.Errorf("failed to initialize engine: %w", err)
	}

	// Check if we're in create mode
	if create, ok := e.Args["create"].(bool); ok && create {
		generator := client.NewClientReportGen(e.URLManager, e.RequestHandler)
		if err := generator.Run(); err != nil {
			return fmt.Errorf("client report generation failed: %w", err)
		}
		return nil
	}

	// Execute main workflow
	if err := e.ExecuteWorkflow(); err != nil {
		return fmt.Errorf("workflow execution failed: %w", err)
	}

	// Apply client overrides if configured
	if clientConfig, ok := e.Args["client_config"].(string); ok && clientConfig != "" {
		if err := e.ApplyClientOverrides(); err != nil {
			return fmt.Errorf("client override application failed: %w", err)
		}
	}

	return nil
}

// InitializeEngine sets up the initial components
func (e *Engine) InitializeEngine() error {
	// Create base URL for Plextrac
	targetPlextrac, ok := e.Args["target_plextrac"].(string)
	if !ok {
		return fmt.Errorf("target_plextrac not provided")
	}
	baseURL := fmt.Sprintf("https://%s.kevlar.bulletproofsi.net/", targetPlextrac)

	// Setup URL manager
	e.URLManager = plextrac.NewURLManager(e.Args, baseURL)

	// Setup request handler
	e.RequestHandler = plextrac.NewRequestHandler("")

	// Get access token
	token, err := e.GetAccessToken()
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}
	e.AccessToken = token
	e.RequestHandler.SetAccessToken(token) // Set token in request handler

	// Set mode based on scope
	scope, _ := e.Args["scope"].(string)
	modeMap := map[string]string{
		"internal":     "internal",
		"external":     "external",
		"web":          "web",
		"surveillance": "surveillance",
		"mobile":       "mobile",
	}
	e.Mode = modeMap[scope]
	if e.Mode == "" {
		e.Mode = "internal" // Default mode
	}

	// Create Plextrac handler
	e.PlextracHandler = plextrac.NewHandler(e.AccessToken, e.RequestHandler, e.URLManager)

	// Load configuration
	conf, err := config.LoadConfig(e.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	e.Config = conf

	// Setup description processor
	e.DescProcessor = findings.NewDescriptionProcessor(e.Config, e.URLManager, e.RequestHandler, e.Mode, e.Args)

	// Initialize addons
	return e.InitializeAddons()
}

// InitializeAddons sets up additional components
func (e *Engine) InitializeAddons() error {
	// Setup flaw lister - DON'T try to type assert
	e.FlawLister = findings.NewFlawLister(e.URLManager, e.RequestHandler, e.Args)

	// Setup converter
	directory, _ := e.Args["directory"].(string)
	e.Converter = converter.NewNessusToPlextracConverter(directory, e.Config, e.Mode, e.Args)

	// Store access token in Args for components that need it
	e.Args["access_token"] = e.AccessToken

	// Setup non-core updater if needed
	if nonCore, ok := e.Args["non_core"].(bool); ok && nonCore {
		e.NonCoreUpdater = findings.NewNonCoreUpdater(e.URLManager, e.RequestHandler, e.Args)
	}

	// Setup screenshot updater
	e.ScreenshotUpdater = findings.NewFlawUpdater(e.Converter, e.Args, e.RequestHandler, e.URLManager)

	return nil
}

// ExecuteWorkflow runs the main operations in sequence
func (e *Engine) ExecuteWorkflow() error {
	// Authenticate to Plextrac
	e.Logger.Info("Authenticating to Plextrac...")
	authenticated, err := e.PlextracHandler.Authenticate()
	if err != nil || !authenticated {
		e.Logger.Warn("Authentication failed: %v", err)
		return fmt.Errorf("authentication failed")
	}
	e.Logger.Info("Authentication successful")

	// Convert to Plextrac format
	e.Logger.Info("Converting Nessus file to Plextrac format...")
	if err := e.Converter.Convert(e.PlextracFormatFile); err != nil {
		e.Logger.Warn("Conversion failed: %v", err)
		return fmt.Errorf("conversion failed")
	}
	e.Logger.Info("Conversion successful")

	// Catalog existing flaws
	e.Logger.Info("Cataloging existing flaws...")

	// Use type assertion correctly with interface check
	if flawLister, ok := e.FlawLister.(interface {
		GetExistingFlaws() []map[string]interface{}
	}); ok {
		existingFlaws := flawLister.GetExistingFlaws()
		flawsFilePath := "./existing_flaws.txt"
		if err := e.WriteFlawsToFile(existingFlaws, flawsFilePath); err != nil {
			e.Logger.Warn("Failed to write flaws to file: %v", err)
			return fmt.Errorf("failed to write flaws to file")
		}
	} else {
		e.Logger.Warn("FlawLister does not implement GetExistingFlaws method")
	}

	e.Logger.Info("Existing flaws cataloged")

	// Upload Nessus file
	e.Logger.Info("Uploading Nessus file to Plextrac...")
	if err := e.PlextracHandler.UploadNessusFile(e.PlextracFormatFile); err != nil {
		e.Logger.Warn("Upload failed: %v", err)
		return fmt.Errorf("upload failed")
	}
	e.Logger.Info("Upload successful")

	// Upload screenshots
	e.Logger.Info("Updating flaws with screenshots...")
	if err := e.ScreenshotUpdater.FlawUpdateEngine(); err != nil {
		e.Logger.Warn("Screenshot update failed: %v", err)
		// Continue execution instead of returning error
		e.Logger.Warn("Continuing execution despite screenshot update failure")
	} else {
		e.Logger.Info("Screenshot update successful")
	}

	// Process descriptions
	e.Logger.Info("Processing and updating descriptions for flaws...")
	if err := e.DescProcessor.Process(); err != nil {
		e.Logger.Warn("Description processing failed: %v", err)
		// Continue execution instead of returning error
		e.Logger.Warn("Continuing execution despite description processing failure")
	} else {
		e.Logger.Info("Description processing successful")
	}

	// Add non-core fields if enabled
	if e.NonCoreUpdater != nil {
		e.Logger.Info("Processing and updating custom fields for flaws...")
		if err := e.NonCoreUpdater.Process(); err != nil {
			e.Logger.Warn("Non-core field processing failed: %v", err)
			// Continue execution instead of returning error
			e.Logger.Warn("Continuing execution despite non-core field processing failure")
		} else {
			e.Logger.Info("Custom field processing successful")
		}
	}

	// Cleanup on exit
	e.CleanupOnExit()
	return nil
}

// GetAccessToken authenticates and obtains an access token
func (e *Engine) GetAccessToken() (string, error) {
	authURL := e.URLManager.GetAuthenticateURL()
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	username, _ := e.Args["username"].(string)
	password, _ := e.Args["password"].(string)

	payload := map[string]interface{}{
		"username": username,
		"password": password,
	}

	response, err := e.RequestHandler.Post(authURL, headers, nil, payload, nil, nil)
	if err != nil {
		return "", fmt.Errorf("authentication request failed: %w", err)
	}

	if response.StatusCode != 200 {
		return "", fmt.Errorf("authentication failed with status code %d", response.StatusCode)
	}

	var data map[string]interface{}
	if err := response.DecodeJSON(&data); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	token, ok := data["token"].(string)
	if !ok {
		return "", fmt.Errorf("failed to get access token from response")
	}

	e.RequestHandler.SetAccessToken(token)
	return token, nil
}

// WriteFlawsToFile writes flaw IDs to a file
func (e *Engine) WriteFlawsToFile(flaws []map[string]interface{}, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	for _, flaw := range flaws {
		flawID, ok := flaw["flaw_id"]
		if !ok {
			continue
		}
		if _, err := fmt.Fprintf(file, "%v\n", flawID); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}

// ApplyClientOverrides applies client-specific configurations
func (e *Engine) ApplyClientOverrides() error {
	e.Logger.Info("Applying client-specific configurations...")

	clientOverrides := client.NewClientOverrides(e.URLManager, e.RequestHandler, e.Args)

	if err := clientOverrides.ReplaceEngine(); err != nil {
		return fmt.Errorf("client override failed: %w", err)
	}

	e.Logger.Info("Client-specific configurations applied")
	return nil
}

// CleanupOnExit performs cleanup operations
func (e *Engine) CleanupOnExit() {
	e.Logger.Info("Cleaning up...")

	// Move Plextrac format file to _merged folder
	if err := e.MovePlextracFormatFile(); err != nil {
		e.Logger.Warn("Failed to move Plextrac format file: %v", err)
	}

	// Clean up existing flaws file
	if err := e.CleanupFile("existing_flaws.txt"); err != nil {
		e.Logger.Warn("Failed to clean up existing flaws file: %v", err)
	}

	e.Logger.Info("Cleanup complete")
}

// MovePlextracFormatFile moves the Plextrac format file to the _merged folder
func (e *Engine) MovePlextracFormatFile() error {
	destFolder := "_merged"
	if err := os.MkdirAll(destFolder, 0755); err != nil {
		return fmt.Errorf("failed to create _merged folder: %w", err)
	}

	destPath := filepath.Join(destFolder, filepath.Base(e.PlextracFormatFile))
	if err := os.Rename(e.PlextracFormatFile, destPath); err != nil {
		return fmt.Errorf("failed to move file: %w", err)
	}

	e.Logger.Infof("Moved merged plextrac file '%s' to %s", e.PlextracFormatFile, destPath)
	return nil
}

// CleanupFile removes a specified file if it exists
func (e *Engine) CleanupFile(filePath string) error {
	if _, err := os.Stat(filePath); err == nil {
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove file: %w", err)
		}
	}
	return nil
}
