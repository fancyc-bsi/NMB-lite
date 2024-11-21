// main.go
package main

import (
	"os"
	"path/filepath"

	"NMB/internal/args"
	"NMB/internal/config"
	"NMB/internal/logging"
	"NMB/internal/nessus"
	NessusController "NMB/internal/nessus-controller"
	"NMB/internal/remote"
	"NMB/internal/render"
	"NMB/internal/report"
	"NMB/internal/scanner"
	"NMB/internal/workerpool"
)

func main() {
	logging.Init()
	defer func() {
		if r := recover(); r != nil {
			logging.ErrorLogger.Printf("Unexpected error: %v", r)
			os.Exit(1)
		}
	}()

	parsedArgs := args.ParseArgs()

	// If Nessus controller mode is specified, handle it separately
	if parsedArgs.NessusMode != "" {
		handleNessusController(parsedArgs)
		return
	}

	// Original NMB functionality
	RunNMB(parsedArgs)
}

func handleNessusController(parsedArgs *args.Args) {
	validateNessusArgs(parsedArgs)

	// Initialize Nessus controller
	controller, err := NessusController.New(
		parsedArgs.RemoteHost,
		parsedArgs.RemoteUser,
		parsedArgs.RemotePass,
		parsedArgs.ProjectName,
		parsedArgs.TargetsFile,
		getExcludeFiles(parsedArgs),
		parsedArgs.Discovery,
	)
	if err != nil {
		logging.ErrorLogger.Fatalf("Failed to initialize Nessus controller: %v", err)
	}

	// Execute the requested operation
	var execErr error
	switch parsedArgs.NessusMode {
	case "deploy":
		execErr = controller.Deploy()
	case "create":
		execErr = controller.Create()
	case "launch":
		execErr = controller.Launch()
	case "pause":
		execErr = controller.Pause()
	case "resume":
		execErr = controller.Resume()
	case "monitor":
		execErr = controller.Monitor()
	case "export":
		execErr = controller.Export()
	default:
		logging.ErrorLogger.Fatalf("Invalid Nessus mode: %s", parsedArgs.NessusMode)
	}

	if execErr != nil {
		logging.ErrorLogger.Fatalf("Failed to execute Nessus %s mode: %v", parsedArgs.NessusMode, execErr)
	}

	logging.InfoLogger.Printf("Successfully completed Nessus %s operation", parsedArgs.NessusMode)
}

func validateNessusArgs(args *args.Args) {
	if args.RemoteHost == "" {
		logging.ErrorLogger.Fatal("Remote host (-remote) is required for Nessus controller operations")
	}
	if args.RemoteUser == "" {
		logging.ErrorLogger.Fatal("Remote user (-user) is required for Nessus controller operations")
	}
	if args.RemotePass == "" {
		logging.ErrorLogger.Fatal("Remote password (-password) is required for Nessus controller operations")
	}
	if args.ProjectName == "" {
		logging.ErrorLogger.Fatal("Project name (-name) is required for Nessus controller operations")
	}

	// Validate mode-specific requirements
	switch args.NessusMode {
	case "deploy", "create":
		if args.TargetsFile == "" {
			logging.ErrorLogger.Fatal("Targets file (-targets) is required for deploy/create operations")
		}
	}
}

func getExcludeFiles(args *args.Args) []string {
	var excludeFiles []string
	if args.ExcludeFile != "" {
		excludeFiles = append(excludeFiles, args.ExcludeFile)
	}
	return excludeFiles
}

func RunNMB(parsedArgs *args.Args) {
	// Validate required args for NMB mode
	if parsedArgs.NessusFilePath == "" || parsedArgs.NessusFilePath == "path/to/nessus.csv" {
		logging.ErrorLogger.Fatal("Nessus file path (-nessus) is required for NMB operation")
	}

	// Load configuration
	var cfg config.Config
	if parsedArgs.ConfigFilePath != "" {
		if _, err := os.Stat(parsedArgs.ConfigFilePath); os.IsNotExist(err) {
			logging.ErrorLogger.Fatalf("Config file %s not found", parsedArgs.ConfigFilePath)
		}
		cfg = config.LoadConfigFromFile(parsedArgs.ConfigFilePath)
		logging.InfoLogger.Println("Using provided config file")
	} else {
		cfg = config.LoadEmbeddedConfig()
		logging.InfoLogger.Println("Using embedded config")
	}

	// Create project folder if it doesn't exist
	if err := os.MkdirAll(parsedArgs.ProjectFolder, 0755); err != nil {
		logging.ErrorLogger.Fatalf("Failed to create project folder: %v", err)
	}

	findings, pluginData, err := nessus.ParseCSV(parsedArgs.NessusFilePath)
	if err != nil {
		logging.ErrorLogger.Fatalf("Failed to parse Nessus CSV: %v", err)
	}

	report := &report.Report{
		ProjectFolder: parsedArgs.ProjectFolder,
	}
	report.SupportedPlugins, report.MissingPlugins = nessus.GetSupportedAndMissingPlugins(findings, cfg.Plugins)

	var remoteExec *remote.RemoteExecutor
	if parsedArgs.RemoteHost != "" {
		remoteExec, err = remote.NewRemoteExecutor(
			parsedArgs.RemoteHost,
			parsedArgs.RemoteUser,
			parsedArgs.RemotePass,
			parsedArgs.RemoteKey,
		)
		if err != nil {
			logging.ErrorLogger.Fatalf("Failed to initialize remote executor: %v", err)
		}
		defer remoteExec.Close()
		logging.InfoLogger.Printf("Connected to remote host: %s", parsedArgs.RemoteHost)
	}

	scn := scanner.Scanner{
		Config:        cfg,
		Findings:      findings,
		PluginData:    pluginData,
		ProjectFolder: parsedArgs.ProjectFolder,
		Report:        report,
		RemoteExec:    remoteExec,
	}

	workerpool.StartWorkerPool(parsedArgs.NumWorkers, findings, scn.RunScans)

	generateAndSaveReport(report, parsedArgs.ProjectFolder)
}

func generateAndSaveReport(report *report.Report, projectFolder string) {
	if err := report.Generate(); err != nil {
		logging.ErrorLogger.Fatalf("Failed to generate report: %v", err)
	}

	renderedContent, err := render.Generate(report)
	if err != nil {
		logging.ErrorLogger.Fatalf("Failed to render report: %v", err)
	}

	reportFilePath := filepath.Join(projectFolder, "NMB_scan_report.html")
	if err := os.WriteFile(reportFilePath, []byte(renderedContent), 0644); err != nil {
		logging.ErrorLogger.Fatalf("Failed to write rendered report: %v", err)
	}

	logging.InfoLogger.Printf("Report generated at %s", reportFilePath)
}
