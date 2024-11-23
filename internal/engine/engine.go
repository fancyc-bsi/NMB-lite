package engine

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

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

	"github.com/fatih/color"
)

func init() {
	// Ensure logging package is initialized
	if logging.InfoLogger == nil {
		logging.InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	}
	if logging.ErrorLogger == nil {
		logging.ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
	}
	if logging.SuccessLogger == nil {
		logging.SuccessLogger = log.New(os.Stdout, "SUCCESS: ", log.Ldate|log.Ltime)
	}
}

func HandleNessusController(parsedArgs *args.Args) {
	validateNessusArgs(parsedArgs)

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

	logging.SuccessLogger.Printf("Successfully completed Nessus %s operation", parsedArgs.NessusMode)
}

func RunNMB(parsedArgs *args.Args) {
	if parsedArgs.NessusFilePath == "" || parsedArgs.NessusFilePath == "path/to/nessus.csv" {
		logging.ErrorLogger.Fatal("Nessus file path (-nessus) is required for NMB operation")
	}

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

	printSupportedPlugins(report.SupportedPlugins)

	var remoteExec *remote.RemoteExecutor
	if parsedArgs.RemoteHost != "" {
		var err error
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

func printSupportedPlugins(supportedPlugins []string) {
	if len(supportedPlugins) == 0 {
		fmt.Println("No supported plugins found.")
		return
	}

	header := color.New(color.FgHiGreen, color.Bold).SprintfFunc()
	pluginItem := color.New(color.FgHiBlue).SprintfFunc()
	divider := strings.Repeat("=", 50)

	fmt.Println(divider)
	fmt.Println(header("Supported Plugins List"))
	fmt.Println(divider)

	for i, plugin := range supportedPlugins {
		fmt.Printf("%s %s\n", pluginItem("[%d]", i+1), plugin)
	}

	fmt.Println(divider)
}
