package main

import (
	"NMB/internal/args"
	"NMB/internal/config"
	"NMB/internal/logging"
	"NMB/internal/nessus"
	"NMB/internal/remote"
	"NMB/internal/render"
	"NMB/internal/report"
	"NMB/internal/scanner"
	"NMB/internal/workerpool"
	"os"
	"path/filepath"
)

func main() {
	logging.Init()

	defer func() {
		if r := recover(); r != nil {
			logging.ErrorLogger.Printf("Unexpected error: %v", r)
			os.Exit(1)
		}
	}()

	RunNMB()
}

func RunNMB() {
	parsedArgs := args.ParseArgs()

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

	if err := report.Generate(); err != nil {
		logging.ErrorLogger.Fatalf("Failed to generate report: %v", err)
	}

	renderedContent, err := render.Generate(report)
	if err != nil {
		logging.ErrorLogger.Fatalf("Failed to render report: %v", err)
	}

	reportFilePath := filepath.Join(parsedArgs.ProjectFolder, "NMB_scan_report.html")
	if err := os.WriteFile(reportFilePath, []byte(renderedContent), 0644); err != nil {
		logging.ErrorLogger.Fatalf("Failed to write rendered report: %v", err)
	}

	logging.InfoLogger.Printf("Report generated at %s", reportFilePath)
}
