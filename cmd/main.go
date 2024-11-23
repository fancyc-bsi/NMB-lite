package main

import (
	"NMB/internal/api"
	"NMB/internal/args"
	"NMB/internal/engine"
	"embed"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed ui
var uiBinary embed.FS

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		// Start the API server in a goroutine
		go func() {
			server := api.NewServer()
			if err := server.Run(); err != nil {
				panic("Failed to start API server: " + err.Error())
			}
		}()

		// Unpack and execute the embedded UI binary
		err := unpackAndRunUI()
		if err != nil {
			panic("Failed to start UI: " + err.Error())
		}

		return
	}

	// Handle CLI mode
	parsedArgs := args.ParseArgs()
	if parsedArgs.NessusMode != "" {
		engine.HandleNessusController(parsedArgs)
		return
	}

	engine.RunNMB(parsedArgs)
}

// Unpack and execute the UI binary
func unpackAndRunUI() error {
	// Define the temporary location for the UI binary
	tempDir := "/tmp/nmb_ui"
	err := os.MkdirAll(tempDir, os.ModePerm)
	if err != nil {
		return err
	}

	// Extract the UI binary from the embed.FS into the temporary directory
	uiData, err := uiBinary.ReadFile("ui")
	if err != nil {
		return err
	}

	// Create the UI binary in the temporary directory
	uiBinaryPath := filepath.Join(tempDir, "ui")
	err = ioutil.WriteFile(uiBinaryPath, uiData, 0755)
	if err != nil {
		return err
	}

	// Run the UI binary
	cmd := exec.Command(uiBinaryPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return err
	}

	return cmd.Wait()
}
