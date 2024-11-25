// main_common.go

package main

import (
	"NMB/internal/api"
	"NMB/internal/args"
	"NMB/internal/engine"
	"NMB/internal/logging"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

func init() {
	logging.Init()
}

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
		if err := unpackAndRunUI(); err != nil {
			panic(fmt.Sprintf("Failed to start UI: %v", err))
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

func unpackAndRunUI() error {
	// Create temporary directory
	tempDir := filepath.Join(os.TempDir(), "nmb_ui")
	if err := os.MkdirAll(tempDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}

	// Clean up temporary files on exit
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to clean up temporary directory: %v\n", err)
		}
	}()

	// Extract the UI binary
	uiData, err := uiBinary.ReadFile(binaryName)
	if err != nil {
		return fmt.Errorf("failed to read UI binary: %w", err)
	}

	// Create the UI binary in the temporary directory
	tempBinaryPath := filepath.Join(tempDir, filepath.Base(binaryName))
	if err := ioutil.WriteFile(tempBinaryPath, uiData, 0755); err != nil {
		return fmt.Errorf("failed to write UI binary: %w", err)
	}

	// Run the UI binary
	cmd := exec.Command(tempBinaryPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start UI binary: %w", err)
	}

	return cmd.Wait()
}
