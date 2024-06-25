package cleanup

import (
	"NMB/internal/logging"
	"os"
	"path/filepath"
)

func MoveCSVToProjectFolder(csvFilePath, projectFolder string) {
	if err := os.MkdirAll(projectFolder, os.ModePerm); err != nil {
		logging.ErrorLogger.Printf("Failed to create project folder: %v", err)
		return
	}

	newFilePath := filepath.Join(projectFolder, filepath.Base(csvFilePath))
	err := os.Rename(csvFilePath, newFilePath)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to move CSV file to project folder: %v", err)
		return
	}

	logging.InfoLogger.Printf("CSV file moved to project folder: %s", newFilePath)
}
