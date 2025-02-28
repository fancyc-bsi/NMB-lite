package editor

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type ScreenshotManager struct {
	ctx context.Context
}

// NewScreenshotManager creates a new screenshot manager
func NewScreenshotManager(ctx context.Context) *ScreenshotManager {
	return &ScreenshotManager{
		ctx: ctx,
	}
}

// OpenDirectoryDialog opens a directory selection dialog
func (sm *ScreenshotManager) OpenDirectoryDialog() (string, error) {
	directory, err := runtime.OpenDirectoryDialog(sm.ctx, runtime.OpenDialogOptions{
		Title: "Select Screenshots Directory",
	})
	if err != nil {
		return "", err
	}
	return directory, nil
}

// ListImageFilesInDirectory returns a list of image files in the given directory
func (sm *ScreenshotManager) ListImageFilesInDirectory(dirPath string) ([]string, error) {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	var imageFiles []string
	validExtensions := map[string]bool{
		".png":  true,
		".jpg":  true,
		".jpeg": true,
		".bmp":  true,
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(file.Name()))
		if validExtensions[ext] {
			imageFiles = append(imageFiles, filepath.Join(dirPath, file.Name()))
		}
	}
	return imageFiles, nil
}

// ReadImageFile reads an image file and returns its content as base64
func (sm *ScreenshotManager) ReadImageFile(filePath string) (string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// SaveImageFile saves a base64-encoded image to the specified path
func (sm *ScreenshotManager) SaveImageFile(filePath string, base64Data string) error {
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return fmt.Errorf("failed to decode base64 data: %w", err)
	}

	// Make a backup of the original file
	backupPath := filePath + ".bak"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		originalData, err := ioutil.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read original file: %w", err)
		}
		if err := ioutil.WriteFile(backupPath, originalData, 0644); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
	}

	// Write the new data
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}
