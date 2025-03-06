// Package plextrac provides functionality for interacting with the Plextrac API
package plextrac

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// FileUpload represents a file to be uploaded
type FileUpload struct {
	Filename string
	File     *os.File
	MimeType string
}

// Handler manages interactions with the Plextrac API
type Handler struct {
	accessToken    string
	requestHandler *RequestHandler
	urlManager     *URLManager
	logger         Logger
}

// Logger defines the logging interface used by the Handler
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// DefaultLogger is a basic implementation of the Logger interface
type DefaultLogger struct{}

// Printf implements the Logger interface
func (l DefaultLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
}

// Println implements the Logger interface
func (l DefaultLogger) Println(v ...interface{}) {
	fmt.Println(v...)
}

// NewHandler creates a new Handler instance
func NewHandler(accessToken string, requestHandler *RequestHandler, urlManager *URLManager) *Handler {
	return &Handler{
		accessToken:    accessToken,
		requestHandler: requestHandler,
		urlManager:     urlManager,
		logger:         DefaultLogger{},
	}
}

// SetLogger sets a custom logger for the Handler
func (h *Handler) SetLogger(logger Logger) {
	h.logger = logger
}

// Authenticate verifies the authentication token
func (h *Handler) Authenticate() (bool, error) {
	return h.requestHandler.accessToken != "", nil
}

// UploadNessusFile uploads a Nessus file to Plextrac
func (h *Handler) UploadNessusFile(filePath string) error {
	url := h.urlManager.GetUploadNessusURL()

	// Check if the file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file %s not found", filePath)
		}
		return fmt.Errorf("error checking file %s: %w", filePath, err)
	}

	if fileInfo.IsDir() {
		return fmt.Errorf("%s is a directory, not a file", filePath)
	}

	// Read the file content
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Get the filename from the path
	fileName := filepath.Base(filePath)

	// Prepare the file data for upload
	files := map[string]interface{}{
		"file": map[string]interface{}{
			"filename": fileName,
			"content":  fileContent,
		},
	}

	// Make the request
	h.logger.Printf("Sending upload request to %s", url)
	response, err := h.requestHandler.Post(url, nil, nil, nil, files, nil)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}
	defer response.Body.Close()

	// Check response status
	if response.StatusCode != 200 {
		// Read the response body for better error details
		bodyBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			bodyBytes = []byte("unable to read response body")
		}
		h.logger.Printf("Upload failed with status code: %d, response: %s", response.StatusCode, string(bodyBytes))
		return fmt.Errorf("failed to upload file, server responded with status code: %d, body: %s",
			response.StatusCode, string(bodyBytes))
	}

	h.logger.Println("Nessus file successfully uploaded!")
	return nil
}

// GetFindingDetails retrieves detailed information about a specific finding
func (h *Handler) GetFindingDetails(findingID string) (map[string]interface{}, error) {
	url := h.urlManager.GetUpdateFindingURL(findingID)

	response, err := h.requestHandler.Get(url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding details: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get finding details, server responded with status code: %d",
			response.StatusCode)
	}

	var findingDetails map[string]interface{}
	if err := response.DecodeJSON(&findingDetails); err != nil {
		return nil, fmt.Errorf("failed to decode finding details: %w", err)
	}

	return findingDetails, nil
}

// UpdateFinding updates a specific finding with new data
func (h *Handler) UpdateFinding(findingID string, data map[string]interface{}) error {
	url := h.urlManager.GetUpdateFindingURL(findingID)

	response, err := h.requestHandler.Put(url, nil, nil, data)
	if err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return fmt.Errorf("failed to update finding, server responded with status code: %d",
			response.StatusCode)
	}

	return nil
}

// ListFindings returns a list of all findings
func (h *Handler) ListFindings() ([]map[string]interface{}, error) {
	url := h.urlManager.GetFlawsURL()

	response, err := h.requestHandler.Get(url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("failed to list findings, server responded with status code: %d",
			response.StatusCode)
	}

	var findings []map[string]interface{}
	if err := response.DecodeJSON(&findings); err != nil {
		return nil, fmt.Errorf("failed to decode findings list: %w", err)
	}

	return findings, nil
}

// ExecuteGraphQLQuery executes a GraphQL query against the Plextrac API
func (h *Handler) ExecuteGraphQLQuery(operationName string, variables map[string]interface{}, query string) (map[string]interface{}, error) {
	url := h.urlManager.GetGraphqlURL()

	payload := map[string]interface{}{
		"operationName": operationName,
		"variables":     variables,
		"query":         query,
	}

	response, err := h.requestHandler.Post(url, nil, nil, payload, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute GraphQL query: %w", err)
	}
	defer response.Body.Close()

	var result map[string]interface{}
	if err := response.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("failed to decode GraphQL response: %w", err)
	}

	// Check for GraphQL errors
	if errors, ok := result["errors"].([]interface{}); ok && len(errors) > 0 {
		return result, fmt.Errorf("GraphQL query returned errors")
	}

	return result, nil
}
