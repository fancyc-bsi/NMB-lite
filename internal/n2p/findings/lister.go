// Package findings manages flaws, descriptions, and screenshots
package findings

import (
	"NMB/internal/n2p/plextrac"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// FlawLister handles listing and managing flaws
type FlawLister struct {
	URLManager     interface{} // Avoid circular dependency with plextrac package
	RequestHandler interface{} // Avoid circular dependency with plextrac package
	Args           map[string]interface{}
	logger         *logrus.Logger
	flawCache      map[string]map[string]interface{}
	cacheMutex     sync.RWMutex
}

// NewFlawLister creates a new FlawLister instance
func NewFlawLister(urlManager, requestHandler interface{}, args map[string]interface{}) interface{} {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Create and return a new FlawLister
	flawLister := &FlawLister{
		URLManager:     urlManager,
		RequestHandler: requestHandler,
		Args:           args,
		logger:         logger,
		flawCache:      make(map[string]map[string]interface{}),
		cacheMutex:     sync.RWMutex{},
	}

	return flawLister
}

// GetFlawsURL returns the URL for retrieving flaws
func (f *FlawLister) getFlawsURL() string {
	// Use type assertion to call the GetFlawsURL method
	if urlManager, ok := f.URLManager.(interface{ GetFlawsURL() string }); ok {
		return urlManager.GetFlawsURL()
	}
	return ""
}

// GetUpdateFindingURL returns the URL for updating a specific finding
func (f *FlawLister) getUpdateFindingURL(flawID string) string {
	// Use type assertion to call the GetUpdateFindingURL method
	if urlManager, ok := f.URLManager.(interface{ GetUpdateFindingURL(string) string }); ok {
		return urlManager.GetUpdateFindingURL(flawID)
	}
	return ""
}

// GetDetailedFlaw retrieves detailed information about a flaw
func (f *FlawLister) GetDetailedFlaw(flawID string) map[string]interface{} {
	// First check if we have the flaw in cache
	f.cacheMutex.RLock()
	if flaw, ok := f.flawCache[flawID]; ok {
		f.cacheMutex.RUnlock()
		return flaw
	}
	f.cacheMutex.RUnlock()

	// If not in cache, fetch it
	detailURL := f.getUpdateFindingURL(flawID)
	if detailURL == "" {
		f.logger.Errorf("Failed to get URL for flaw ID: %s", flawID)
		return nil
	}

	// Use our wrapper function to make the request
	bodyBytes, statusCode, err := f.makeGetRequest(detailURL)
	if err != nil {
		f.logger.Errorf("Failed to get detailed data for flaw ID %s: %v", flawID, err)
		return nil
	}

	// Check status code
	if statusCode != 200 {
		f.logger.Errorf("Failed to get detailed data for flaw ID %s: status code %d", flawID, statusCode)
		return nil
	}

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		f.logger.Errorf("Failed to decode response for flaw ID %s: %v", flawID, err)
		return nil
	}

	// Add the flaw_id to the result explicitly
	result["flaw_id"] = flawID

	// Cache the result
	f.cacheMutex.Lock()
	f.flawCache[flawID] = result
	f.cacheMutex.Unlock()

	return result
}

func (f *FlawLister) GetExistingFlaws() []map[string]interface{} {
	url := f.getFlawsURL()
	if url == "" {
		f.logger.Error("Failed to get flaws URL")
		return nil
	}

	// Use our wrapper function to make the request
	bodyBytes, statusCode, err := f.makeGetRequest(url)
	if err != nil {
		f.logger.Errorf("Failed to list flaws: %v", err)
		return nil
	}

	// Check status code
	if statusCode != 200 {
		f.logger.Errorf("Failed to list flaws: status code %d", statusCode)
		return nil
	}

	// Parse the JSON response
	var content []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &content); err != nil {
		f.logger.Errorf("Failed to decode flaws response: %v", err)
		return nil
	}

	existingFlaws := make([]map[string]interface{}, 0)
	for _, item := range content {
		if data, ok := item["data"].([]interface{}); ok && len(data) > 0 {
			flawID := fmt.Sprintf("%v", data[0])

			// Write to file for future reference
			file, err := os.OpenFile("existing_flaws.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				file.WriteString(flawID + "\n")
				file.Close()
			}

			detailedFlaw := f.GetDetailedFlaw(flawID)
			if detailedFlaw != nil {
				// Ensure flaw_id is set
				if _, ok := detailedFlaw["flaw_id"]; !ok {
					detailedFlaw["flaw_id"] = flawID
				}
				existingFlaws = append(existingFlaws, detailedFlaw)
			}
		}
	}

	return existingFlaws
}

// ListFlaws lists all new flaws by comparing against existing ones
func (f *FlawLister) ListFlaws() []map[string]interface{} {
	existingIDs := f.loadExcludedFlawIDs()

	url := f.getFlawsURL()
	if url == "" {
		f.logger.Error("Failed to get flaws URL")
		return nil
	}

	// Use our wrapper function to make the request
	bodyBytes, statusCode, err := f.makeGetRequest(url)
	if err != nil {
		f.logger.Errorf("Failed to list flaws: %v", err)
		return nil
	}

	// Check status code
	if statusCode != 200 {
		f.logger.Errorf("Failed to list flaws: status code %d", statusCode)
		return nil
	}

	// Parse the JSON response
	var content []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &content); err != nil {
		f.logger.Errorf("Failed to decode flaws response: %v", err)
		return nil
	}

	detailedFlaws := make([]map[string]interface{}, 0)
	for _, item := range content {
		var flawID string

		// Try to extract flawID from item["data"][0] (current approach)
		if data, ok := item["data"].([]interface{}); ok && len(data) > 0 {
			flawID = fmt.Sprintf("%v", data[0])
		} else {
			// If the above fails, try other ways to extract the flaw ID
			if id, ok := item["id"]; ok {
				flawID = fmt.Sprintf("%v", id)
			} else if id, ok := item["flaw_id"]; ok {
				flawID = fmt.Sprintf("%v", id)
			} else {
				// Log the item for debugging
				f.logger.Warnf("Unable to find flaw ID in item: %+v", item)
				continue
			}
		}

		// Skip if in excluded IDs
		if _, exists := existingIDs[flawID]; exists {
			continue
		}

		detailedFlaw := f.GetDetailedFlaw(flawID)
		if detailedFlaw != nil {
			// Double-check that flaw_id is set (added by GetDetailedFlaw)
			if _, ok := detailedFlaw["flaw_id"]; !ok {
				detailedFlaw["flaw_id"] = flawID
			}
			detailedFlaws = append(detailedFlaws, detailedFlaw)
		}
	}

	return detailedFlaws
}

// makeGetRequest performs a GET request using the request handler
func (f *FlawLister) makeGetRequest(url string) ([]byte, int, error) {
	// Create a new RequestHandler directly without type assertion
	handler := plextrac.NewRequestHandler("")

	// Set the access token
	if token, ok := f.Args["access_token"].(string); ok {
		handler.SetAccessToken(token)
	}

	// Make the request
	f.logger.Debugf("Making GET request to %s", url)
	response, err := handler.Get(url, nil, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %v", err)
	}
	defer response.Body.Close()

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("failed to read response body: %v", err)
	}

	return bodyBytes, response.StatusCode, nil
}

// loadExcludedFlawIDs loads flaw IDs to exclude from the existing_flaws.txt file
func (f *FlawLister) loadExcludedFlawIDs() map[string]struct{} {
	result := make(map[string]struct{})

	data, err := os.ReadFile("existing_flaws.txt")
	if err != nil {
		f.logger.Warnf("existing_flaws.txt not found. No flaws will be excluded: %v", err)
		return result
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result[line] = struct{}{}
		}
	}

	return result
}
