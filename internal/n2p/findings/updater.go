package findings

import (
	"NMB/internal/n2p/plextrac"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// FlawUpdater handles updating flaws with screenshots and custom fields
type FlawUpdater struct {
	Converter             interface{}
	Args                  map[string]interface{}
	RequestHandler        interface{}
	URLManager            interface{}
	ProcessedFlaws        map[string]bool
	CustomFields          map[string]string
	FlawCache             map[string]map[string]interface{}
	MD5Pattern            *regexp.Regexp
	PluginNamePattern     *regexp.Regexp
	URLPattern            *regexp.Regexp
	HTMLTagPattern        *regexp.Regexp
	FlawLister            *FlawLister
	Mode                  string
	Logger                *logrus.Logger
	ProcessedFindingsFile string
}

// NewFlawUpdater creates a new FlawUpdater instance
func NewFlawUpdater(converter, args, requestHandler, urlManager interface{}) *FlawUpdater {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Get organized descriptions from converter if available
	var customFields map[string]string
	if c, ok := converter.(interface{ GetOrganizedDescriptions() map[string]string }); ok {
		customFields = c.GetOrganizedDescriptions()
	} else {
		customFields = make(map[string]string)
	}

	// Get mode from converter or default
	var mode string
	if c, ok := converter.(interface{ GetMode() string }); ok {
		mode = c.GetMode()
	} else {
		modeMap := map[string]string{
			"internal":     "internal",
			"external":     "external",
			"web":          "web",
			"surveillance": "surveillance",
			"mobile":       "mobile",
		}
		if argScope, ok := args.(map[string]interface{})["scope"].(string); ok {
			mode = modeMap[argScope]
		}
		if mode == "" {
			mode = "internal" // Default
		}
	}

	return &FlawUpdater{
		Converter:             converter,
		Args:                  args.(map[string]interface{}),
		RequestHandler:        requestHandler,
		URLManager:            urlManager,
		ProcessedFlaws:        make(map[string]bool),
		CustomFields:          customFields,
		FlawCache:             make(map[string]map[string]interface{}),
		MD5Pattern:            regexp.MustCompile(`[a-f0-9]{32}`),
		PluginNamePattern:     regexp.MustCompile(`<b>(.*?)(?:\s*\(severity:.*?\))?</b>`),
		URLPattern:            regexp.MustCompile(`(https?://)`),
		HTMLTagPattern:        regexp.MustCompile(`<.*?>`),
		FlawLister:            NewFlawLister(urlManager, requestHandler, args.(map[string]interface{})).(*FlawLister),
		Mode:                  mode,
		Logger:                logger,
		ProcessedFindingsFile: "_processed_findings.json",
	}
}

// GetTitlePrefix returns the appropriate title prefix based on the mode
func (u *FlawUpdater) GetTitlePrefix() string {
	prefixMap := map[string]string{
		"external":     "(External) ",
		"web":          "(Web) ",
		"surveillance": "(Surveillance) ",
		"mobile":       "(Mobile) ",
		"internal":     "",
	}

	prefix, ok := prefixMap[u.Mode]
	if !ok {
		return ""
	}
	return prefix
}

// LoadProcessedFindings loads the list of processed findings from a file
func (u *FlawUpdater) LoadProcessedFindings() map[string]interface{} {
	if _, err := os.Stat(u.ProcessedFindingsFile); os.IsNotExist(err) {
		return make(map[string]interface{})
	}

	data, err := ioutil.ReadFile(u.ProcessedFindingsFile)
	if err != nil {
		u.Logger.Warnf("Failed to read processed findings file: %v", err)
		return make(map[string]interface{})
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		u.Logger.Warnf("Failed to parse processed findings file: %v", err)
		return make(map[string]interface{})
	}

	return result
}

// SaveProcessedFindings saves the list of processed findings to a file
func (u *FlawUpdater) SaveProcessedFindings(data map[string]interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal processed findings: %v", err)
	}

	if err := ioutil.WriteFile(u.ProcessedFindingsFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write processed findings file: %v", err)
	}

	return nil
}

// FlawUpdateEngine updates findings with screenshots and custom fields
func (u *FlawUpdater) FlawUpdateEngine() error {
	flaws := u.FlawLister.ListFlaws()
	u.Logger.Infof("Found %d flaws to process", len(flaws))

	// Create a map of custom fields for each flaw
	customFieldsForFlaw := make(map[string]string)

	// Process flaws for screenshots and custom fields
	for _, flaw := range flaws {
		// Get the flaw ID and normalize it
		flawIDRaw, ok := flaw["flaw_id"]
		if !ok {
			u.Logger.Warnf("Flaw is missing flaw_id field: %+v", flaw)
			continue
		}

		// Normalize the flaw ID
		flawID := u.NormalizeID(flawIDRaw)
		u.Logger.Debugf("Processing flaw with normalized ID: %s", flawID)

		// Process references to find MD5 hashes for screenshots
		references, ok := flaw["references"].(string)
		if ok && references != "" {
			u.Logger.Debugf("Processing references for flaw ID %s", flawID)
			u.ProcessFlawReferences(flawID, references)
		} else {
			u.Logger.Debugf("No references found for flaw ID %s", flawID)
		}

		// Get the flaw title and try to match it to a category in our config
		title, _ := flaw["title"].(string)
		if title != "" {
			// First try direct match by flaw ID
			if description, ok := u.CustomFields[flawID]; ok && description != "" {
				u.Logger.Infof("Found direct match by flaw ID %s", flawID)
				customFieldsForFlaw[flawID] = description
				continue
			}

			// If no direct match by ID, try to match by title
			category, description := u.MatchTitleToCategory(title)
			if description != "" {
				u.Logger.Infof("Found matching category '%s' for flaw ID %s with title '%s'",
					category, flawID, title)
				customFieldsForFlaw[flawID] = description
			} else {
				u.Logger.Warnf("No custom field match for flaw ID %s with title '%s'", flawID, title)
			}
		}
	}

	// Log how many custom fields we found
	u.Logger.Infof("Found custom fields for %d flaws", len(customFieldsForFlaw))

	// Make sure all flaws are in the processed set so we update all of them
	if len(u.ProcessedFlaws) == 0 {
		u.AddMissingFlaws(flaws)
	}

	u.Logger.Infof("Total flaws to update: %d", len(u.ProcessedFlaws))

	// Update all flaws with custom fields
	errorCount := 0
	successCount := 0

	for flawID := range u.ProcessedFlaws {
		description, ok := customFieldsForFlaw[flawID]
		if !ok {
			u.Logger.Debugf("No custom field found for flaw ID %s", flawID)
			continue
		}

		if err := u.UpdateFindingWithCustomField(flawID, description); err != nil {
			u.Logger.Warnf("Failed to update custom field for flaw ID %s: %v", flawID, err)
			errorCount++
		} else {
			u.Logger.Infof("Successfully updated custom field for flaw ID %s", flawID)
			successCount++
		}
	}

	u.Logger.Infof("Custom field updates: %d successful, %d failed", successCount, errorCount)

	// Clean up MD5 hashes from references
	u.Logger.Debug("Clearing MD5 hashes from references")
	u.ClearMD5HashesFromReferences(flaws)

	return nil
}

// ProcessFlawReferences processes references to find MD5 hashes
func (u *FlawUpdater) ProcessFlawReferences(flawID, references string) {
	md5Hashes := u.MD5Pattern.FindAllString(references, -1)
	u.Logger.Debugf("Found %d MD5 hashes in references for flaw ID %s", len(md5Hashes), flawID)

	for _, md5Hash := range md5Hashes {
		u.Logger.Debugf("Processing MD5 hash %s for flaw ID %s", md5Hash, flawID)
		u.HandleMD5HashedScreenshot(flawID, md5Hash)
	}
}

// HandleMD5HashedScreenshot handles the screenshot associated with an MD5 hash for a given flaw.
func (u *FlawUpdater) HandleMD5HashedScreenshot(flawID string, md5Hash string) {
	screenshotDir, _ := u.Args["screenshot_dir"].(string)
	if screenshotDir == "" {
		u.Logger.Debug("Screenshot directory is not provided. Skipping screenshot handling.")
		return
	}

	screenshotPath := filepath.Join(screenshotDir, md5Hash+".png")
	if _, err := os.Stat(screenshotPath); err == nil {
		// Read file as bytes instead of using a file handle
		fileData, err := ioutil.ReadFile(screenshotPath)
		if err != nil {
			u.Logger.Errorf("Failed to read screenshot file: %v", err)
			return
		}

		// Create a new buffer and multipart writer
		var requestBody bytes.Buffer
		writer := multipart.NewWriter(&requestBody)

		// Create form file field with explicit png mime type
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "file", md5Hash+".png"))
		h.Set("Content-Type", "image/png")

		part, err := writer.CreatePart(h)
		if err != nil {
			u.Logger.Errorf("Failed to create form part: %v", err)
			return
		}

		// Write file data to the form part
		if _, err := part.Write(fileData); err != nil {
			u.Logger.Errorf("Failed to write file data: %v", err)
			return
		}

		// Close the writer to finalize the form
		writer.Close()

		// Get the upload URL
		var url string
		if urlManager, ok := u.URLManager.(interface{ GetUploadScreenshotURL() string }); ok {
			url = urlManager.GetUploadScreenshotURL()
		}
		if url == "" {
			u.Logger.Error("Failed to get upload screenshot URL")
			return
		}

		// Create the HTTP request
		req, err := http.NewRequest("POST", url, &requestBody)
		if err != nil {
			u.Logger.Errorf("Failed to create HTTP request: %v", err)
			return
		}

		// Set the content type with boundary
		req.Header.Set("Content-Type", writer.FormDataContentType())

		// Add authorization header
		if token, ok := u.Args["access_token"].(string); ok {
			req.Header.Set("Authorization", token)
		}

		// Create HTTP client that skips TLS verification
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		// Execute the request
		resp, err := client.Do(req)
		if err != nil {
			u.Logger.Errorf("Failed to send HTTP request: %v", err)
			return
		}
		defer resp.Body.Close()

		// Read response body
		bodyBytes, _ := ioutil.ReadAll(resp.Body)

		// Check status code
		if resp.StatusCode != 200 {
			u.Logger.Errorf("Screenshot upload failed with status code %d: %s", resp.StatusCode, string(bodyBytes))
			return
		}

		// Parse response JSON
		var result map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &result); err != nil {
			u.Logger.Errorf("Failed to parse response JSON: %v", err)
			return
		}

		// Extract exhibit ID
		exhibitID, ok := result["id"].(string)
		if !ok {
			u.Logger.Errorf("Exhibit ID not found in response: %v", result)
			return
		}

		// Process the successful upload
		u.ProcessSuccessfulUpload(flawID, exhibitID, md5Hash)
	} else {
		u.ProcessMissingScreenshot(flawID, md5Hash)
	}
}

// Helper method to get upload screenshot URL
func (u *FlawUpdater) GetUploadScreenshotURL() string {
	if urlManager, ok := u.URLManager.(interface{ GetUploadScreenshotURL() string }); ok {
		return urlManager.GetUploadScreenshotURL()
	}
	return ""
}

// makeGetRequest performs a GET request using the request handler
func (u *FlawUpdater) makeGetRequest(url string) ([]byte, int, error) {
	// Create a new RequestHandler using the imported plextrac package
	handler := plextrac.NewRequestHandler("")

	// Set the access token
	if token, ok := u.Args["access_token"].(string); ok {
		handler.SetAccessToken(token)
	}

	// Make the request
	u.Logger.Debugf("Making GET request to %s", url)
	response, err := handler.Get(url, nil, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %v", err)
	}

	// Process the response - the response is already a *plextrac.Response
	respObj := response

	bodyBytes := respObj.GetBody()
	statusCode := respObj.GetStatusCode()

	return bodyBytes, statusCode, nil
}

// makePostRequest performs a POST request using the request handler
// func (u *FlawUpdater) makePostRequest(url string, jsonData map[string]interface{}) ([]byte, int, error) {
// 	// Create a new RequestHandler using the imported plextrac package
// 	handler := plextrac.NewRequestHandler("")

// 	// Set the access token
// 	if token, ok := u.Args["access_token"].(string); ok {
// 		handler.SetAccessToken(token)
// 	}

// 	// Make the request
// 	u.Logger.Debugf("Making POST request to %s", url)
// 	response, err := handler.Post(url, nil, nil, jsonData, nil, nil)
// 	if err != nil {
// 		return nil, 0, fmt.Errorf("request failed: %v", err)
// 	}

// 	// Process the response - the response is already a *plextrac.Response
// 	respObj := response

// 	bodyBytes := respObj.GetBody()
// 	statusCode := respObj.GetStatusCode()

// 	return bodyBytes, statusCode, nil
// }

// makePostFileRequest performs a POST request with file upload using the request handler
func (u *FlawUpdater) makePostFileRequest(url string, files map[string]interface{}) ([]byte, int, error) {
	// Create a new RequestHandler directly without type assertion
	handler := plextrac.NewRequestHandler("")

	// Set the access token
	if token, ok := u.Args["access_token"].(string); ok {
		handler.SetAccessToken(token)
	}

	// Add explicit Content-Type header for PNG files
	headers := map[string]string{
		"Accept": "*/*",
	}

	// Make the request
	u.Logger.Debugf("Making POST file request to %s", url)
	response, err := handler.Post(url, headers, nil, nil, files, nil)
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

// UploadScreenshotToFinding uploads a screenshot to a finding
func (u *FlawUpdater) UploadScreenshotToFinding(screenshotBytes map[string]interface{}) (string, error) {
	// Get URL for uploading screenshots
	urlManager, ok := u.URLManager.(interface{ GetUploadScreenshotURL() string })
	if !ok {
		u.Logger.Error("URL manager does not implement GetUploadScreenshotURL method")
		return "", fmt.Errorf("URL manager does not implement GetUploadScreenshotURL method")
	}

	url := urlManager.GetUploadScreenshotURL()
	if url == "" {
		u.Logger.Error("Failed to get upload screenshot URL")
		return "", fmt.Errorf("failed to get upload screenshot URL")
	}

	// Use our wrapper function instead of directly accessing RequestHandler
	u.Logger.Debugf("Sending screenshot upload request to %s", url)
	bodyBytes, statusCode, err := u.makePostFileRequest(url, screenshotBytes)
	if err != nil {
		u.Logger.Errorf("Failed to upload screenshot: %v", err)
		return "", fmt.Errorf("failed to upload screenshot: %v", err)
	}

	// Check status code
	if statusCode != 200 {
		u.Logger.Errorf("Screenshot upload failed with status code %d: %s", statusCode, string(bodyBytes))
		return "", fmt.Errorf("screenshot upload failed with status code %d", statusCode)
	}

	// Log the response for debugging
	u.Logger.Debugf("Screenshot upload response: %s", string(bodyBytes))

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		u.Logger.Errorf("Failed to parse response JSON: %v", err)
		return "", fmt.Errorf("failed to parse response JSON: %v", err)
	}

	// Extract the exhibit ID
	exhibitID, ok := result["id"].(string)
	if !ok {
		u.Logger.Errorf("Exhibit ID not found in response: %+v", result)
		return "", fmt.Errorf("exhibit ID not found in response")
	}

	u.Logger.Infof("Successfully uploaded screenshot, received exhibit ID: %s", exhibitID)
	return exhibitID, nil
}

// ProcessSuccessfulUpload processes a successful screenshot upload
func (u *FlawUpdater) ProcessSuccessfulUpload(flawID, exhibitID, md5Hash string) {
	// Normalize flaw ID if it's in scientific notation
	var normalizedFlawID string
	if strings.Contains(flawID, "e+") {
		// Parse scientific notation to float
		floatVal, err := strconv.ParseFloat(flawID, 64)
		if err != nil {
			u.Logger.Errorf("Failed to parse flaw ID '%s' as float: %v", flawID, err)
			normalizedFlawID = flawID // Fall back to original ID on error
		} else {
			// Convert to integer form
			normalizedFlawID = fmt.Sprintf("%.0f", floatVal)
			u.Logger.Debugf("Converted scientific notation ID '%s' to '%s'", flawID, normalizedFlawID)
		}
	} else {
		normalizedFlawID = flawID
	}

	// Extract the caption (plugin name) for the given MD5 hash
	caption := u.GetCaptionFromMD5(md5Hash)

	u.Logger.Infof("Uploaded screenshot with MD5 %s for flaw ID %s and received exhibit ID %s", md5Hash, normalizedFlawID, exhibitID)
	u.Logger.Infof("Caption for this screenshot: %s", caption)

	// Update the finding with the new exhibit
	if err := u.UpdateFinding(normalizedFlawID, exhibitID, caption); err != nil {
		u.Logger.Errorf("Failed to update finding with screenshot: %v", err)
	} else {
		u.Logger.Infof("Successfully updated finding %s with screenshot (exhibit ID: %s)", normalizedFlawID, exhibitID)
	}

	// Store the normalized flaw ID
	u.ProcessedFlaws[normalizedFlawID] = true
}
func (u *FlawUpdater) GetCaptionFromMD5(md5Hash string) string {
	u.Logger.Debugf("Looking for caption for MD5 hash: %s", md5Hash)

	// This is the critical fix - check flaw titles first
	flaws := u.FlawLister.ListFlaws()
	for _, flaw := range flaws {
		if title, ok := flaw["title"].(string); ok {
			// Strip prefix
			cleanTitle := u.StripPrefix(title)

			// CRITICAL: Use the EXACT same transformation as in converter.go
			// We need to lowercase to match how the hash was originally created
			lowercaseTitle := strings.ToLower(cleanTitle)

			// Log for debugging
			u.Logger.Debugf("Testing title '%s' -> lowercase '%s'", cleanTitle, lowercaseTitle)

			// Generate hash exactly as it's done in converter.go
			hash := md5.Sum([]byte(lowercaseTitle))
			generatedHash := hex.EncodeToString(hash[:])

			u.Logger.Debugf("Generated hash: %s", generatedHash)

			if generatedHash == md5Hash {
				u.Logger.Infof("Found matching title '%s' for hash %s", cleanTitle, md5Hash)
				return cleanTitle
			}
		}
	}

	// Fall back to checking plugin names in custom fields
	for _, customField := range u.CustomFields {
		matches := u.PluginNamePattern.FindAllStringSubmatch(customField, -1)
		for _, match := range matches {
			if len(match) > 1 {
				pluginName := strings.TrimSpace(match[1])
				lowercasePluginName := strings.ToLower(pluginName)

				hash := md5.Sum([]byte(lowercasePluginName))
				generatedHash := hex.EncodeToString(hash[:])

				if generatedHash == md5Hash {
					u.Logger.Infof("Found matching plugin name '%s' for hash %s", pluginName, md5Hash)
					return pluginName
				}
			}
		}
	}

	u.Logger.Warnf("No match found for hash %s", md5Hash)
	return "Screenshot " + md5Hash
}

// ProcessMissingScreenshot handles cases where a screenshot is missing
func (u *FlawUpdater) ProcessMissingScreenshot(flawID, md5Hash string) {
	u.Logger.Debugf("No screenshot found for MD5 hash '%s' related to flaw ID %s", md5Hash, flawID)
	u.ProcessedFlaws[flawID] = true
}

// GetExistingFieldsForFlaw retrieves existing fields for a flaw, handling scientific notation IDs
func (u *FlawUpdater) GetExistingFieldsForFlaw(flawID string) ([]map[string]interface{}, string) {
	// Convert scientific notation to regular integer if needed
	u.Logger.Info("THIS IS THE IMPORTANT PART !!!!!!!!!!!")
	var normalizedFlawID string
	if strings.Contains(flawID, "e+") {
		// Parse scientific notation to float
		floatVal, err := strconv.ParseFloat(flawID, 64)
		if err != nil {
			u.Logger.Errorf("Failed to parse flaw ID '%s' as float: %v", flawID, err)
			return nil, ""
		}
		// Convert to integer form
		normalizedFlawID = fmt.Sprintf("%.0f", floatVal)
		u.Logger.Debugf("Converted scientific notation ID '%s' to '%s'", flawID, normalizedFlawID)
	} else {
		normalizedFlawID = flawID
	}

	// Check cache first using normalized ID
	if flaw, ok := u.FlawCache[normalizedFlawID]; ok {
		fields, _ := flaw["fields"].([]map[string]interface{})
		title, _ := flaw["title"].(string)
		u.Logger.Debugf("Using cached fields for flaw ID %s", normalizedFlawID)
		return fields, title
	}

	// Log args for debugging
	u.Logger.Debugf("Args: %+v", u.Args)

	// Extract target_plextrac, client_id, and report_id
	targetPlextrac, ok := u.Args["target_plextrac"].(string)
	if !ok {
		u.Logger.Errorf("target_plextrac is missing or not a string: %v", u.Args["target_plextrac"])
		return nil, ""
	}

	clientID, ok := u.Args["client_id"].(string)
	if !ok {
		u.Logger.Errorf("client_id is missing or not a string: %v", u.Args["client_id"])
		return nil, ""
	}

	reportID, ok := u.Args["report_id"].(string)
	if !ok {
		u.Logger.Errorf("report_id is missing or not a string: %v", u.Args["report_id"])
		return nil, ""
	}

	// Get access token
	accessToken, ok := u.Args["access_token"].(string)
	if !ok {
		u.Logger.Errorf("access_token is missing or not a string: %v", u.Args["access_token"])
		return nil, ""
	}

	// Construct URL manually
	url := fmt.Sprintf("https://%s.kevlar.bulletproofsi.net/api/v1/client/%s/report/%s/flaw/%s",
		targetPlextrac, clientID, reportID, normalizedFlawID)

	u.Logger.Infof("Constructed URL: %s", url)
	u.Logger.Infof("Using access token: %s...", accessToken[:10]+"...")

	// Create a direct HTTP request to avoid type assertion issues
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		u.Logger.Errorf("Failed to create request: %v", err)
		return nil, ""
	}

	// Add authorization header
	req.Header.Set("Authorization", accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Create HTTP client that skips TLS verification
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Execute the request
	u.Logger.Infof("Sending GET request to %s", url)
	resp, err := client.Do(req)
	if err != nil {
		u.Logger.Errorf("Failed to execute request: %v", err)
		return nil, ""
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		u.Logger.Errorf("Failed to read response body: %v", err)
		return nil, ""
	}

	// Log response status and headers
	u.Logger.Infof("Response status: %s", resp.Status)
	u.Logger.Infof("Response headers: %+v", resp.Header)

	// Check status code
	if resp.StatusCode != 200 {
		u.Logger.Errorf("Failed to fetch fields for flaw ID %s: status code %d", normalizedFlawID, resp.StatusCode)
		if len(bodyBytes) > 0 {
			u.Logger.Errorf("Response body: %s", string(bodyBytes))
		}
		return nil, ""
	}

	// Log response body for debugging (limited to 1000 chars to avoid log flooding)
	responseStr := string(bodyBytes)
	if len(responseStr) > 1000 {
		u.Logger.Debugf("Response body (truncated): %s...", responseStr[:1000])
	} else {
		u.Logger.Debugf("Response body: %s", responseStr)
	}

	// Parse the response
	var content map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &content); err != nil {
		u.Logger.Errorf("Failed to decode fields response for flaw ID %s: %v", normalizedFlawID, err)
		return nil, ""
	}

	// Cache the result using normalized ID
	u.FlawCache[normalizedFlawID] = content

	// Log the content structure
	keys := make([]string, 0, len(content))
	for k := range content {
		keys = append(keys, k)
	}
	u.Logger.Debugf("Content keys: %v", keys)

	// Extract fields and title
	var title string
	if t, ok := content["title"]; ok {
		title, _ = t.(string)
	}

	fieldsRaw, ok := content["fields"]
	if !ok {
		u.Logger.Debugf("No 'fields' key found in response for flaw ID %s", normalizedFlawID)
		return []map[string]interface{}{}, title
	}

	// Log the fields type
	u.Logger.Debugf("Fields type: %T", fieldsRaw)

	// Handle different field formats
	var fields []map[string]interface{}
	switch f := fieldsRaw.(type) {
	case []interface{}:
		// Convert []interface{} to []map[string]interface{}
		u.Logger.Debugf("Fields is []interface{} with %d items", len(f))
		fields = make([]map[string]interface{}, 0, len(f))
		for _, item := range f {
			if itemMap, ok := item.(map[string]interface{}); ok {
				fields = append(fields, itemMap)
			}
		}
	case []map[string]interface{}:
		// Already in the right format
		u.Logger.Debugf("Fields is already []map[string]interface{} with %d items", len(f))
		fields = f
	case map[string]interface{}:
		// Convert map to slice of maps
		u.Logger.Debugf("Fields is map[string]interface{} with %d items", len(f))
		fields = make([]map[string]interface{}, 0, len(f))
		for key, value := range f {
			if valueMap, ok := value.(map[string]interface{}); ok {
				valueMap["key"] = key
				fields = append(fields, valueMap)
			}
		}
	default:
		u.Logger.Warnf("Unexpected fields type %T for flaw ID %s", fieldsRaw, normalizedFlawID)
		if fieldsRaw == nil {
			u.Logger.Warnf("Fields is nil")
		}
		fields = []map[string]interface{}{}
	}

	u.Logger.Debugf("Successfully fetched fields for flaw ID %s (title: '%s')", normalizedFlawID, title)
	u.Logger.Debugf("Returning %d fields", len(fields))

	return fields, title
}

// ProcessUpdateFindingWithCustomField processes and updates custom fields
func (u *FlawUpdater) ProcessUpdateFindingWithCustomField(customFieldsForFlaw map[string]string, flaws []map[string]interface{}) {
	if len(u.ProcessedFlaws) == 0 {
		u.AddMissingFlaws(flaws)
	}

	for flawID := range u.ProcessedFlaws {
		description, ok := customFieldsForFlaw[flawID]
		if !ok {
			description = ""
		}
		u.UpdateFindingWithCustomField(flawID, description)
	}
}

// NormalizeID converts a flaw ID from any format (string, float, scientific notation) to a standard integer string
func (u *FlawUpdater) NormalizeID(rawID interface{}) string {
	switch id := rawID.(type) {
	case string:
		// If it's a string, check if it's in scientific notation
		if strings.Contains(id, "e+") || strings.Contains(id, "E+") {
			floatVal, err := strconv.ParseFloat(id, 64)
			if err != nil {
				u.Logger.Warnf("Failed to parse scientific notation ID '%s': %v", id, err)
				return id // Return original on error
			}
			normalizedID := fmt.Sprintf("%.0f", floatVal)
			u.Logger.Debugf("Normalized scientific notation ID '%s' to '%s'", id, normalizedID)
			return normalizedID
		}
		return id

	case float64:
		// If it's a float, convert to integer string
		normalizedID := fmt.Sprintf("%.0f", id)
		u.Logger.Debugf("Normalized float ID %.6f to '%s'", id, normalizedID)
		return normalizedID

	case int:
		// If it's an int, convert to string
		return fmt.Sprintf("%d", id)

	case int64:
		// If it's an int64, convert to string
		return fmt.Sprintf("%d", id)

	default:
		// For any other type, convert to string using fmt.Sprintf
		normalizedID := fmt.Sprintf("%v", rawID)
		u.Logger.Debugf("Normalized ID of type %T to '%s'", rawID, normalizedID)
		return normalizedID
	}
}

// AddMissingFlaws adds flaws that haven't been processed yet, normalizing IDs
func (u *FlawUpdater) AddMissingFlaws(flaws []map[string]interface{}) {
	for _, flaw := range flaws {
		if flawID, ok := flaw["flaw_id"].(string); ok {
			// Normalize the flaw ID if it's in scientific notation
			var normalizedFlawID string
			if strings.Contains(flawID, "e+") {
				// Parse scientific notation to float
				floatVal, err := strconv.ParseFloat(flawID, 64)
				if err != nil {
					u.Logger.Errorf("Failed to parse flaw ID '%s' as float: %v", flawID, err)
					normalizedFlawID = flawID // Fall back to original ID on error
				} else {
					// Convert to integer form
					normalizedFlawID = fmt.Sprintf("%.0f", floatVal)
					u.Logger.Debugf("Converted scientific notation ID '%s' to '%s'", flawID, normalizedFlawID)
				}
			} else {
				normalizedFlawID = flawID
			}

			u.ProcessedFlaws[normalizedFlawID] = true
			u.Logger.Debugf("Added flaw ID %s to processed flaws", normalizedFlawID)
		} else if flawIDRaw, ok := flaw["flaw_id"]; ok {
			// Handle non-string flaw IDs (like float64 or int)
			normalizedFlawID := fmt.Sprintf("%.0f", flawIDRaw)
			u.ProcessedFlaws[normalizedFlawID] = true
			u.Logger.Debugf("Added non-string flaw ID %v (normalized to %s) to processed flaws",
				flawIDRaw, normalizedFlawID)
		}
	}
}

// UpdateFindingWithCustomField updates a finding's custom field using the exact query format
func (u *FlawUpdater) UpdateFindingWithCustomField(flawID string, description string) error {
	const (
		MergedAssetsKey   = "merged_assets"
		MergedAssetsLabel = "Merged assets"
	)

	// Skip empty descriptions
	if description == "" {
		u.Logger.Debugf("Skipping empty description for flaw ID %s", flawID)
		return nil
	}

	u.Logger.Infof("Starting direct field update for flaw ID %s", flawID)
	u.Logger.Infof("Description length: %d bytes", len(description))

	// Create field array with just our field
	fields := []map[string]interface{}{
		{
			"key":   MergedAssetsKey,
			"label": MergedAssetsLabel,
			"value": description,
		},
	}

	// Get required arguments
	targetPlextrac, ok := u.Args["target_plextrac"].(string)
	if !ok {
		u.Logger.Errorf("target_plextrac is missing or not a string: %v", u.Args["target_plextrac"])
		return fmt.Errorf("target_plextrac is missing or not a string")
	}

	// Convert client_id to int
	clientIDRaw := u.Args["client_id"]
	clientIDStr := fmt.Sprintf("%v", clientIDRaw)
	clientID, err := strconv.Atoi(clientIDStr)
	if err != nil {
		u.Logger.Errorf("Failed to convert client_id '%v' to int: %v", clientIDRaw, err)
		return fmt.Errorf("failed to convert client_id to int: %v", err)
	}
	u.Logger.Infof("Using client_id: %s (as int: %d)", clientIDStr, clientID)

	// Convert report_id to int
	reportIDRaw := u.Args["report_id"]
	reportIDStr := fmt.Sprintf("%v", reportIDRaw)
	reportID, err := strconv.Atoi(reportIDStr)
	if err != nil {
		u.Logger.Errorf("Failed to convert report_id '%v' to int: %v", reportIDRaw, err)
		return fmt.Errorf("failed to convert report_id to int: %v", err)
	}
	u.Logger.Infof("Using report_id: %s (as int: %d)", reportIDStr, reportID)

	// Convert flaw_id to float
	var flawIDFloat float64
	if strings.Contains(flawID, "e+") || strings.Contains(flawID, "E+") {
		// Handle scientific notation
		flawIDFloat, err = strconv.ParseFloat(flawID, 64)
		if err != nil {
			u.Logger.Errorf("Failed to parse scientific notation flaw_id '%s' as float: %v", flawID, err)
			return fmt.Errorf("failed to parse flaw_id as float: %v", err)
		}
	} else {
		// Handle regular number
		flawIDInt, err := strconv.Atoi(flawID)
		if err != nil {
			// Try parsing as float if int parsing fails
			flawIDFloat, err = strconv.ParseFloat(flawID, 64)
			if err != nil {
				u.Logger.Errorf("Failed to convert flaw_id '%s' to float: %v", flawID, err)
				return fmt.Errorf("failed to convert flaw_id to float: %v", err)
			}
		} else {
			flawIDFloat = float64(flawIDInt)
		}
	}

	// Prepare the GraphQL variables with correct data types
	variables := map[string]interface{}{
		"clientId":  clientID,
		"reportId":  reportID,
		"findingId": flawIDFloat,
		"data": map[string]interface{}{
			"fields": fields,
		},
	}

	// Log variables for debugging
	varsJSON, _ := json.MarshalIndent(variables, "", "  ")
	u.Logger.Infof("Variables for GraphQL: %s", string(varsJSON))

	// Construct the GraphQL URL directly
	url := fmt.Sprintf("https://%s.kevlar.bulletproofsi.net/graphql", targetPlextrac)
	u.Logger.Infof("GraphQL URL: %s", url)

	// CRITICAL FIX: Use the EXACT query format from the example
	query := `mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {
  findingUpdate(
    clientId: $clientId
    data: $data
    findingId: $findingId
    reportId: $reportId
  ) {
    ... on FindingUpdateSuccess {
      finding {
        ...FindingFragment
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment FindingFragment on Finding {
  assignedTo
  closedAt
  createdAt
  code_samples {
    caption
    code
    id
    __typename
  }
  common_identifiers {
    CVE {
      name
      id
      year
      link
      __typename
    }
    CWE {
      name
      id
      link
      __typename
    }
    __typename
  }
  description
  exhibits {
    assets {
      asset
      id
      __typename
    }
    caption
    exhibitID
    index
    type
    __typename
  }
  fields {
    key
    label
    value
    __typename
  }
  flaw_id
  includeEvidence
  recommendations
  references
  scores
  selectedScore
  severity
  source
  status
  subStatus
  tags
  title
  visibility
  calculated_severity
  risk_score {
    CVSS3_1 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS3 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS2 {
      overall
      vector
      subScore {
        base
        temporal
        __typename
      }
      __typename
    }
    CWSS {
      overall
      vector
      subScore {
        base
        environmental
        attackSurface
        __typename
      }
      __typename
    }
    __typename
  }
  hackerOneData {
    bountyAmount
    programId
    programName
    remoteId
    __typename
  }
  snykData {
    issueType
    pkgName
    issueUrl
    identifiers {
      CVE
      CWE
      __typename
    }
    exploitMaturity
    patches
    nearestFixedInVersion
    isMaliciousPackage
    violatedPolicyPublicId
    introducedThrough
    fixInfo {
      isUpgradable
      isPinnable
      isPatchable
      isFixable
      isPartiallyFixable
      nearestFixedInVersion
      __typename
    }
    __typename
  }
  edgescanData {
    id
    portal_url
    details {
      html
      id
      orginal_detail_hash
      parameter_name
      parameter_type
      port
      protocol
      screenshot_urls {
        file
        id
        medium_thumb
        small_thumb
        __typename
      }
      src
      type
      __typename
    }
    __typename
  }
  __typename
}`

	payload := map[string]interface{}{
		"operationName": "FindingUpdate",
		"variables":     variables,
		"query":         query,
	}

	// Convert payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		u.Logger.Errorf("Failed to marshal payload: %v", err)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create a direct HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		u.Logger.Errorf("Failed to create request: %v", err)
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if token, ok := u.Args["access_token"].(string); ok {
		req.Header.Set("Authorization", token)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Execute the request
	u.Logger.Infof("Sending GraphQL request to %s", url)
	resp, err := client.Do(req)
	if err != nil {
		u.Logger.Errorf("Failed to execute request: %v", err)
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		u.Logger.Errorf("Failed to read response: %v", err)
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Log response status and body
	u.Logger.Infof("Response status: %s", resp.Status)
	u.Logger.Infof("Response body: %s", string(body))

	// Check status code
	if resp.StatusCode != 200 {
		u.Logger.Errorf("Request failed with status %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		u.Logger.Errorf("Failed to parse response: %v", err)
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Check for GraphQL errors
	if errors, ok := result["errors"].([]interface{}); ok && len(errors) > 0 {
		u.Logger.Errorf("GraphQL returned errors: %v", errors)
		return fmt.Errorf("GraphQL returned errors: %v", errors)
	}

	u.Logger.Infof("Successfully updated merged assets for flaw ID %s", flawID)
	return nil
}

// ExecuteExtendedGraphQLQuery executes a GraphQL query with better error handling and logging
func (u *FlawUpdater) ExecuteExtendedGraphQLQuery(variables map[string]interface{}) error {
	// Get GraphQL URL
	var url string
	if urlManager, ok := u.URLManager.(interface{ GetGraphqlURL() string }); ok {
		url = urlManager.GetGraphqlURL()
	}
	if url == "" {
		return fmt.Errorf("failed to get GraphQL URL")
	}

	// Create the full mutation query with all required fragments
	query := `
    mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {
            clientId: $clientId
            data: $data
            findingId: $findingId
            reportId: $reportId
        ) {
            ... on FindingUpdateSuccess {
                finding {
                    fields {
                        key
                        label
                        value
                        __typename
                    }
                    exhibits {
                        caption
                        exhibitID
                        index
                        type
                        __typename
                    }
                    flaw_id
                    __typename
                }
                __typename
            }
            ... on FindingUpdateFailure {
                error
                __typename
            }
            __typename
        }
    }
    `

	// Create the full payload
	payload := map[string]interface{}{
		"operationName": "FindingUpdate",
		"variables":     variables,
		"query":         query,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal GraphQL payload: %v", err)
	}

	// Create direct HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create GraphQL request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if token, ok := u.Args["access_token"].(string); ok {
		req.Header.Set("Authorization", token)
	}

	// Create client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GraphQL request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	// Check status
	if resp.StatusCode != 200 {
		u.Logger.Errorf("GraphQL request failed with status code %d: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("GraphQL request failed with status code %d", resp.StatusCode)
	}

	// Parse response
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		u.Logger.Errorf("Failed to parse GraphQL response: %v", err)
		return fmt.Errorf("failed to parse GraphQL response: %v", err)
	}

	// Check for errors in response
	if errors, hasErrors := result["errors"].([]interface{}); hasErrors && len(errors) > 0 {
		u.Logger.Errorf("GraphQL returned errors: %v", errors)
		return fmt.Errorf("GraphQL returned errors: %v", errors)
	}

	// Log success details
	u.Logger.Debugf("Successfully updated custom fields for flaw ID %s", variables["findingId"])

	return nil
}

// MatchTitleToCategory matches flaw titles to categories in a more robust way
func (u *FlawUpdater) MatchTitleToCategory(title string) (string, string) {
	// Strip prefix for comparison
	modifiedTitle := u.StripPrefix(title)
	u.Logger.Infof("Looking for category match for title: '%s'", modifiedTitle)

	config := u.Config()
	if config == nil {
		u.Logger.Warn("Failed to get configuration")
		return "", ""
	}

	plugins, ok := config["plugins"].(map[string]interface{})
	if !ok {
		u.Logger.Warn("Plugins section not found in configuration")
		return "", ""
	}

	// Log all categories and their writeup names for debugging
	u.Logger.Debugf("Available categories in config: %d", len(plugins))
	for category, details := range plugins {
		if categoryDetails, ok := details.(map[string]interface{}); ok {
			if writeupName, ok := categoryDetails["writeup_name"].(string); ok {
				u.Logger.Debugf("Config category: '%s', Writeup name: '%s'", category, writeupName)
			}
		}
	}

	// Log all organized descriptions for debugging
	u.Logger.Debugf("Available organized descriptions: %d", len(u.CustomFields))
	for category := range u.CustomFields {
		u.Logger.Debugf("CustomFields category: '%s'", category)
	}

	// Try different matching strategies
	matchStrategies := []struct {
		name    string
		matchFn func(string, string) bool
	}{
		{"exact match", func(a, b string) bool { return a == b }},
		{"case-insensitive match", func(a, b string) bool { return strings.ToLower(a) == strings.ToLower(b) }},
		{"a contains b", func(a, b string) bool { return strings.Contains(strings.ToLower(a), strings.ToLower(b)) }},
		{"b contains a", func(a, b string) bool { return strings.Contains(strings.ToLower(b), strings.ToLower(a)) }},
	}

	for _, strategy := range matchStrategies {
		for category, details := range plugins {
			categoryDetails, ok := details.(map[string]interface{})
			if !ok {
				continue
			}

			writeupName, ok := categoryDetails["writeup_name"].(string)
			if !ok || writeupName == "" {
				continue
			}

			if strategy.matchFn(modifiedTitle, writeupName) {
				description, ok := u.CustomFields[category]
				if ok && description != "" {
					u.Logger.Infof("Found match using %s for category '%s' with title '%s'",
						strategy.name, category, modifiedTitle)
					return category, description
				}
			}
		}
	}

	// Direct lookup in CustomFields by title as a last resort
	if description, ok := u.CustomFields[modifiedTitle]; ok && description != "" {
		u.Logger.Infof("Found direct match in CustomFields for title '%s'", modifiedTitle)
		return modifiedTitle, description
	}

	u.Logger.Warnf("No matching category found for title: %s", modifiedTitle)
	return "", ""
}

// StripPrefix removes any defined prefix from the title
func (u *FlawUpdater) StripPrefix(title string) string {
	titlePrefix := u.GetTitlePrefix()
	if titlePrefix != "" && strings.HasPrefix(title, titlePrefix) {
		return title[len(titlePrefix):]
	}
	return title
}

// ExecuteFindingUpdateGraphQL updates a finding using the GraphQL API
func (u *FlawUpdater) ExecuteFindingUpdateGraphQL(flawID string, fields []map[string]interface{}) error {
	// Get GraphQL URL
	urlManager, ok := u.URLManager.(interface{ GetGraphqlURL() string })
	if !ok {
		return fmt.Errorf("URL manager does not implement GetGraphqlURL method")
	}

	url := urlManager.GetGraphqlURL()
	if url == "" {
		return fmt.Errorf("failed to get GraphQL URL")
	}

	// Prepare variables
	clientID, _ := u.Args["client_id"].(string)
	reportID, _ := u.Args["report_id"].(string)

	variables := map[string]interface{}{
		"clientId":  clientID,
		"data":      map[string]interface{}{"fields": fields},
		"findingId": flawID,
		"reportId":  reportID,
	}

	// Prepare the GraphQL query
	payload := map[string]interface{}{
		"operationName": "FindingUpdate",
		"variables":     variables,
		"query": `
   		 mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {
				clientId: $clientId
				data: $data
				findingId: $findingId
				reportId: $reportId
			) {
				... on FindingUpdateSuccess {
					finding {
						...FindingFragment
						__typename
					}
					__typename
				}
				__typename
			}
		}
		
		fragment FindingFragment on Finding {
			assignedTo
			closedAt
			createdAt
			code_samples {
				caption
				code
				id
				__typename
			}
			common_identifiers {
				CVE {
					name
					id
					year
					link
					__typename
				}
				CWE {
					name
					id
					link
					__typename
				}
				__typename
			}
			description
			exhibits {
				assets {
					asset
					id
					__typename
				}
				caption
				exhibitID
				index
				type
				__typename
			}
			fields {
				key
				label
				value
				__typename
			}
			flaw_id
			includeEvidence
			recommendations
			references
			scores
			selectedScore
			severity
			source
			status
			subStatus
			tags
			title
			visibility
			calculated_severity
			risk_score {
				CVSS3_1 {
					overall
					vector
					subScore {
						base
						temporal
						environmental
						__typename
					}
					__typename
				}
				CVSS3 {
					overall
					vector
					subScore {
						base
						temporal
						environmental
						__typename
					}
					__typename
				}
				CVSS2 {
					overall
					vector
					subScore {
						base
						temporal
						__typename
					}
					__typename
				}
				CWSS {
					overall
					vector
					subScore {
						base
						environmental
						attackSurface
						__typename
					}
					__typename
				}
				__typename
			}
			hackerOneData {
				bountyAmount
				programId
				programName
				remoteId
				__typename
			}
			snykData {
				issueType
				pkgName
				issueUrl
				identifiers {
					CVE
					CWE
					__typename
				}
				exploitMaturity
				patches
				nearestFixedInVersion
				isMaliciousPackage
				violatedPolicyPublicId
				introducedThrough
				fixInfo {
					isUpgradable
					isPinnable
					isPatchable
					isFixable
					isPartiallyFixable
					nearestFixedInVersion
					__typename
				}
				__typename
			}
			edgescanData {
				id
				portal_url
				details {
					html
					id
					orginal_detail_hash
					parameter_name
					parameter_type
					port
					protocol
					screenshot_urls {
						file
						id
						medium_thumb
						small_thumb
						__typename
					}
					src
					type
					__typename
				}
				__typename
			}
			__typename
		}
		`,
	}

	// Make the request
	requestHandler, ok := u.RequestHandler.(interface {
		Post(string, map[string]string, map[string]interface{}, map[string]interface{}, map[string]interface{}, map[string]string) (interface{}, error)
	})
	if !ok {
		return fmt.Errorf("request handler does not implement required methods")
	}

	response, err := requestHandler.Post(url, nil, nil, payload, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to execute GraphQL query: %v", err)
	}

	// Process the response
	resp, ok := response.(interface {
		GetStatusCode() int
	})
	if !ok {
		return fmt.Errorf("response does not implement required methods")
	}

	if resp.GetStatusCode() != 200 {
		return fmt.Errorf("GraphQL query failed with status code %d", resp.GetStatusCode())
	}

	u.Logger.Debugf("Custom field updated for flaw ID %s", flawID)
	return nil
}

// UpdateFinding updates a finding with a new exhibit (screenshot) using exact query format
func (u *FlawUpdater) UpdateFinding(flawID, exhibitID, caption string) error {
	// Get current exhibits
	exhibits, err := u.GetCurrentExhibits(flawID)
	if err != nil {
		return fmt.Errorf("failed to get current exhibits: %v", err)
	}

	// Create a new exhibit
	newExhibit := map[string]interface{}{
		"type":      "image/png",
		"caption":   caption,
		"exhibitID": exhibitID,
		"index":     len(exhibits) + 1, // Set the index to be the next one in the list
	}

	// Add the new exhibit
	exhibits = append(exhibits, newExhibit)
	u.Logger.Debugf("Adding new exhibit to existing %d exhibits for flaw ID %s", len(exhibits)-1, flawID)

	// Update the finding
	clientID, _ := u.Args["client_id"].(string)
	reportID, _ := u.Args["report_id"].(string)

	// Convert string IDs to appropriate types for GraphQL
	clientIDInt, _ := strconv.Atoi(clientID)
	reportIDInt, _ := strconv.Atoi(reportID)

	// Handle scientific notation in flawID
	var flawIDFloat float64
	if strings.Contains(flawID, "e+") || strings.Contains(flawID, "E+") {
		parsed, err := strconv.ParseFloat(flawID, 64)
		if err != nil {
			return fmt.Errorf("failed to parse scientific notation flaw ID: %v", err)
		}
		flawIDFloat = parsed
	} else {
		// Try parsing as integer first
		flawIDInt, err := strconv.Atoi(flawID)
		if err != nil {
			// If that fails, try parsing as float
			parsed, err := strconv.ParseFloat(flawID, 64)
			if err != nil {
				return fmt.Errorf("failed to parse flaw ID: %v", err)
			}
			flawIDFloat = parsed
		} else {
			flawIDFloat = float64(flawIDInt)
		}
	}

	variables := map[string]interface{}{
		"clientId":  clientIDInt,
		"reportId":  reportIDInt,
		"findingId": flawIDFloat,
		"data": map[string]interface{}{
			"exhibits": exhibits,
		},
	}

	// Get GraphQL URL
	targetPlextrac, ok := u.Args["target_plextrac"].(string)
	if !ok {
		return fmt.Errorf("target_plextrac is missing or not a string")
	}
	url := fmt.Sprintf("https://%s.kevlar.bulletproofsi.net/graphql", targetPlextrac)

	// Use the exact query format
	query := `mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {
  findingUpdate(
    clientId: $clientId
    data: $data
    findingId: $findingId
    reportId: $reportId
  ) {
    ... on FindingUpdateSuccess {
      finding {
        ...FindingFragment
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment FindingFragment on Finding {
  assignedTo
  closedAt
  createdAt
  code_samples {
    caption
    code
    id
    __typename
  }
  common_identifiers {
    CVE {
      name
      id
      year
      link
      __typename
    }
    CWE {
      name
      id
      link
      __typename
    }
    __typename
  }
  description
  exhibits {
    assets {
      asset
      id
      __typename
    }
    caption
    exhibitID
    index
    type
    __typename
  }
  fields {
    key
    label
    value
    __typename
  }
  flaw_id
  includeEvidence
  recommendations
  references
  scores
  selectedScore
  severity
  source
  status
  subStatus
  tags
  title
  visibility
  calculated_severity
  risk_score {
    CVSS3_1 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS3 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS2 {
      overall
      vector
      subScore {
        base
        temporal
        __typename
      }
      __typename
    }
    CWSS {
      overall
      vector
      subScore {
        base
        environmental
        attackSurface
        __typename
      }
      __typename
    }
    __typename
  }
  hackerOneData {
    bountyAmount
    programId
    programName
    remoteId
    __typename
  }
  snykData {
    issueType
    pkgName
    issueUrl
    identifiers {
      CVE
      CWE
      __typename
    }
    exploitMaturity
    patches
    nearestFixedInVersion
    isMaliciousPackage
    violatedPolicyPublicId
    introducedThrough
    fixInfo {
      isUpgradable
      isPinnable
      isPatchable
      isFixable
      isPartiallyFixable
      nearestFixedInVersion
      __typename
    }
    __typename
  }
  edgescanData {
    id
    portal_url
    details {
      html
      id
      orginal_detail_hash
      parameter_name
      parameter_type
      port
      protocol
      screenshot_urls {
        file
        id
        medium_thumb
        small_thumb
        __typename
      }
      src
      type
      __typename
    }
    __typename
  }
  __typename
}`

	payload := map[string]interface{}{
		"operationName": "FindingUpdate",
		"variables":     variables,
		"query":         query,
	}

	// Log the payload for debugging
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
	u.Logger.Debugf("GraphQL payload: %s", string(payloadJSON))

	// Convert payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create a direct HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if token, ok := u.Args["access_token"].(string); ok {
		req.Header.Set("Authorization", token)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Log the response
	u.Logger.Debugf("Response status: %s", resp.Status)
	u.Logger.Debugf("Response body: %s", string(body))

	// Check status code
	if resp.StatusCode != 200 {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Check for GraphQL errors
	if errors, ok := result["errors"].([]interface{}); ok && len(errors) > 0 {
		return fmt.Errorf("GraphQL returned errors: %v", errors)
	}

	u.Logger.Debug("Finding updated with screenshot successfully")
	return nil
}

// GetCurrentExhibits gets the current exhibits for a finding
func (u *FlawUpdater) GetCurrentExhibits(flawID string) ([]map[string]interface{}, error) {
	// Check cache first
	if flaw, ok := u.FlawCache[flawID]; ok {
		if exhibits, ok := flaw["exhibits"].([]map[string]interface{}); ok {
			u.Logger.Debugf("Using cached exhibits for flaw ID %s", flawID)
			return exhibits, nil
		}
	}

	// Get URL for updating finding
	urlManager, ok := u.URLManager.(interface{ GetUpdateFindingURL(string) string })
	if !ok {
		u.Logger.Error("URL manager does not implement GetUpdateFindingURL method")
		return nil, fmt.Errorf("URL manager does not implement GetUpdateFindingURL method")
	}

	url := urlManager.GetUpdateFindingURL(flawID)
	if url == "" {
		u.Logger.Errorf("Failed to get update finding URL for flaw ID %s", flawID)
		return nil, fmt.Errorf("failed to get update finding URL for flaw ID %s", flawID)
	}

	// Use our wrapper function to make the request
	u.Logger.Debugf("Fetching current exhibits for flaw ID %s", flawID)
	bodyBytes, statusCode, err := u.makeGetRequest(url)
	if err != nil {
		u.Logger.Errorf("Failed to get exhibits: %v", err)
		return nil, fmt.Errorf("failed to get exhibits: %v", err)
	}

	// Check status code
	if statusCode != 200 {
		u.Logger.Errorf("Failed to get exhibits: status code %d, response: %s", statusCode, string(bodyBytes))
		return nil, fmt.Errorf("failed to get exhibits: status code %d", statusCode)
	}

	// Parse the JSON response
	var content map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &content); err != nil {
		u.Logger.Errorf("Failed to decode exhibits response: %v", err)
		return nil, fmt.Errorf("failed to decode exhibits response: %v", err)
	}

	// Cache the flaw data
	u.FlawCache[flawID] = content

	// Extract exhibits
	exhibitsObj, ok := content["exhibits"]
	if !ok {
		u.Logger.Debugf("No exhibits found for flaw ID %s", flawID)
		return []map[string]interface{}{}, nil
	}

	exhibits, ok := exhibitsObj.([]interface{})
	if !ok {
		u.Logger.Debugf("Exhibits is not an array for flaw ID %s", flawID)
		return []map[string]interface{}{}, nil
	}

	// Convert to the required format
	result := make([]map[string]interface{}, 0, len(exhibits))
	for _, ex := range exhibits {
		if exhibit, ok := ex.(map[string]interface{}); ok {
			// Extract only needed fields
			simplifiedExhibit := map[string]interface{}{
				"type":      exhibit["type"],
				"caption":   exhibit["caption"],
				"exhibitID": exhibit["exhibitID"],
				"index":     exhibit["index"],
			}
			result = append(result, simplifiedExhibit)
		}
	}

	u.Logger.Debugf("Found %d existing exhibits for flaw ID %s", len(result), flawID)
	return result, nil
}

// ExecuteGraphQLQuery executes a GraphQL query using the exact format required
func (u *FlawUpdater) ExecuteGraphQLQuery(operationName string, variables map[string]interface{}) error {
	// Prepare the GraphQL URL directly
	targetPlextrac := u.Args["target_plextrac"].(string)
	url := fmt.Sprintf("https://%s.kevlar.bulletproofsi.net/graphql", targetPlextrac)

	// CRITICAL FIX: Use the EXACT query format from the example
	query := `mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {
  findingUpdate(
    clientId: $clientId
    data: $data
    findingId: $findingId
    reportId: $reportId
  ) {
    ... on FindingUpdateSuccess {
      finding {
        ...FindingFragment
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment FindingFragment on Finding {
  assignedTo
  closedAt
  createdAt
  code_samples {
    caption
    code
    id
    __typename
  }
  common_identifiers {
    CVE {
      name
      id
      year
      link
      __typename
    }
    CWE {
      name
      id
      link
      __typename
    }
    __typename
  }
  description
  exhibits {
    assets {
      asset
      id
      __typename
    }
    caption
    exhibitID
    index
    type
    __typename
  }
  fields {
    key
    label
    value
    __typename
  }
  flaw_id
  includeEvidence
  recommendations
  references
  scores
  selectedScore
  severity
  source
  status
  subStatus
  tags
  title
  visibility
  calculated_severity
  risk_score {
    CVSS3_1 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS3 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS2 {
      overall
      vector
      subScore {
        base
        temporal
        __typename
      }
      __typename
    }
    CWSS {
      overall
      vector
      subScore {
        base
        environmental
        attackSurface
        __typename
      }
      __typename
    }
    __typename
  }
  hackerOneData {
    bountyAmount
    programId
    programName
    remoteId
    __typename
  }
  snykData {
    issueType
    pkgName
    issueUrl
    identifiers {
      CVE
      CWE
      __typename
    }
    exploitMaturity
    patches
    nearestFixedInVersion
    isMaliciousPackage
    violatedPolicyPublicId
    introducedThrough
    fixInfo {
      isUpgradable
      isPinnable
      isPatchable
      isFixable
      isPartiallyFixable
      nearestFixedInVersion
      __typename
    }
    __typename
  }
  edgescanData {
    id
    portal_url
    details {
      html
      id
      orginal_detail_hash
      parameter_name
      parameter_type
      port
      protocol
      screenshot_urls {
        file
        id
        medium_thumb
        small_thumb
        __typename
      }
      src
      type
      __typename
    }
    __typename
  }
  __typename
}`

	payload := map[string]interface{}{
		"operationName": operationName,
		"variables":     variables,
		"query":         query,
	}

	// Log the payload for debugging
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
	u.Logger.Debugf("GraphQL payload: %s", string(payloadJSON))

	// Convert payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create a direct HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if token, ok := u.Args["access_token"].(string); ok {
		req.Header.Set("Authorization", token)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Log the response
	u.Logger.Debugf("Response status: %s", resp.Status)
	u.Logger.Debugf("Response body: %s", string(body))

	// Check status code
	if resp.StatusCode != 200 {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Check for GraphQL errors
	if errors, ok := result["errors"].([]interface{}); ok && len(errors) > 0 {
		return fmt.Errorf("GraphQL returned errors: %v", errors)
	}

	u.Logger.Infof("GraphQL query %s completed successfully", operationName)
	return nil
}

// ClearMD5HashesFromReferences removes MD5 hashes from references fields
func (u *FlawUpdater) ClearMD5HashesFromReferences(flaws []map[string]interface{}) {
	successCount := 0
	errorCount := 0

	for _, flaw := range flaws {
		flawID, ok := flaw["flaw_id"].(string)
		if !ok {
			u.Logger.Warnf("Flaw is missing flaw_id field")
			continue
		}

		references, ok := flaw["references"].(string)
		if !ok || references == "" {
			u.Logger.Debugf("No references found for flaw ID %s", flawID)
			continue
		}

		// Remove HTML tags
		cleanReferences := u.HTMLTagPattern.ReplaceAllString(references, "")

		// Find all MD5 hashes
		md5Hashes := u.MD5Pattern.FindAllString(cleanReferences, -1)
		if len(md5Hashes) > 0 {
			u.Logger.Debugf("Found %d MD5 hashes in references for flaw ID %s", len(md5Hashes), flawID)

			// Remove MD5 hashes
			for _, md5Hash := range md5Hashes {
				cleanReferences = strings.ReplaceAll(cleanReferences, md5Hash, "")
			}

			// Separate URLs by new line
			cleanReferences = u.URLPattern.ReplaceAllString(cleanReferences, "\n$1")
			if len(cleanReferences) > 0 && cleanReferences[0] == '\n' {
				cleanReferences = cleanReferences[1:] // Skip the first newline
			}

			// Update references
			u.Logger.Debugf("Updating references for flaw ID %s", flawID)
			if err := u.UpdateReferencesForFlaw(flawID, strings.TrimSpace(cleanReferences)); err != nil {
				u.Logger.Warnf("Failed to update references for flaw ID %s: %v", flawID, err)
				errorCount++
			} else {
				u.Logger.Debugf("Successfully updated references for flaw ID %s", flawID)
				successCount++
			}
		}
	}

	u.Logger.Infof("Reference updates completed: %d successful, %d failed", successCount, errorCount)
}

// UpdateReferencesForFlaw updates the references field for a flaw using the exact query format
func (u *FlawUpdater) UpdateReferencesForFlaw(flawID, references string) error {
	// Prepare variables
	clientID, _ := u.Args["client_id"].(string)
	reportID, _ := u.Args["report_id"].(string)

	// Convert string IDs to appropriate types for GraphQL
	clientIDInt, _ := strconv.Atoi(clientID)
	reportIDInt, _ := strconv.Atoi(reportID)

	// Handle scientific notation in flawID
	var flawIDFloat float64
	if strings.Contains(flawID, "e+") || strings.Contains(flawID, "E+") {
		parsed, err := strconv.ParseFloat(flawID, 64)
		if err != nil {
			u.Logger.Warnf("Failed to update references for flaw ID %s: %v", flawID, err)
			return fmt.Errorf("failed to parse flaw ID: %v", err)
		}
		flawIDFloat = parsed
	} else {
		// Try parsing as integer first
		flawIDInt, err := strconv.Atoi(flawID)
		if err != nil {
			// If that fails, try parsing as float
			parsed, err := strconv.ParseFloat(flawID, 64)
			if err != nil {
				u.Logger.Warnf("Failed to update references for flaw ID %s: %v", flawID, err)
				return fmt.Errorf("failed to parse flaw ID: %v", err)
			}
			flawIDFloat = parsed
		} else {
			flawIDFloat = float64(flawIDInt)
		}
	}

	variables := map[string]interface{}{
		"clientId":  clientIDInt,
		"reportId":  reportIDInt,
		"findingId": flawIDFloat,
		"data": map[string]interface{}{
			"references": references,
		},
	}

	// Get GraphQL URL
	targetPlextrac, ok := u.Args["target_plextrac"].(string)
	if !ok {
		u.Logger.Errorf("target_plextrac is missing or not a string: %v", u.Args["target_plextrac"])
		return fmt.Errorf("target_plextrac is missing or not a string")
	}
	url := fmt.Sprintf("https://%s.kevlar.bulletproofsi.net/graphql", targetPlextrac)

	// Use the exact query format
	query := `mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {
  findingUpdate(
    clientId: $clientId
    data: $data
    findingId: $findingId
    reportId: $reportId
  ) {
    ... on FindingUpdateSuccess {
      finding {
        ...FindingFragment
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment FindingFragment on Finding {
  assignedTo
  closedAt
  createdAt
  code_samples {
    caption
    code
    id
    __typename
  }
  common_identifiers {
    CVE {
      name
      id
      year
      link
      __typename
    }
    CWE {
      name
      id
      link
      __typename
    }
    __typename
  }
  description
  exhibits {
    assets {
      asset
      id
      __typename
    }
    caption
    exhibitID
    index
    type
    __typename
  }
  fields {
    key
    label
    value
    __typename
  }
  flaw_id
  includeEvidence
  recommendations
  references
  scores
  selectedScore
  severity
  source
  status
  subStatus
  tags
  title
  visibility
  calculated_severity
  risk_score {
    CVSS3_1 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS3 {
      overall
      vector
      subScore {
        base
        temporal
        environmental
        __typename
      }
      __typename
    }
    CVSS2 {
      overall
      vector
      subScore {
        base
        temporal
        __typename
      }
      __typename
    }
    CWSS {
      overall
      vector
      subScore {
        base
        environmental
        attackSurface
        __typename
      }
      __typename
    }
    __typename
  }
  hackerOneData {
    bountyAmount
    programId
    programName
    remoteId
    __typename
  }
  snykData {
    issueType
    pkgName
    issueUrl
    identifiers {
      CVE
      CWE
      __typename
    }
    exploitMaturity
    patches
    nearestFixedInVersion
    isMaliciousPackage
    violatedPolicyPublicId
    introducedThrough
    fixInfo {
      isUpgradable
      isPinnable
      isPatchable
      isFixable
      isPartiallyFixable
      nearestFixedInVersion
      __typename
    }
    __typename
  }
  edgescanData {
    id
    portal_url
    details {
      html
      id
      orginal_detail_hash
      parameter_name
      parameter_type
      port
      protocol
      screenshot_urls {
        file
        id
        medium_thumb
        small_thumb
        __typename
      }
      src
      type
      __typename
    }
    __typename
  }
  __typename
}`

	payload := map[string]interface{}{
		"operationName": "FindingUpdate",
		"variables":     variables,
		"query":         query,
	}

	// Convert payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		u.Logger.Errorf("Failed to marshal payload: %v", err)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Create a direct HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		u.Logger.Errorf("Failed to create request: %v", err)
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if token, ok := u.Args["access_token"].(string); ok {
		req.Header.Set("Authorization", token)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Execute the request
	u.Logger.Debugf("Sending GraphQL request to update references for flaw ID %s", flawID)
	resp, err := client.Do(req)
	if err != nil {
		u.Logger.Errorf("Failed to execute request: %v", err)
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		u.Logger.Errorf("Failed to read response: %v", err)
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Log the response
	u.Logger.Debugf("Response status: %s", resp.Status)
	u.Logger.Debugf("Response body: %s", string(body))

	// Check status code
	if resp.StatusCode != 200 {
		u.Logger.Errorf("Request failed with status %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		u.Logger.Errorf("Failed to parse response: %v", err)
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Check for GraphQL errors
	if errors, ok := result["errors"].([]interface{}); ok && len(errors) > 0 {
		u.Logger.Errorf("GraphQL returned errors: %v", errors)
		return fmt.Errorf("GraphQL returned errors: %v", errors)
	}

	u.Logger.Debugf("Successfully updated references for flaw ID %s", flawID)
	return nil
}

// Config provides access to the configuration
func (u *FlawUpdater) Config() map[string]interface{} {
	if c, ok := u.Converter.(interface{ GetConfig() map[string]interface{} }); ok {
		return c.GetConfig()
	}
	return nil
}
