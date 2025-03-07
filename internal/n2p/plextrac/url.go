// Package plextrac provides functionality for interacting with the Plextrac API
package plextrac

import (
	"fmt"
	"strings"
)

// URLManager handles construction of URLs for the Plextrac API
type URLManager struct {
	args            map[string]interface{}
	baseURL         string
	v2BaseURL       string
	authenticateURL string
}

// NewURLManager creates a new URLManager instance
func NewURLManager(args map[string]interface{}, baseURL string) *URLManager {
	return &URLManager{
		args:            args,
		baseURL:         baseURL + "api/v1",
		v2BaseURL:       baseURL + "api/v2",
		authenticateURL: baseURL + "api/v1/authenticate",
	}
}

// constructURL builds a URL by joining the base URL with the provided segments
func (m *URLManager) constructURL(segments ...interface{}) string {
	strSegments := make([]string, len(segments))
	for i, segment := range segments {
		strSegments[i] = fmt.Sprintf("%v", segment)
	}
	return fmt.Sprintf("%s/%s", m.baseURL, strings.Join(strSegments, "/"))
}

// constructV2URL builds a URL using the v2 API base URL
func (m *URLManager) constructV2URL(segments ...interface{}) string {
	strSegments := make([]string, len(segments))
	for i, segment := range segments {
		strSegments[i] = fmt.Sprintf("%v", segment)
	}
	return fmt.Sprintf("%s/%s", m.v2BaseURL, strings.Join(strSegments, "/"))
}

// GetAuthenticateURL returns the authentication URL
func (m *URLManager) GetAuthenticateURL() string {
	return m.authenticateURL
}

// GetWriteupDBURL returns the URL for a specific write-up database
func (m *URLManager) GetWriteupDBURL(writeupID string) string {
	return m.constructURL("template", writeupID)
}

// GetUpdateFindingURL returns the URL for updating a specific finding
func (m *URLManager) GetUpdateFindingURL(flawID string) string {
	// If flawID already has a special format like "flaw_[clientId]-[reportId]-[actualFlawId]"
	// extract the actual flawID
	actualFlawID := flawID
	if strings.HasPrefix(flawID, "flaw_") {
		parts := strings.Split(flawID, "-")
		if len(parts) >= 3 {
			// The last part is the actual flawID we need
			actualFlawID = parts[len(parts)-1]
		}
	}

	// Construct the URL using the API v1 format
	apiUrl := fmt.Sprintf(
		"client/%s/report/%s/flaw/%s",
		m.args["client_id"],
		m.args["report_id"],
		actualFlawID,
	)

	// Log the constructed URL for debugging
	fmt.Printf("Constructed URL for flaw ID %s: %s/%s\n", flawID, m.baseURL, apiUrl)

	return m.constructURL(
		"client",
		m.args["client_id"],
		"report",
		m.args["report_id"],
		"flaw",
		actualFlawID,
	)
}

// GetDeleteFindingURL returns the URL for deleting a specific finding
func (m *URLManager) GetDeleteFindingURL(flawID int) string {
	return m.constructURL(
		"client",
		m.args["client_id"],
		"report",
		m.args["report_id"],
		"flaw",
		flawID,
	)
}

// GetGraphqlURL returns the GraphQL URL
func (m *URLManager) GetGraphqlURL() string {
	return fmt.Sprintf(
		"https://%s.kevlar.bulletproofsi.net/graphql",
		m.args["target_plextrac"],
	)
}

// GetCopyReportURL returns the URL for copying a report
func (m *URLManager) GetCopyReportURL(writeupID string) string {
	return m.constructURL("copy", writeupID)
}

// GetClientInfoURL returns the URL for client information
func (m *URLManager) GetClientInfoURL() string {
	return m.constructURL("client", m.args["client_id"])
}

// GetReportInfoURL returns the URL for report information
func (m *URLManager) GetReportInfoURL() string {
	return m.constructURL(
		"client",
		m.args["client_id"],
		"report",
		m.args["report_id"],
	)
}

// GetDeleteFlawURL returns the URL for deleting flaws
func (m *URLManager) GetDeleteFlawURL() string {
	return m.constructURL(
		"client",
		m.args["client_id"],
		"report",
		m.args["report_id"],
		"flaws",
		"delete",
	)
}

// GetFlawsURL returns the URL for flaws
func (m *URLManager) GetFlawsURL() string {
	return m.constructURL(
		"client",
		m.args["client_id"],
		"report",
		m.args["report_id"],
		"flaws",
	)
}

// GetUploadNessusURL returns the URL for uploading Nessus files
func (m *URLManager) GetUploadNessusURL() string {
	// Will change in v1.61 to v2 API
	return m.constructURL(
		"client",
		m.args["client_id"],
		"report",
		m.args["report_id"],
		"import",
		"offlinecsv",
	)
}

// GetClientCreateURL returns the URL for creating a new client
func (m *URLManager) GetClientCreateURL() string {
	return m.constructURL("client", "create")
}

// GetReportCreateURL returns the URL for creating a new report
func (m *URLManager) GetReportCreateURL(clientID string) string {
	return m.constructURL("client", clientID, "report", "create")
}

// GetReportTemplateURL returns the URL for report templates
func (m *URLManager) GetReportTemplateURL() string {
	return m.constructURL("tenant", "0", "report-templates")
}

// GetFieldTemplateURL returns the URL for field templates
func (m *URLManager) GetFieldTemplateURL() string {
	return m.constructURL("field-templates")
}

// GetUploadScreenshotURL returns the URL for uploading screenshots
func (m *URLManager) GetUploadScreenshotURL() string {
	return m.constructURL(
		"client",
		m.args["client_id"],
		"report",
		m.args["report_id"],
		"upload2",
	)
}
