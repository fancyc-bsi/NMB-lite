package client

import (
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
)

// TomlFinding represents a finding configuration in the TOML file
type TomlFinding struct {
	Title    string `toml:"title"`
	Severity string `toml:"severity"`
}

// TomlConfig represents the structure of the TOML configuration file
type TomlConfig struct {
	Finding []TomlFinding `toml:"finding"`
}

// ClientOverrides manages client-specific overrides based on TOML configuration
type ClientOverrides struct {
	URLManager     interface{} // Avoid circular dependency with plextrac package
	RequestHandler interface{} // Avoid circular dependency with plextrac package
	Args           map[string]interface{}
	FlawLister     interface{} // Avoid circular dependency with findings package
	SeverityMap    map[string]string
	Logger         *logrus.Logger
}

// NewClientOverrides creates a new ClientOverrides instance
func NewClientOverrides(urlManager, requestHandler interface{}, args map[string]interface{}) *ClientOverrides {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Create flaw lister - use type assertion to avoid import cycle
	var flawLister interface{}
	if fl, ok := requestHandler.(interface{ GetFlawLister() interface{} }); ok {
		flawLister = fl.GetFlawLister()
	} else {
		// Try to get it from URLManager
		if fl, ok := urlManager.(interface{ GetFlawLister() interface{} }); ok {
			flawLister = fl.GetFlawLister()
		} else {
			// Create a new one if we can't get it otherwise
			flawLister = NewFlawLister(urlManager, requestHandler)
		}
	}

	return &ClientOverrides{
		URLManager:     urlManager,
		RequestHandler: requestHandler,
		Args:           args,
		FlawLister:     flawLister,
		SeverityMap:    make(map[string]string),
		Logger:         logger,
	}
}

// LoadSeverityMap loads severity mappings from a TOML file
func (c *ClientOverrides) LoadSeverityMap(tomlFile string) (map[string]string, error) {
	severityMap := make(map[string]string)

	// Read TOML content
	data, err := ioutil.ReadFile(tomlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read TOML file: %w", err)
	}

	// Parse TOML
	var config TomlConfig
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse TOML file: %w", err)
	}

	// Build severity map
	for _, finding := range config.Finding {
		if finding.Title != "" && finding.Severity != "" {
			severityMap[finding.Title] = finding.Severity
		}
	}

	return severityMap, nil
}

// BuildPayload builds the payload for updating a flaw
func (c *ClientOverrides) BuildPayload(severity string, flaw map[string]interface{}) (map[string]interface{}, error) {
	// Check essential fields
	clientID, _ := c.Args["client_id"].(string)
	reportID, _ := c.Args["report_id"].(string)

	// Prepare payload
	risk_score, _ := flaw["risk_score"].(map[string]interface{})
	calculated_severity, _ := flaw["calculated_severity"].(bool)
	affected_assets, _ := flaw["affected_assets"].(map[string]interface{})
	common_identifiers, _ := flaw["common_identifiers"].(map[string]interface{})
	exhibits, _ := flaw["exhibits"].([]interface{})
	fields, _ := flaw["fields"].([]interface{})

	// Cast exhibits to required format
	exhibitsArray := make([]map[string]interface{}, 0)
	if exhibits != nil {
		for _, ex := range exhibits {
			if exMap, ok := ex.(map[string]interface{}); ok {
				exhibitsArray = append(exhibitsArray, exMap)
			}
		}
	}

	// Cast fields to required format
	fieldsArray := make([]map[string]interface{}, 0)
	if fields != nil {
		for _, field := range fields {
			if fieldMap, ok := field.(map[string]interface{}); ok {
				fieldsArray = append(fieldsArray, fieldMap)
			}
		}
	}

	return map[string]interface{}{
		"status":              flaw["status"],
		"title":               flaw["title"],
		"severity":            severity,
		"subStatus":           flaw["sub_status"],
		"assignedTo":          flaw["assigned_to"],
		"description":         flaw["description"],
		"recommendations":     flaw["recommendations"],
		"references":          flaw["references"],
		"tags":                flaw["tags"],
		"risk_score":          risk_score,
		"calculated_severity": calculated_severity,
		"affected_assets":     affected_assets,
		"common_identifiers":  common_identifiers,
		"exhibits":            exhibitsArray,
		"client_id":           clientID,
		"report_id":           reportID,
		"source":              flaw["source"],
		"last_update":         flaw["last_update"],
		"doc_version":         flaw["doc_version"],
		"createdAt":           flaw["createdAt"],
		"report_name":         flaw["report_name"],
		"visibility":          flaw["visibility"],
		"operators":           flaw["operators"],
		"reportedBy":          flaw["reportedBy"],
		"cuid":                flaw["cuid"],
		"doc_type":            flaw["doc_type"],
		"fields":              fieldsArray,
		"tenant_id":           flaw["tenant_id"],
		"id":                  flaw["id"],
	}, nil
}

// GetFlawIDs returns a list of flaw IDs from the FlawLister
func (c *ClientOverrides) GetFlawIDs() ([]string, error) {
	// Use type assertion to call the ListFlaws method
	if flawLister, ok := c.FlawLister.(interface {
		ListFlaws() []map[string]interface{}
	}); ok {
		flaws := flawLister.ListFlaws()
		flawIDs := make([]string, 0, len(flaws))
		for _, flaw := range flaws {
			if flawID, ok := flaw["flaw_id"].(string); ok {
				flawIDs = append(flawIDs, flawID)
			}
		}
		return flawIDs, nil
	}
	return nil, fmt.Errorf("flaw lister does not implement required methods")
}

// ReplaceEngine applies client-specific overrides to findings
func (c *ClientOverrides) ReplaceEngine() error {
	c.Logger.Info("Applying client-specific configurations...")

	// Load severity map from TOML
	clientConfigFile, _ := c.Args["client_config"].(string)
	severityMap, err := c.LoadSeverityMap(clientConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load severity map: %w", err)
	}
	c.SeverityMap = severityMap

	// Get flaw IDs
	flawIDs, err := c.GetFlawIDs()
	if err != nil {
		return fmt.Errorf("failed to get flaw IDs: %w", err)
	}

	for _, flawID := range flawIDs {
		err := c.ProcessFlaw(flawID)
		if err != nil {
			c.Logger.Errorf("Failed to process flaw %s: %v", flawID, err)
			// Continue with other flaws
		}
	}

	c.Logger.Info("Client-specific configurations applied successfully.")
	return nil
}

// ProcessFlaw processes a single flaw based on the configuration
func (c *ClientOverrides) ProcessFlaw(flawID string) error {
	// Get detailed flaw
	flaw, err := c.GetDetailedFlaw(flawID)
	if err != nil {
		return fmt.Errorf("failed to get detailed flaw: %w", err)
	}
	if flaw == nil {
		return fmt.Errorf("flaw not found")
	}

	// Check if this flaw needs to be updated
	title, ok := flaw["title"].(string)
	if !ok {
		return fmt.Errorf("flaw title not found")
	}

	newSeverity, ok := c.SeverityMap[title]
	if !ok {
		// No override for this flaw
		c.Logger.Debugf("No severity update found for flaw %s with title '%s'", flawID, title)
		return nil
	}

	// Handle DELETE
	if newSeverity == "DELETE" {
		return c.DeleteFlaw(flawID)
	}

	// Update severity
	return c.UpdateFlawSeverity(flawID, flaw, newSeverity)
}

// GetDetailedFlaw gets detailed information about a flaw
func (c *ClientOverrides) GetDetailedFlaw(flawID string) (map[string]interface{}, error) {
	// Use type assertion to call the GetDetailedFlaw method
	if flawLister, ok := c.FlawLister.(interface {
		GetDetailedFlaw(string) map[string]interface{}
	}); ok {
		return flawLister.GetDetailedFlaw(flawID), nil
	}

	// Alternative: make our own request
	urlManager, ok := c.URLManager.(interface{ GetUpdateFindingURL(string) string })
	if !ok {
		return nil, fmt.Errorf("URL manager does not implement GetUpdateFindingURL method")
	}

	url := urlManager.GetUpdateFindingURL(flawID)
	if url == "" {
		return nil, fmt.Errorf("failed to get update finding URL")
	}

	requestHandler, ok := c.RequestHandler.(interface {
		Get(string, map[string]string, map[string]interface{}) (interface{}, error)
	})
	if !ok {
		return nil, fmt.Errorf("request handler does not implement required methods")
	}

	response, err := requestHandler.Get(url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get flaw details: %w", err)
	}

	resp, ok := response.(interface {
		DecodeJSON(interface{}) error
		GetStatusCode() int
	})
	if !ok {
		return nil, fmt.Errorf("response does not implement required methods")
	}

	if resp.GetStatusCode() != 200 {
		return nil, fmt.Errorf("failed to get flaw details: status code %d", resp.GetStatusCode())
	}

	var flaw map[string]interface{}
	if err := resp.DecodeJSON(&flaw); err != nil {
		return nil, fmt.Errorf("failed to decode flaw details: %w", err)
	}

	return flaw, nil
}

// DeleteFlaw deletes a flaw
func (c *ClientOverrides) DeleteFlaw(flawID string) error {
	// Get delete URL
	urlManager, ok := c.URLManager.(interface{ GetDeleteFindingURL(int) string })
	if !ok {
		return fmt.Errorf("URL manager does not implement GetDeleteFindingURL method")
	}

	// Convert flawID to int
	flawIDInt, err := strconv.Atoi(flawID)
	if err != nil {
		return fmt.Errorf("invalid flaw ID: %w", err)
	}

	url := urlManager.GetDeleteFindingURL(flawIDInt)
	if url == "" {
		return fmt.Errorf("failed to get delete finding URL")
	}

	// Make delete request
	requestHandler, ok := c.RequestHandler.(interface {
		Delete(string, map[string]string) (interface{}, error)
	})
	if !ok {
		return fmt.Errorf("request handler does not implement Delete method")
	}

	response, err := requestHandler.Delete(url, nil)
	if err != nil {
		return fmt.Errorf("failed to delete flaw: %w", err)
	}

	resp, ok := response.(interface {
		GetStatusCode() int
	})
	if !ok {
		return fmt.Errorf("response does not implement required methods")
	}

	if resp.GetStatusCode() != 200 {
		return fmt.Errorf("failed to delete flaw: status code %d", resp.GetStatusCode())
	}

	c.Logger.Infof("Successfully deleted flaw %s", flawID)
	return nil
}

// UpdateFlawSeverity updates the severity of a flaw
func (c *ClientOverrides) UpdateFlawSeverity(flawID string, flaw map[string]interface{}, newSeverity string) error {
	// Build payload
	payload, err := c.BuildPayload(newSeverity, flaw)
	if err != nil {
		return fmt.Errorf("failed to build payload: %w", err)
	}

	// Get update URL
	urlManager, ok := c.URLManager.(interface{ GetUpdateFindingURL(string) string })
	if !ok {
		return fmt.Errorf("URL manager does not implement GetUpdateFindingURL method")
	}

	url := urlManager.GetUpdateFindingURL(flawID)
	if url == "" {
		return fmt.Errorf("failed to get update finding URL")
	}

	// Make put request
	requestHandler, ok := c.RequestHandler.(interface {
		Put(string, map[string]string, map[string]interface{}, map[string]interface{}) (interface{}, error)
	})
	if !ok {
		return fmt.Errorf("request handler does not implement Put method")
	}

	response, err := requestHandler.Put(url, nil, nil, payload)
	if err != nil {
		return fmt.Errorf("failed to update flaw: %w", err)
	}

	resp, ok := response.(interface {
		GetStatusCode() int
	})
	if !ok {
		return fmt.Errorf("response does not implement required methods")
	}

	if resp.GetStatusCode() != 200 {
		return fmt.Errorf("failed to update flaw: status code %d", resp.GetStatusCode())
	}

	c.Logger.Infof("Successfully updated flaw %s severity to %s", flawID, newSeverity)
	return nil
}

// NewFlawLister creates a minimal FlawLister for use by ClientOverrides
func NewFlawLister(urlManager, requestHandler interface{}) interface{} {
	// This is a simplified version of the FlawLister to avoid import cycles
	return struct {
		URLManager     interface{}
		RequestHandler interface{}
		Logger         *logrus.Logger
	}{
		URLManager:     urlManager,
		RequestHandler: requestHandler,
		Logger:         logrus.New(),
	}
}
