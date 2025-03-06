package findings

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// NonCoreUpdater updates non-core custom fields for findings
type NonCoreUpdater struct {
	URLManager     interface{} // Avoid circular dependency with plextrac package
	RequestHandler interface{} // Avoid circular dependency with plextrac package
	Args           map[string]interface{}
	FlawLister     interface{} // Changed from *FlawLister to interface{}
	Logger         *logrus.Logger
}

// NewNonCoreUpdater creates a new NonCoreUpdater instance
func NewNonCoreUpdater(urlManager, requestHandler interface{}, args map[string]interface{}) *NonCoreUpdater {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	flawLister := NewFlawLister(urlManager, requestHandler, args)
	return &NonCoreUpdater{
		URLManager:     urlManager,
		RequestHandler: requestHandler,
		Args:           args,
		FlawLister:     flawLister,
		Logger:         logger,
	}
}

// GetNewFields returns the new fields to add to findings
func (n *NonCoreUpdater) GetNewFields() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"key":   "recommendation_title",
			"label": "Title of the recommendation - Short Recommendation",
			"value": "FIXME",
		},
		{
			"key":   "owner",
			"label": "Recommendation owner (who will fix the finding)",
			"value": "Systems Administrator",
		},
	}
}

// PrepareFields processes current fields and adds new ones
func (n *NonCoreUpdater) PrepareFields(currentFields interface{}) []map[string]interface{} {
	var currentFieldList []map[string]interface{}

	// Convert current fields to a map for easy manipulation
	currentFieldMap := make(map[string]map[string]interface{})

	// Handle different input types
	switch fields := currentFields.(type) {
	case map[string]interface{}:
		// If currentFields is a map, convert it to our structure
		for key, value := range fields {
			if fieldMap, ok := value.(map[string]interface{}); ok {
				currentFieldMap[key] = fieldMap
			}
		}
	case []map[string]interface{}:
		// If currentFields is already a list of maps, convert to our structure
		for _, field := range fields {
			key, ok := field["key"].(string)
			if !ok {
				continue
			}
			currentFieldMap[key] = field
		}
	default:
		n.Logger.Errorf("Unexpected format for current_fields: %T", currentFields)
		return []map[string]interface{}{}
	}

	// Remove any existing 'merged_assets' field
	if mergedAssets, ok := currentFieldMap["merged_assets"]; ok {
		mergedAssets["key"] = "merged_assets"
		// Remove sort_order if it exists
		delete(mergedAssets, "sort_order")
	}

	// Add new fields
	newFields := n.GetNewFields()
	for _, field := range newFields {
		key, ok := field["key"].(string)
		if !ok {
			continue
		}
		currentFieldMap[key] = field
	}

	// Convert back to list format
	currentFieldList = make([]map[string]interface{}, 0, len(currentFieldMap))
	for _, field := range currentFieldMap {
		// Ensure field has required keys
		if _, ok := field["key"]; !ok {
			continue
		}
		if _, ok := field["label"]; !ok {
			continue
		}
		if _, ok := field["value"]; !ok {
			continue
		}

		// Add simplified field to the list
		simplifiedField := map[string]interface{}{
			"key":   field["key"],
			"label": field["label"],
			"value": field["value"],
		}
		currentFieldList = append(currentFieldList, simplifiedField)
	}

	return currentFieldList
}

// SendGraphQLRequest sends a GraphQL request to update finding fields using exact query format
func (n *NonCoreUpdater) SendGraphQLRequest(flawID string, finalFields []map[string]interface{}) (bool, error) {
	// Get GraphQL URL
	urlManager, ok := n.URLManager.(interface{ GetGraphqlURL() string })
	if !ok {
		return false, fmt.Errorf("URL manager does not implement GetGraphqlURL method")
	}

	url := urlManager.GetGraphqlURL()
	if url == "" {
		return false, fmt.Errorf("failed to get GraphQL URL")
	}

	// Prepare the GraphQL payload
	clientID, _ := n.Args["client_id"].(string)
	reportID, _ := n.Args["report_id"].(string)

	// Convert string IDs to appropriate types for GraphQL
	clientIDInt, err := strconv.Atoi(clientID)
	if err != nil {
		return false, fmt.Errorf("failed to convert client_id to int: %v", err)
	}

	reportIDInt, err := strconv.Atoi(reportID)
	if err != nil {
		return false, fmt.Errorf("failed to convert report_id to int: %v", err)
	}

	// Convert flawID to float if it's in scientific notation
	var flawIDFloat float64
	if strings.Contains(flawID, "e+") {
		parsed, err := strconv.ParseFloat(flawID, 64)
		if err != nil {
			return false, fmt.Errorf("failed to parse flaw ID as float: %v", err)
		}
		flawIDFloat = parsed
	} else {
		parsed, err := strconv.ParseFloat(flawID, 64)
		if err != nil {
			return false, fmt.Errorf("failed to parse flaw ID as float: %v", err)
		}
		flawIDFloat = parsed
	}

	variables := map[string]interface{}{
		"clientId":  clientIDInt,
		"reportId":  reportIDInt,
		"findingId": flawIDFloat,
		"data": map[string]interface{}{
			"fields": finalFields,
		},
	}

	// Log the variables for debugging
	varsJSON, _ := json.MarshalIndent(variables, "", "  ")
	n.Logger.Debugf("GraphQL variables: %s", string(varsJSON))

	// Use the exact query format from the example
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

	// Convert to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal GraphQL payload: %v", err)
	}

	// Create direct HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create GraphQL request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if token, ok := n.Args["access_token"].(string); ok {
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
		return false, fmt.Errorf("GraphQL request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	// Log the response
	n.Logger.Debugf("Response status: %s", resp.Status)
	n.Logger.Debugf("Response body: %s", string(bodyBytes))

	// Check status
	if resp.StatusCode != 200 {
		n.Logger.Errorf("GraphQL request failed with status code %d: %s", resp.StatusCode, string(bodyBytes))
		return false, fmt.Errorf("GraphQL request failed with status code %d", resp.StatusCode)
	}

	// Parse response
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		n.Logger.Errorf("Failed to parse GraphQL response: %v", err)
		return false, fmt.Errorf("failed to parse GraphQL response: %v", err)
	}

	// Check for errors in response
	if errors, hasErrors := result["errors"].([]interface{}); hasErrors && len(errors) > 0 {
		n.Logger.Errorf("GraphQL returned errors: %v", errors)
		return false, fmt.Errorf("GraphQL returned errors: %v", errors)
	}

	// Log success details
	n.Logger.Debugf("Successfully updated custom fields for flaw ID %s", flawID)

	return true, nil
}

// UpdateFlawFields updates the custom fields for a flaw
func (n *NonCoreUpdater) UpdateFlawFields(flawID string, currentFields interface{}) bool {
	finalFields := n.PrepareFields(currentFields)

	success, err := n.SendGraphQLRequest(flawID, finalFields)
	if err != nil {
		n.Logger.Errorf("Error updating fields for flaw ID %s: %v", flawID, err)
		return false
	}

	return success
}

// Process updates all flaws with non-core custom fields
func (n *NonCoreUpdater) Process() error {
	// Use type assertion with interface check
	var flaws []map[string]interface{}
	if flawLister, ok := n.FlawLister.(interface {
		ListFlaws() []map[string]interface{}
	}); ok {
		flaws = flawLister.ListFlaws()
	} else {
		n.Logger.Error("FlawLister does not implement ListFlaws method")
		return fmt.Errorf("FlawLister does not implement ListFlaws method")
	}

	for _, flaw := range flaws {
		flawID, ok := flaw["id"].(string)
		if !ok {
			// Try flaw_id if id is not available
			if flawID, ok = flaw["flaw_id"].(string); !ok {
				continue
			}
		}

		existingFields, ok := flaw["fields"]
		if !ok {
			existingFields = []map[string]interface{}{}
		}

		if !n.UpdateFlawFields(flawID, existingFields) {
			n.Logger.Errorf("Failed to update fields for flaw ID %s", flawID)
		}
	}

	return nil
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) && s[len(s)-len(substr):] == substr
}
