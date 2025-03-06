package findings

import (
	"NMB/internal/n2p/plextrac"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/sirupsen/logrus"
)

// DescriptionProcessor updates description and recommendation information for flaws
type DescriptionProcessor struct {
	Config         map[string]interface{}
	URLManager     interface{} // Avoid circular dependency with plextrac package
	RequestHandler interface{} // Avoid circular dependency with plextrac package
	Mode           string
	Args           map[string]interface{}
	FlawLister     interface{} // Changed from *FlawLister to interface{}
	Logger         *logrus.Logger
}

// NewDescriptionProcessor creates a new DescriptionProcessor instance
func NewDescriptionProcessor(config map[string]interface{}, urlManager, requestHandler interface{}, mode string, args map[string]interface{}) *DescriptionProcessor {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Store the FlawLister as interface{}
	flawLister := NewFlawLister(urlManager, requestHandler, args)

	return &DescriptionProcessor{
		Config:         config,
		URLManager:     urlManager,
		RequestHandler: requestHandler,
		Mode:           mode,
		Args:           args,
		FlawLister:     flawLister,
		Logger:         logger,
	}
}

// makeGetRequest performs a GET request using the request handler
func (p *DescriptionProcessor) makeGetRequest(url string) ([]byte, int, error) {
	// Create a new RequestHandler directly without type assertion
	handler := plextrac.NewRequestHandler("")

	// Set the access token
	if token, ok := p.Args["access_token"].(string); ok {
		handler.SetAccessToken(token)
	}

	// Make the request
	p.Logger.Debugf("Making GET request to %s", url)
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

// makePostRequest performs a POST request using the request handler
func (p *DescriptionProcessor) makePostRequest(url string, jsonData map[string]interface{}) ([]byte, int, error) {
	// Create a new RequestHandler directly without type assertion
	handler := plextrac.NewRequestHandler("")

	// Set the access token
	if token, ok := p.Args["access_token"].(string); ok {
		handler.SetAccessToken(token)
	}

	// Make the request
	p.Logger.Debugf("Making POST request to %s", url)
	response, err := handler.Post(url, nil, nil, jsonData, nil, nil)
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

// RetrieveWriteupDetails fetches details for a specific writeup from the database
func (p *DescriptionProcessor) RetrieveWriteupDetails(writeupID string) map[string]interface{} {
	// Get URL for the writeup
	urlManager, ok := p.URLManager.(interface{ GetWriteupDBURL(string) string })
	if !ok {
		p.Logger.Error("URL manager does not implement GetWriteupDBURL method")
		return nil
	}

	url := urlManager.GetWriteupDBURL(writeupID)
	if url == "" {
		p.Logger.Errorf("Failed to get writeup URL for ID: %s", writeupID)
		return nil
	}

	// Use our wrapper function to make the request
	p.Logger.Debugf("Fetching writeup details for ID %s", writeupID)
	bodyBytes, statusCode, err := p.makeGetRequest(url)
	if err != nil {
		p.Logger.Errorf("Failed to retrieve writeup details: %v", err)
		return nil
	}

	// Check status code
	if statusCode != 200 {
		p.Logger.Errorf("Failed to retrieve writeup details: status code %d", statusCode)
		return nil
	}

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		p.Logger.Errorf("Failed to decode writeup details: %v", err)
		return nil
	}

	return result
}

// UpdateFlawDescription updates the description and recommendation of a flaw
func (p *DescriptionProcessor) UpdateFlawDescription(flawID string, description, recommendation, references string) bool {
	// Get GraphQL URL
	urlManager, ok := p.URLManager.(interface{ GetGraphqlURL() string })
	if !ok {
		p.Logger.Error("URL manager does not implement GetGraphqlURL method")
		return false
	}

	url := urlManager.GetGraphqlURL()
	if url == "" {
		p.Logger.Errorf("Failed to get GraphQL URL")
		return false
	}

	// Prepare the GraphQL payload
	clientID, _ := p.Args["client_id"].(string)
	reportID, _ := p.Args["report_id"].(string)

	// Convert string IDs to appropriate types for GraphQL
	clientIDInt, _ := strconv.Atoi(clientID)
	reportIDInt, _ := strconv.Atoi(reportID)
	flawIDFloat, _ := strconv.ParseFloat(flawID, 64)

	payload := map[string]interface{}{
		"operationName": "FindingUpdate",
		"variables": map[string]interface{}{
			"clientId": clientIDInt,
			"data": map[string]interface{}{
				"description":     description,
				"recommendations": recommendation,
				"references":      references,
			},
			"findingId": flawIDFloat,
			"reportId":  reportIDInt,
		},
		"query": `
        mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {
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
        }
        `,
	}

	// Log the variables for debugging
	variablesJSON, _ := json.MarshalIndent(payload["variables"], "", "  ")
	p.Logger.Debugf("GraphQL variables: %s", string(variablesJSON))

	// Use our wrapper function to make the request
	p.Logger.Debugf("Sending GraphQL request to update flaw ID %s", flawID)
	bodyBytes, statusCode, err := p.makePostRequest(url, payload)
	if err != nil {
		p.Logger.Warnf("Failed to update description for flaw ID %s: %v", flawID, err)
		return false
	}

	// Check status code
	if statusCode != 200 {
		p.Logger.Warnf("Failed to update description for flaw ID %s: status code %d, response: %s",
			flawID, statusCode, string(bodyBytes))
		return false
	}

	// Check for GraphQL errors in the response
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		p.Logger.Warnf("Failed to decode GraphQL response: %v", err)
		return false
	}

	errors, hasErrors := result["errors"].([]interface{})
	if hasErrors && len(errors) > 0 {
		p.Logger.Warnf("GraphQL returned errors for flaw ID %s: %v", flawID, errors)
		return false
	}

	p.Logger.Debugf("Update complete for flaw %s", flawID)
	return true
}

// GetTitlePrefix returns the appropriate title prefix based on the mode
func (p *DescriptionProcessor) GetTitlePrefix() string {
	prefixMap := map[string]string{
		"external":     "(External) ",
		"web":          "(Web) ",
		"surveillance": "(Surveillance) ",
		"mobile":       "(Mobile) ",
		"internal":     "",
	}

	prefix, ok := prefixMap[p.Mode]
	if !ok {
		return ""
	}
	return prefix
}

// Process updates the descriptions for all relevant flaws
func (p *DescriptionProcessor) Process() error {
	// Use type assertion with interface check
	var flaws []map[string]interface{}
	if fl, ok := p.FlawLister.(interface {
		ListFlaws() []map[string]interface{}
	}); ok {
		flaws = fl.ListFlaws()
	} else {
		p.Logger.Error("FlawLister does not implement ListFlaws method")
		return fmt.Errorf("flawLister does not implement ListFlaws method")
	}

	titlePrefix := p.GetTitlePrefix()

	p.Logger.Debugf("Found %d flaws to process", len(flaws))
	p.Logger.Debugf("Using title prefix: '%s'", titlePrefix)

	plugins, ok := p.Config["plugins"].(map[string]interface{})
	if !ok {
		p.Logger.Error("Plugins section not found in configuration")
		return fmt.Errorf("plugins section not found in configuration")
	}

	successCount := 0
	errorCount := 0
	skippedCount := 0

	for _, flaw := range flaws {
		flawName, ok := flaw["title"].(string)
		if !ok {
			p.Logger.Warnf("Flaw is missing title field")
			skippedCount++
			continue
		}

		p.Logger.Debugf("Processing flaw with title: %s", flawName)
		matchFound := false

		// Check if this flaw matches any category
		for categoryName, details := range plugins {
			categoryDetails, ok := details.(map[string]interface{})
			if !ok {
				p.Logger.Warnf("Category %s details are not in expected format", categoryName)
				continue
			}

			writeupName, ok := categoryDetails["writeup_name"].(string)
			if !ok {
				p.Logger.Warnf("Category %s is missing writeup_name", categoryName)
				continue
			}

			// Adjust writeup name with prefix
			adjustedWriteupName := titlePrefix + writeupName

			if flawName == adjustedWriteupName {
				matchFound = true
				p.Logger.Debugf("Found matching category %s for flaw %s", categoryName, flawName)

				// Found a match, retrieve writeup details
				writeupID, ok := categoryDetails["writeup_db_id"].(string)
				if !ok {
					p.Logger.Warnf("Category %s is missing writeup_db_id", categoryName)
					continue
				}

				writeupDetails := p.RetrieveWriteupDetails(writeupID)
				if writeupDetails == nil {
					p.Logger.Warnf("Failed to retrieve writeup details for ID %s", writeupID)
					errorCount++
					continue
				}

				// Extract details
				description, _ := writeupDetails["description"].(string)
				recommendation, _ := writeupDetails["recommendations"].(string)
				references, _ := writeupDetails["references"].(string)

				// Update the flaw
				flawID, ok := flaw["id"].(string)
				if !ok {
					// Try flaw_id if id is not available
					if flawID, ok = flaw["flaw_id"].(string); !ok {
						p.Logger.Warnf("Flaw is missing both id and flaw_id fields")
						skippedCount++
						continue
					}
				}

				p.Logger.Debugf("Updating flaw ID %s with writeup details", flawID)
				if p.UpdateFlawDescription(flawID, description, recommendation, references) {
					successCount++
					p.Logger.Infof("Successfully updated description for flaw ID %s", flawID)
				} else {
					errorCount++
					p.Logger.Warnf("Failed to update description for flaw ID %s", flawID)
				}

				break // Found a match, no need to check other categories
			}
		}

		if !matchFound {
			p.Logger.Debugf("No matching category found for flaw: %s", flawName)
			skippedCount++
		}
	}

	p.Logger.Infof("Description processing completed: %d successful, %d failed, %d skipped",
		successCount, errorCount, skippedCount)

	// Even if some updates failed, return success
	return nil
}
