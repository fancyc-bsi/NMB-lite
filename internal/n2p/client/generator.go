// Package client provides client and report generation functionality
package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// ClientReportGen generates clients and reports in Plextrac
type ClientReportGen struct {
	URLManager     interface{} // Avoid circular dependency with plextrac package
	RequestHandler interface{} // Avoid circular dependency with plextrac package
	Logger         *logrus.Logger
}

// NewClientReportGen creates a new ClientReportGen instance
func NewClientReportGen(urlManager, requestHandler interface{}) *ClientReportGen {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	return &ClientReportGen{
		URLManager:     urlManager,
		RequestHandler: requestHandler,
		Logger:         logger,
	}
}

// GetUserInput prompts the user for input and validates it
func (g *ClientReportGen) GetUserInput(promptMessage string, validatorType string) (string, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(promptMessage)
		userInput, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}

		userInput = strings.TrimSpace(userInput)

		if validatorType != "" {
			if err := g.SimpleValidator(userInput, validatorType); err != nil {
				g.Logger.Error(err)
				continue
			}
		}

		return userInput, nil
	}
}

// SimpleValidator validates user input based on the validator type
func (g *ClientReportGen) SimpleValidator(userInput, validatorType string) error {
	switch validatorType {
	case "sn_code", "ps_code", "eu_code", "project_code":
		// Accept any input for project codes
		if userInput == "" {
			return fmt.Errorf("project code cannot be empty")
		}
		return nil

	case "state_code":
		if !regexp.MustCompile(`^[a-zA-Z]{2}$`).MatchString(userInput) {
			return fmt.Errorf("invalid State code. It should be two letters.")
		}
		return nil

	case "client_name":
		if userInput == "" {
			return fmt.Errorf("client name cannot be empty")
		}
		return nil

	default:
		return nil
	}
}

// getIDFromValue extracts an ID as a string from different types of values
func getIDFromValue(val interface{}) (string, bool) {
	switch v := val.(type) {
	case string:
		return v, true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case float64:
		return strconv.FormatInt(int64(v), 10), true
	case json.Number:
		return v.String(), true
	}
	return "", false
}

// CreateClient creates a new client in Plextrac
func (g *ClientReportGen) CreateClient(clientName, projectCode, stateCode string) (string, error) {
	// Get URL for creating client
	urlManager, ok := g.URLManager.(interface{ GetClientCreateURL() string })
	if !ok {
		return "", fmt.Errorf("URL manager does not implement GetClientCreateURL method")
	}

	url := urlManager.GetClientCreateURL()
	if url == "" {
		return "", fmt.Errorf("failed to get client create URL")
	}

	// Format the client name with the project code
	formattedName := fmt.Sprintf("%s - %s - %s", projectCode, clientName, stateCode)
	g.Logger.Infof("Creating client with name: %s", formattedName)
	g.Logger.Infof("Sending request to URL: %s", url)

	// Prepare payload
	payload := map[string]interface{}{
		"name":        formattedName,
		"description": "",
		"poc":         "FIXME",
		"poc_email":   "email@FIXME.com",
	}

	// Debug payload
	payloadBytes, _ := json.Marshal(payload)
	g.Logger.Infof("Request payload: %s", string(payloadBytes))

	// Use reflection to call the Post method, avoiding interface type issues
	reqHandler := reflect.ValueOf(g.RequestHandler)
	postMethod := reqHandler.MethodByName("Post")

	if !postMethod.IsValid() {
		g.Logger.Errorf("Request handler type: %T", g.RequestHandler)
		return "", fmt.Errorf("request handler does not have a Post method")
	}

	// Call Post method with the correct arguments
	args := []reflect.Value{
		reflect.ValueOf(url),
		reflect.ValueOf(map[string]string{
			"Content-Type": "application/json",
		}),
		reflect.ValueOf(map[string]interface{}(nil)),
		reflect.ValueOf(payload),
		reflect.ValueOf(map[string]interface{}(nil)),
		reflect.ValueOf(map[string]string(nil)),
	}

	results := postMethod.Call(args)

	// Check for error
	if !results[1].IsNil() {
		err := results[1].Interface().(error)
		return "", fmt.Errorf("failed to create client: %w", err)
	}

	// Get the response object
	response := results[0].Interface()

	// Now use reflection to call methods on the response
	respValue := reflect.ValueOf(response)

	// Get status code
	getStatusCodeMethod := respValue.MethodByName("GetStatusCode")
	if !getStatusCodeMethod.IsValid() {
		return "", fmt.Errorf("response object does not have GetStatusCode method")
	}

	statusCodeValue := getStatusCodeMethod.Call(nil)[0]
	statusCode := int(statusCodeValue.Int())

	// Get body for debugging and error message
	getBodyMethod := respValue.MethodByName("GetBody")
	if !getBodyMethod.IsValid() {
		return "", fmt.Errorf("response object does not have GetBody method")
	}

	bodyBytes := getBodyMethod.Call(nil)[0].Interface().([]byte)
	bodyStr := string(bodyBytes)

	// Debug response
	g.Logger.Infof("Response status code: %d", statusCode)
	g.Logger.Infof("Response body: %s", bodyStr)

	if statusCode != 200 && statusCode != 201 { // Accept both 200 and 201 as success
		g.Logger.WithFields(logrus.Fields{
			"status_code": statusCode,
			"body":        bodyStr,
		}).Error("Failed to create client")

		return "", fmt.Errorf("failed to create client: status code %d, body: %s", statusCode, bodyStr)
	}

	// Decode JSON response
	decodeJSONMethod := respValue.MethodByName("DecodeJSON")
	if !decodeJSONMethod.IsValid() {
		return "", fmt.Errorf("response object does not have DecodeJSON method")
	}

	var result map[string]interface{}
	args = []reflect.Value{reflect.ValueOf(&result)}

	decodeResults := decodeJSONMethod.Call(args)
	if !decodeResults[0].IsNil() {
		err := decodeResults[0].Interface().(error)
		return "", fmt.Errorf("failed to decode client creation response: %w", err)
	}

	// Debug the decoded result
	resultBytes, _ := json.Marshal(result)
	g.Logger.Infof("Decoded result: %s", string(resultBytes))

	// Look for client_id in different keys and handle various types
	var clientID string
	var idFound bool

	for _, key := range []string{"client_id", "id", "clientId"} {
		if val, ok := result[key]; ok {
			clientID, idFound = getIDFromValue(val)
			if idFound {
				g.Logger.Infof("Found client ID in field '%s': %s", key, clientID)
				break
			}
		}
	}

	if !idFound {
		// Try looking inside a data object if it exists
		if data, ok := result["data"].(map[string]interface{}); ok {
			for _, key := range []string{"client_id", "id", "clientId"} {
				if val, ok := data[key]; ok {
					clientID, idFound = getIDFromValue(val)
					if idFound {
						g.Logger.Infof("Found client ID in data.%s: %s", key, clientID)
						break
					}
				}
			}
		}
	}

	// Log all keys in the result to help with debugging
	g.Logger.Info("All keys in the response:")
	for k := range result {
		g.Logger.Infof("Key: %s", k)
	}

	if !idFound || clientID == "" {
		return "", fmt.Errorf("client ID not found in response")
	}

	g.Logger.Info("Client created successfully")
	return clientID, nil
}

// ParseTemplates parses templates from the API response
func (g *ClientReportGen) ParseTemplates(responseContent []interface{}) ([]map[string]string, error) {
	templates := make([]map[string]string, 0, len(responseContent))

	for _, template := range responseContent {
		templateMap, ok := template.(map[string]interface{})
		if !ok {
			continue
		}

		data, ok := templateMap["data"].(map[string]interface{})
		if !ok {
			continue
		}

		templateName, ok := data["template_name"].(string)
		if !ok {
			continue
		}

		docID, ok := data["doc_id"].(string)
		if !ok {
			continue
		}

		templates = append(templates, map[string]string{
			"name":  templateName,
			"value": docID,
		})
	}

	for i := 0; i < len(templates)-1; i++ {
		for j := 0; j < len(templates)-i-1; j++ {
			if templates[j]["name"] > templates[j+1]["name"] {
				templates[j], templates[j+1] = templates[j+1], templates[j]
			}
		}
	}

	return templates, nil
}

// SelectOption presents a list of options and returns the user's choice
func (g *ClientReportGen) SelectOption(options []map[string]string, message string) (string, error) {
	fmt.Println(message)
	for i, option := range options {
		fmt.Printf("%d. %s\n", i+1, option["name"])
	}

	for {
		input, err := g.GetUserInput("Enter your choice (number): ", "")
		if err != nil {
			return "", err
		}

		var choice int
		if _, err := fmt.Sscanf(input, "%d", &choice); err != nil {
			g.Logger.Error("Invalid choice. Please enter a number.")
			continue
		}

		if choice < 1 || choice > len(options) {
			g.Logger.Error("Invalid choice. Please enter a number from the list.")
			continue
		}

		return options[choice-1]["value"], nil
	}
}

// GatherInfo gathers information for report creation
func (g *ClientReportGen) GatherInfo() (string, string, string, string, error) {
	// Get report templates
	urlManager, ok := g.URLManager.(interface{ GetReportTemplateURL() string })
	if !ok {
		return "", "", "", "", fmt.Errorf("URL manager does not implement GetReportTemplateURL method")
	}

	url := urlManager.GetReportTemplateURL()
	if url == "" {
		return "", "", "", "", fmt.Errorf("failed to get report template URL")
	}

	g.Logger.Infof("Getting report templates from URL: %s", url)

	// Use reflection to call the Get method
	reqHandler := reflect.ValueOf(g.RequestHandler)
	getMethod := reqHandler.MethodByName("Get")

	if !getMethod.IsValid() {
		return "", "", "", "", fmt.Errorf("request handler does not have a Get method")
	}

	// Call Get method with the correct arguments
	args := []reflect.Value{
		reflect.ValueOf(url),
		reflect.ValueOf(map[string]string(nil)),
		reflect.ValueOf(map[string]interface{}(nil)),
	}

	results := getMethod.Call(args)

	// Check for error
	if !results[1].IsNil() {
		err := results[1].Interface().(error)
		return "", "", "", "", fmt.Errorf("failed to get report templates: %w", err)
	}

	// Get the response object
	response := results[0].Interface()
	respValue := reflect.ValueOf(response)

	// Get status code
	getStatusCodeMethod := respValue.MethodByName("GetStatusCode")
	if !getStatusCodeMethod.IsValid() {
		return "", "", "", "", fmt.Errorf("response object does not have GetStatusCode method")
	}

	statusCodeValue := getStatusCodeMethod.Call(nil)[0]
	statusCode := int(statusCodeValue.Int())

	// Get body for debugging
	getBodyMethod := respValue.MethodByName("GetBody")
	if !getBodyMethod.IsValid() {
		return "", "", "", "", fmt.Errorf("response object does not have GetBody method")
	}

	bodyBytes := getBodyMethod.Call(nil)[0].Interface().([]byte)
	g.Logger.Infof("Report templates response: %s", string(bodyBytes))

	if statusCode != 200 {
		return "", "", "", "", fmt.Errorf("failed to get report templates: status code %d", statusCode)
	}

	// Decode JSON response
	decodeJSONMethod := respValue.MethodByName("DecodeJSON")
	if !decodeJSONMethod.IsValid() {
		return "", "", "", "", fmt.Errorf("response object does not have DecodeJSON method")
	}

	var reportTemplatesResponse []interface{}
	decodeArgs := []reflect.Value{reflect.ValueOf(&reportTemplatesResponse)}

	decodeResults := decodeJSONMethod.Call(decodeArgs)
	if !decodeResults[0].IsNil() {
		err := decodeResults[0].Interface().(error)
		return "", "", "", "", fmt.Errorf("failed to decode report templates response: %w", err)
	}

	reportTemplates, err := g.ParseTemplates(reportTemplatesResponse)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse report templates: %w", err)
	}

	g.Logger.Infof("Found %d report templates", len(reportTemplates))

	// Get field templates
	urlManager2, ok := g.URLManager.(interface{ GetFieldTemplateURL() string })
	if !ok {
		return "", "", "", "", fmt.Errorf("URL manager does not implement GetFieldTemplateURL method")
	}

	url2 := urlManager2.GetFieldTemplateURL()
	if url2 == "" {
		return "", "", "", "", fmt.Errorf("failed to get field template URL")
	}

	g.Logger.Infof("Getting field templates from URL: %s", url2)

	// Get field templates using reflection
	args = []reflect.Value{
		reflect.ValueOf(url2),
		reflect.ValueOf(map[string]string(nil)),
		reflect.ValueOf(map[string]interface{}(nil)),
	}

	results = getMethod.Call(args)

	// Check for error
	if !results[1].IsNil() {
		err := results[1].Interface().(error)
		return "", "", "", "", fmt.Errorf("failed to get field templates: %w", err)
	}

	// Get the response object
	response2 := results[0].Interface()
	respValue2 := reflect.ValueOf(response2)

	// Get status code
	statusCodeValue = respValue2.MethodByName("GetStatusCode").Call(nil)[0]
	statusCode = int(statusCodeValue.Int())

	// Get body for debugging
	bodyBytes = respValue2.MethodByName("GetBody").Call(nil)[0].Interface().([]byte)
	g.Logger.Infof("Field templates response: %s", string(bodyBytes))

	if statusCode != 200 {
		return "", "", "", "", fmt.Errorf("failed to get field templates: status code %d", statusCode)
	}

	// Decode JSON response
	var fieldTemplatesResponse []interface{}
	decodeArgs = []reflect.Value{reflect.ValueOf(&fieldTemplatesResponse)}

	decodeResults = respValue2.MethodByName("DecodeJSON").Call(decodeArgs)
	if !decodeResults[0].IsNil() {
		err := decodeResults[0].Interface().(error)
		return "", "", "", "", fmt.Errorf("failed to decode field templates response: %w", err)
	}

	customFieldTemplates, err := g.ParseTemplates(fieldTemplatesResponse)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse field templates: %w", err)
	}

	g.Logger.Infof("Found %d field templates", len(customFieldTemplates))

	// Add a "None" option for custom fields
	customFieldTemplates = append(customFieldTemplates, map[string]string{
		"name":  "None",
		"value": "",
	})

	// Select templates
	reportTemplate, err := g.SelectOption(reportTemplates, "Select a report template:")
	if err != nil {
		return "", "", "", "", err
	}

	customFieldTemplate, err := g.SelectOption(customFieldTemplates, "Select a custom field template:")
	if err != nil {
		return "", "", "", "", err
	}

	// Get template names
	var reportTemplateName, customFieldTemplateName string
	for _, template := range reportTemplates {
		if template["value"] == reportTemplate {
			reportTemplateName = template["name"]
			break
		}
	}

	for _, template := range customFieldTemplates {
		if template["value"] == customFieldTemplate {
			customFieldTemplateName = template["name"]
			break
		}
	}

	return reportTemplate, customFieldTemplate, reportTemplateName, customFieldTemplateName, nil
}

// CreateReport creates a new report for a client
func (g *ClientReportGen) CreateReport(reportName, clientID, reportTemplate, customFieldTemplate string) (string, error) {
	// Get URL for creating report
	urlManager, ok := g.URLManager.(interface{ GetReportCreateURL(string) string })
	if !ok {
		return "", fmt.Errorf("URL manager does not implement GetReportCreateURL method")
	}

	url := urlManager.GetReportCreateURL(clientID)
	if url == "" {
		return "", fmt.Errorf("failed to get report create URL")
	}

	g.Logger.Infof("Creating report at URL: %s", url)

	// Prepare payload
	payload := map[string]interface{}{
		"name":            reportName,
		"status":          "Draft",
		"template":        reportTemplate,
		"fields_template": customFieldTemplate,
		"start_date":      "",
		"end_date":        "",
	}

	// Debug payload
	payloadBytes, _ := json.Marshal(payload)
	g.Logger.Infof("Report creation payload: %s", string(payloadBytes))

	// Use reflection to call the Post method
	reqHandler := reflect.ValueOf(g.RequestHandler)
	postMethod := reqHandler.MethodByName("Post")

	if !postMethod.IsValid() {
		g.Logger.Errorf("Request handler type: %T", g.RequestHandler)
		return "", fmt.Errorf("request handler does not have a Post method")
	}

	// Call Post method with the correct arguments
	args := []reflect.Value{
		reflect.ValueOf(url),
		reflect.ValueOf(map[string]string{
			"Content-Type": "application/json",
		}),
		reflect.ValueOf(map[string]interface{}(nil)),
		reflect.ValueOf(payload),
		reflect.ValueOf(map[string]interface{}(nil)),
		reflect.ValueOf(map[string]string(nil)),
	}

	results := postMethod.Call(args)

	// Check for error
	if !results[1].IsNil() {
		err := results[1].Interface().(error)
		return "", fmt.Errorf("failed to create report: %w", err)
	}

	// Get the response object
	response := results[0].Interface()
	respValue := reflect.ValueOf(response)

	// Get status code
	getStatusCodeMethod := respValue.MethodByName("GetStatusCode")
	if !getStatusCodeMethod.IsValid() {
		return "", fmt.Errorf("response object does not have GetStatusCode method")
	}

	statusCodeValue := getStatusCodeMethod.Call(nil)[0]
	statusCode := int(statusCodeValue.Int())

	// Get body for debugging and error message
	getBodyMethod := respValue.MethodByName("GetBody")
	if !getBodyMethod.IsValid() {
		return "", fmt.Errorf("failed to create report: status code %d", statusCode)
	}

	bodyBytes := getBodyMethod.Call(nil)[0].Interface().([]byte)
	bodyStr := string(bodyBytes)

	// Debug response
	g.Logger.Infof("Report creation response status code: %d", statusCode)
	g.Logger.Infof("Report creation response body: %s", bodyStr)

	if statusCode != 200 && statusCode != 201 { // Accept both 200 and 201 as success
		g.Logger.WithFields(logrus.Fields{
			"status_code": statusCode,
			"body":        bodyStr,
		}).Error("Failed to create report")

		return "", fmt.Errorf("failed to create report: status code %d, body: %s", statusCode, bodyStr)
	}

	// Decode JSON response
	decodeJSONMethod := respValue.MethodByName("DecodeJSON")
	if !decodeJSONMethod.IsValid() {
		return "", fmt.Errorf("response object does not have DecodeJSON method")
	}

	var result map[string]interface{}
	decodeArgs := []reflect.Value{reflect.ValueOf(&result)}

	decodeResults := decodeJSONMethod.Call(decodeArgs)
	if !decodeResults[0].IsNil() {
		err := decodeResults[0].Interface().(error)
		return "", fmt.Errorf("failed to decode report creation response: %w", err)
	}

	// Debug the decoded result
	resultBytes, _ := json.Marshal(result)
	g.Logger.Infof("Decoded report result: %s", string(resultBytes))

	// Look for report_id in different keys and handle various types
	var reportID string
	var idFound bool

	for _, key := range []string{"report_id", "id", "reportId"} {
		if val, ok := result[key]; ok {
			reportID, idFound = getIDFromValue(val)
			if idFound {
				g.Logger.Infof("Found report ID in field '%s': %s", key, reportID)
				break
			}
		}
	}

	if !idFound {
		// Try looking inside a data object if it exists
		if data, ok := result["data"].(map[string]interface{}); ok {
			for _, key := range []string{"report_id", "id", "reportId"} {
				if val, ok := data[key]; ok {
					reportID, idFound = getIDFromValue(val)
					if idFound {
						g.Logger.Infof("Found report ID in data.%s: %s", key, reportID)
						break
					}
				}
			}
		}
	}

	// Log all keys in the result to help with debugging
	g.Logger.Info("All keys in the report response:")
	for k := range result {
		g.Logger.Infof("Key: %s", k)
	}

	if !idFound || reportID == "" {
		return "", fmt.Errorf("report ID not found in response")
	}

	g.Logger.Info("Report created successfully")
	return reportID, nil
}

// WriteOutputToFile writes the client and report IDs to a file
func (g *ClientReportGen) WriteOutputToFile(filePath, clientID, reportID string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := fmt.Fprintf(file, "Client ID: %s\nReport ID: %s\n", clientID, reportID); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

// Run executes the report generation process
func (g *ClientReportGen) Run() error {
	reportTemplate, customFieldTemplate, reportTemplateName, customFieldTemplateName, err := g.GatherInfo()
	if err != nil {
		return fmt.Errorf("failed to gather information: %w", err)
	}

	// Get client information
	var projectCode string

	// Accept any format for project code, no validation needed
	projectCode, err = g.GetUserInput("Enter the project code: ", "project_code")
	if err != nil {
		return fmt.Errorf("failed to get project code: %w", err)
	}
	projectCode = strings.ToUpper(projectCode)

	stateCode, err := g.GetUserInput("Enter the State code: ", "state_code")
	if err != nil {
		return fmt.Errorf("failed to get state code: %w", err)
	}
	stateCode = strings.ToUpper(stateCode)

	clientName, err := g.GetUserInput("Enter the name of the client: ", "client_name")
	if err != nil {
		return fmt.Errorf("failed to get client name: %w", err)
	}

	// Create client
	clientID, err := g.CreateClient(clientName, projectCode, stateCode)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Formulate report name
	reportName := fmt.Sprintf("%s-%s-%s-Cybersecurity_Assessment-Draft-v1.0", projectCode, clientName, stateCode)

	// Create report
	reportID, err := g.CreateReport(reportName, clientID, reportTemplate, customFieldTemplate)
	if err != nil {
		return fmt.Errorf("failed to create report: %w", err)
	}

	// Print information
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println("Client ID: ", clientID)
	fmt.Println("Report ID: ", reportID)
	fmt.Println("Report Template: ", reportTemplateName)
	fmt.Println("Custom Field Template: ", customFieldTemplateName)
	fmt.Println("Report Name: ", reportName)
	fmt.Println(strings.Repeat("-", 50))

	// Write to file
	outputFilePath := "report_info.txt"
	if err := g.WriteOutputToFile(outputFilePath, clientID, reportID); err != nil {
		return fmt.Errorf("failed to write output to file: %w", err)
	}

	return nil
}
