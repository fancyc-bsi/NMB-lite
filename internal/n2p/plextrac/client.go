package plextrac

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	type_url "net/url" // Required for url.Values and url.Parse
	"strings"
	"time"
)

// Response wraps http.Response and provides utility methods
type Response struct {
	*http.Response
	StatusCode int
	body       []byte // Cache the body for multiple reads
	bodyRead   bool   // Flag to track if body has been read
}

// GetStatusCode returns the HTTP status code
func (r *Response) GetStatusCode() int {
	return r.StatusCode
}

// GetBody returns the raw response body as bytes
func (r *Response) GetBody() []byte {
	if r.bodyRead {
		return r.body
	}

	// Read the body if not already read
	defer r.Body.Close()
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return []byte(fmt.Sprintf("error reading response body: %v", err))
	}

	// Cache the body and reset the reader
	r.body = bodyBytes
	r.bodyRead = true
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	return bodyBytes
}

// DecodeJSON decodes the response body into the provided interface
func (r *Response) DecodeJSON(v interface{}) error {
	// Use GetBody to handle body caching
	bodyBytes := r.GetBody()

	// Debug the response JSON
	fmt.Printf("Response JSON: %s\n", string(bodyBytes))

	err := json.Unmarshal(bodyBytes, v)
	if err != nil {
		return fmt.Errorf("error unmarshaling JSON: %w", err)
	}
	return nil
}

// RequestHandler manages HTTP requests to the Plextrac API
type RequestHandler struct {
	client      *http.Client
	accessToken string
	headers     map[string]string
}

// NewRequestHandler creates a new RequestHandler
func NewRequestHandler(accessToken string) *RequestHandler {
	client := &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip SSL verification for development
			},
		},
	}
	return &RequestHandler{
		client:      client,
		accessToken: accessToken,
		headers:     make(map[string]string),
	}
}

// SetAccessToken sets the access token for authentication
func (h *RequestHandler) SetAccessToken(accessToken string) {
	h.accessToken = accessToken
}

// GetAccessToken returns the current access token
func (h *RequestHandler) GetAccessToken() string {
	return h.accessToken
}

// setHeaders sets up request headers
func (h *RequestHandler) setHeaders(headers map[string]string) {
	h.headers = make(map[string]string)
	for k, v := range headers {
		h.headers[k] = v
	}
	if h.accessToken != "" {
		h.headers["Authorization"] = h.accessToken
	}
}

// validateResponse checks if the response is valid
func (h *RequestHandler) validateResponse(resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("invalid response received")
	}
	return nil
}

// Get makes a GET request
func (h *RequestHandler) Get(url string, headers map[string]string, params map[string]interface{}) (*Response, error) {
	h.setHeaders(headers)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	// Add query parameters
	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, fmt.Sprintf("%v", v))
	}
	req.URL.RawQuery = q.Encode()

	// Make the request
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if err := h.validateResponse(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}

	return &Response{Response: resp, StatusCode: resp.StatusCode}, nil
}

func (h *RequestHandler) Post(url string, headers map[string]string, data map[string]interface{},
	jsonData map[string]interface{}, files map[string]interface{}, proxies map[string]string) (*Response, error) {
	h.setHeaders(headers)

	var body io.Reader
	var contentType string

	if files != nil {
		// Handle file uploads with multipart form
		var b bytes.Buffer
		w := multipart.NewWriter(&b)

		// fmt.Printf("Debug - Files map content: %+v\n", files)

		for k, v := range files {
			if file, ok := v.(map[string]interface{}); ok {
				fileName, _ := file["filename"].(string)
				fileContent, _ := file["content"].([]byte)

				fmt.Printf("Debug - Creating form file: %s\n", fileName)

				part, err := w.CreateFormFile(k, fileName)
				if err != nil {
					return nil, fmt.Errorf("failed to create form file: %w", err)
				}

				if _, err := part.Write(fileContent); err != nil {
					return nil, fmt.Errorf("failed to write file content: %w", err)
				}
			}
		}

		// Add any form fields
		if data != nil {
			for k, v := range data {
				if err := w.WriteField(k, fmt.Sprintf("%v", v)); err != nil {
					return nil, fmt.Errorf("failed to write form field: %w", err)
				}
			}
		}

		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("failed to close multipart writer: %w", err)
		}

		body = &b
		contentType = w.FormDataContentType()
		fmt.Printf("Debug - Content-Type: %s\n", contentType)
	} else if jsonData != nil {
		// Handle JSON data
		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON: %w", err)
		}

		fmt.Printf("Debug - JSON payload: %s\n", string(jsonBytes))
		body = bytes.NewBuffer(jsonBytes)
		contentType = "application/json"
	} else if data != nil {
		// Handle form data
		formValues := type_url.Values{}
		for k, v := range data {
			formValues.Add(k, fmt.Sprintf("%v", v))
		}

		body = strings.NewReader(formValues.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	// Create request
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	// Set content type if not already set
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Make the request
	fmt.Printf("Debug - Making POST request to %s\n", url)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if err := h.validateResponse(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}

	return &Response{Response: resp, StatusCode: resp.StatusCode}, nil
}

// Put makes a PUT request
func (h *RequestHandler) Put(url string, headers map[string]string, data map[string]interface{}, jsonData map[string]interface{}) (*Response, error) {
	h.setHeaders(headers)

	var body io.Reader
	var contentType string

	if jsonData != nil {
		// Handle JSON data
		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON: %w", err)
		}

		body = bytes.NewBuffer(jsonBytes)
		contentType = "application/json"
	} else if data != nil {
		// Handle form data
		formValues := type_url.Values{} // Using url.Values for form data
		for k, v := range data {
			formValues.Add(k, fmt.Sprintf("%v", v))
		}

		body = strings.NewReader(formValues.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	// Create request
	req, err := http.NewRequest("PUT", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	// Set content type if not already set
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Make the request
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if err := h.validateResponse(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}

	return &Response{Response: resp, StatusCode: resp.StatusCode}, nil
}

// Delete makes a DELETE request
func (h *RequestHandler) Delete(url string, headers map[string]string) (*Response, error) {
	h.setHeaders(headers)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	// Make the request
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if err := h.validateResponse(resp); err != nil {
		resp.Body.Close()
		return nil, err

	}

	return &Response{Response: resp, StatusCode: resp.StatusCode}, nil
}
