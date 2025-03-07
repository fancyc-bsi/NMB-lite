// internal/api/server.go
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"NMB/internal/args"
	"NMB/internal/crash"
	"NMB/internal/engine"
	"NMB/internal/nessus-controller"
	websocket "NMB/internal/ws"
)

// Maintain a cache of active sessions to prevent multiple authentications
type NessusSessionCache struct {
	sessions map[string]*nessus.Nessus
	mutex    sync.RWMutex
	timeout  time.Duration
}

var sessionCache = &NessusSessionCache{
	sessions: make(map[string]*nessus.Nessus),
	timeout:  15 * time.Minute, // Sessions last 15 minutes
}

// GetSession gets or creates a Nessus session
func (c *NessusSessionCache) GetSession(host, user, pass string) (*nessus.Nessus, error) {
	sessionKey := fmt.Sprintf("%s:%s", host, user)

	// Try to get session from cache
	c.mutex.RLock()
	session, exists := c.sessions[sessionKey]
	c.mutex.RUnlock()

	if exists {
		// Session found in cache
		return session, nil
	}

	// Create new session
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check again in case another goroutine created the session while we were waiting
	session, exists = c.sessions[sessionKey]
	if exists {
		return session, nil
	}

	// Create a new session
	newSession, err := nessus.New(host, user, pass, "", "", nil, false)
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.sessions[sessionKey] = newSession

	// Start a timeout goroutine to remove the session after the timeout
	go func() {
		time.Sleep(c.timeout)
		c.mutex.Lock()
		delete(c.sessions, sessionKey)
		c.mutex.Unlock()
	}()

	return newSession, nil
}

type ScanRequest struct {
	NessusFilePath string `json:"nessusFilePath"`
	ProjectFolder  string `json:"projectFolder"`
	RemoteHost     string `json:"remoteHost,omitempty"`
	RemoteUser     string `json:"remoteUser,omitempty"`
	RemotePass     string `json:"remotePass,omitempty"`
	RemoteKey      string `json:"remoteKey,omitempty"`
	NumWorkers     int    `json:"numWorkers"`
	ConfigFilePath string `json:"configFilePath,omitempty"`
	ExcludeFile    string `json:"excludeFile,omitempty"`
	NessusMode     string `json:"nessusMode,omitempty"`
	TargetsFile    string `json:"targetsFile,omitempty"`
	ProjectName    string `json:"projectName,omitempty"`
	Discovery      bool   `json:"discovery"`
}

type Settings struct {
	DefaultProjectFolder string  `json:"defaultProjectFolder"`
	SSHKeyFile           string  `json:"sshKeyFile"`
	MaxWorkers           int     `json:"maxWorkers"`
	AutoStart            bool    `json:"autoStart"`
	Telemetry            bool    `json:"telemetry"`
	Drones               []Drone `json:"drones"`
}

type Drone struct {
	Name string `json:"name"`
	Host string `json:"host"`
	User string `json:"user"`
}

type Server struct {
	router    *gin.Engine
	wsManager *websocket.WebSocketManager
}

// New Scan structure for responses - removed Findings field
type ScanDetail struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Status         string                 `json:"status"`
	Progress       float64                `json:"progress"`
	Targets        string                 `json:"targets"`
	CreatedAt      string                 `json:"createdAt"`
	CompletedAt    string                 `json:"completedAt,omitempty"`
	Owner          string                 `json:"owner"`
	AdditionalData map[string]interface{} `json:"additionalData,omitempty"`
}

func NewServer() *Server {
	router := gin.Default()
	wsManager := websocket.GetInstance()

	// Configure CORS with WebSocket support
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // For development. In production, specify exact origin
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "Sec-WebSocket-Protocol", "Sec-WebSocket-Version", "Sec-WebSocket-Key"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	server := &Server{
		router:    router,
		wsManager: wsManager,
	}

	server.setupRoutes()
	return server
}

func (s *Server) handleWebSocket(c *gin.Context) {
	log.Println("WebSocket connection attempt received")

	// Set required headers
	c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
	c.Header("Access-Control-Allow-Credentials", "true")

	conn, err := websocket.Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}

	// Set read deadline for initial connection
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	// Configure the connection
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Add the client to the manager
	wsManager := websocket.GetInstance()
	wsManager.AddClient(conn)

	defer func() {
		wsManager.RemoveClient(conn)
		log.Println("WebSocket connection closed")
	}()

	// Keep connection alive and handle messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseNormalClosure,
				websocket.CloseGoingAway,
				websocket.CloseNoStatusReceived) {
				log.Printf("Unexpected close error: %v", err)
			}
			return
		}

		// Handle different message types
		switch messageType {
		case websocket.PingMessage:
			if err := conn.WriteControl(websocket.PongMessage, nil, time.Now().Add(10*time.Second)); err != nil {
				log.Printf("Error sending pong: %v", err)
				return
			}
		case websocket.TextMessage:
			if string(message) == "ping" {
				// Handle ping from client
				if err := conn.WriteControl(websocket.PongMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					log.Printf("Error sending pong response: %v", err)
					return
				}
			} else {
				log.Printf("Received text message: %s", string(message))
			}
		}

		// Reset read deadline after successful message
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
}

func (s *Server) setupRoutes() {
	s.router.GET("/ws", s.handleWebSocket)
	s.router.POST("/api/scan", s.handleScan)
	s.router.GET("/api/supported-plugins", s.handleGetSupportedPlugins)
	s.router.POST("/api/nessus-controller", s.handleNessusController)
	s.router.GET("/api/settings", s.handleGetSettings)
	s.router.POST("/api/settings", s.handleSaveSettings)

	// New Nessus endpoints
	s.router.GET("/api/nessus/scans", s.handleGetNessusScans)
	s.router.GET("/api/nessus/scan/:id", s.handleGetNessusScanDetail)
	s.router.POST("/api/nessus/scan/:id/:action", s.handleNessusScanAction)
}

// Get all Nessus scans
func (s *Server) handleGetNessusScans(c *gin.Context) {
	remoteHost := c.DefaultQuery("host", "")
	remoteUser := c.DefaultQuery("user", "bstg")
	remotePass := c.DefaultQuery("pass", "BulletH@x")

	if remoteHost == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host parameter is required"})
		return
	}

	// Use the session cache to get a Nessus session
	nessusSession, err := sessionCache.GetSession(remoteHost, remoteUser, remotePass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to authenticate with Nessus: %v", err)})
		return
	}

	// Get raw scans
	rawScans, err := s.getNessusScans(nessusSession)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get scans: %v", err)})
		return
	}

	// Process scans to include additional information
	scans := s.processScans(rawScans, remoteHost, remoteUser)

	c.JSON(http.StatusOK, gin.H{"scans": scans})

	// Send the initial scan list via WebSocket as well
	s.broadcastScansUpdate(scans)
}

// Process scans to add additional information - without findings
func (s *Server) processScans(rawScans []map[string]interface{}, host, user string) []ScanDetail {
	var scans []ScanDetail

	for _, scan := range rawScans {
		// Basic info
		id := fmt.Sprintf("%v", scan["id"])
		name := fmt.Sprintf("%v", scan["name"])
		status := fmt.Sprintf("%v", scan["status"])

		// Parse progress
		var progress float64
		if p, ok := scan["progress"].(float64); ok {
			progress = p
		}

		// Parse creation time
		createdAt := "Unknown"
		if ts, ok := scan["creation_date"].(float64); ok {
			createdAt = time.Unix(int64(ts), 0).Format("2006-01-02 15:04:05")
		}

		// Parse completion time (if available)
		completedAt := ""
		if ts, ok := scan["last_modification_date"].(float64); ok && (status == "completed" || status == "failed" || status == "canceled") {
			completedAt = time.Unix(int64(ts), 0).Format("2006-01-02 15:04:05")
		}

		// Parse targets (may need extraction from scan details)
		targets := "Multiple targets"
		if t, ok := scan["targets"].(string); ok && t != "" {
			targets = t
		}

		scanDetail := ScanDetail{
			ID:          id,
			Name:        name,
			Status:      status,
			Progress:    progress,
			Targets:     targets,
			CreatedAt:   createdAt,
			CompletedAt: completedAt,
			Owner:       user,
		}

		scans = append(scans, scanDetail)
	}

	return scans
}

func (s *Server) getNessusScans(n *nessus.Nessus) ([]map[string]interface{}, error) {
	// Use the exported GetScans method instead of directly calling makeRequest
	return n.GetScans()
}

// Handle actions on a specific scan
func (s *Server) handleNessusScanAction(c *gin.Context) {
	scanID := c.Param("id")
	action := c.Param("action")
	remoteHost := c.DefaultQuery("host", "")
	remoteUser := c.DefaultQuery("user", "bstg")
	remotePass := c.DefaultQuery("pass", "BulletH@x")

	if remoteHost == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host parameter is required"})
		return
	}

	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan ID is required"})
		return
	}

	// Validate action
	validActions := map[string]bool{
		"start":  true,
		"stop":   true,
		"pause":  true,
		"resume": true,
		"export": true,
		"delete": true,
	}

	if !validActions[action] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("invalid action: %s, must be one of start, stop, pause, resume, export, delete", action),
		})
		return
	}

	// Use the session cache to get a Nessus session
	nessusSession, err := sessionCache.GetSession(remoteHost, remoteUser, remotePass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to authenticate with Nessus: %v", err)})
		return
	}

	if action == "delete" {
		// Use exported DeleteScan method
		if err := nessusSession.DeleteScan(scanID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete scan: %v", err)})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Scan deleted successfully"})
		return
	}

	if action == "export" {
		// Use exported ExportScanByID method
		c.JSON(http.StatusOK, gin.H{"message": "Export started, files will be available in the evidence folder"})

		// Start export in background
		go func() {
			if err := nessusSession.ExportScanByID(scanID); err != nil {
				log.Printf("Export error: %v", err)
				s.wsManager.BroadcastMessage("error", fmt.Sprintf("Export failed: %v", err))
			} else {
				s.wsManager.BroadcastMessage("success", "Export completed successfully")
			}
		}()

		return
	}

	// For other actions (start, stop, pause, resume)
	// Use exported ExecuteScanAction method
	if err := nessusSession.ExecuteScanAction(scanID, action); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to %s scan: %v", action, err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Scan %s operation successful", action)})

	// Broadcast update to connected clients
	s.wsManager.BroadcastMessage("info", fmt.Sprintf("Scan %s operation started for scan ID %s", action, scanID))

	// Start background scan status monitoring if needed
	if action == "start" || action == "resume" {
		go s.monitorScanProgress(nessusSession, scanID, remoteHost, remoteUser, remotePass)
	}
}

// Get detailed information about a specific scan
func (s *Server) handleGetNessusScanDetail(c *gin.Context) {
	scanID := c.Param("id")
	remoteHost := c.DefaultQuery("host", "")
	remoteUser := c.DefaultQuery("user", "bstg")
	remotePass := c.DefaultQuery("pass", "BulletH@x")

	if remoteHost == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host parameter is required"})
		return
	}

	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan ID is required"})
		return
	}

	// Use the session cache to get a Nessus session
	nessusSession, err := sessionCache.GetSession(remoteHost, remoteUser, remotePass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to authenticate with Nessus: %v", err)})
		return
	}

	// Use exported GetScanDetails method
	result, err := nessusSession.GetScanDetails(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get scan details: %v", err)})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Monitor scan progress in background
func (s *Server) monitorScanProgress(n *nessus.Nessus, scanID, host, user, pass string) {
	// Create a crash reporter
	reporter := crash.NewReporter("crash_reports")

	// Add extra information for crash reports
	extra := map[string]string{
		"scanID": scanID,
		"host":   host,
		"user":   user,
	}

	// Recover from panics with crash reporting
	defer reporter.RecoverWithCrashReport("ScanProgressMonitor", extra)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Use the session cache to get a Nessus session instead of creating a new one each time
			nessusSession, err := sessionCache.GetSession(host, user, pass)
			if err != nil {
				s.wsManager.BroadcastMessage("error", fmt.Sprintf("Failed to connect to Nessus: %v", err))
				return
			}

			// Get scan status using exported method
			result, err := nessusSession.GetScanDetails(scanID)
			if err != nil {
				s.wsManager.BroadcastMessage("error", fmt.Sprintf("Failed to get scan status: %v", err))
				return
			}

			// Extract status info
			info, ok := result["info"].(map[string]interface{})
			if !ok {
				continue
			}

			status, _ := info["status"].(string)
			progress, _ := info["progress"].(float64)

			// Broadcast status update via WebSocket
			s.wsManager.BroadcastMessage("scan_update", fmt.Sprintf("Scan %s: %s - %.0f%% complete", scanID, status, progress))

			// If scan is no longer running, stop monitoring
			if status == "completed" || status == "canceled" || status == "stopped" || status == "failed" {
				s.wsManager.BroadcastMessage("scan_complete", fmt.Sprintf("Scan %s %s", scanID, status))

				// Get all scans and broadcast updated list
				rawScans, err := nessusSession.GetScans()
				if err == nil {
					scans := s.processScans(rawScans, host, user)
					s.broadcastScansUpdate(scans)
				}
				return
			}
		}
	}
}

// Broadcast scan list updates via WebSocket
func (s *Server) broadcastScansUpdate(scans []ScanDetail) {
	// Convert scan list to JSON
	scanData, err := json.Marshal(scans)
	if err != nil {
		log.Printf("Failed to marshal scan data: %v", err)
		return
	}

	s.wsManager.BroadcastMessage("scans_list", string(scanData))
}

func (s *Server) handleGetSettings(c *gin.Context) {
	settings := Settings{
		DefaultProjectFolder: "/evidence",
		MaxWorkers:           4,
		AutoStart:            true,
	}

	c.JSON(http.StatusOK, settings)
}

func (s *Server) handleSaveSettings(c *gin.Context) {
	var settings Settings
	if err := c.BindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Settings saved successfully"})
}

func (s *Server) handleScan(c *gin.Context) {
	// Create a crash reporter
	reporter := crash.NewReporter("crash_reports")

	var req ScanRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if req.NessusFilePath == "" || req.ProjectFolder == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "nessusFilePath and projectFolder are required"})
		return
	}

	// Convert request to args
	parsedArgs := &args.Args{
		NessusFilePath: req.NessusFilePath,
		ProjectFolder:  req.ProjectFolder,
		RemoteHost:     req.RemoteHost,
		RemoteUser:     req.RemoteUser,
		RemotePass:     req.RemotePass,
		RemoteKey:      req.RemoteKey,
		NumWorkers:     req.NumWorkers,
		ConfigFilePath: req.ConfigFilePath,
		ExcludeFile:    req.ExcludeFile,
	}

	// Add extra information for crash reports
	extra := map[string]string{
		"nessusFilePath": req.NessusFilePath,
		"projectFolder":  req.ProjectFolder,
		"host":           req.RemoteHost,
		"clientIP":       c.ClientIP(),
	}

	go func() {
		// Enhanced panic recovery with crash reporting
		defer reporter.RecoverWithCrashReport("Scan", extra)

		engine.RunNMB(parsedArgs)
	}()

	c.JSON(http.StatusOK, gin.H{"message": "Scan started successfully"})
}

func (s *Server) handleGetSupportedPlugins(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Supported plugins retrieved successfully"})
}

func (s *Server) handleNessusController(c *gin.Context) {
	// Create a crash reporter
	reporter := crash.NewReporter("crash_reports")

	var req ScanRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	parsedArgs := &args.Args{
		NessusMode:  req.NessusMode,
		RemoteHost:  req.RemoteHost,
		RemoteUser:  req.RemoteUser,
		RemotePass:  req.RemotePass,
		ProjectName: req.ProjectName,
		TargetsFile: req.TargetsFile,
		ExcludeFile: req.ExcludeFile,
		Discovery:   req.Discovery,
	}

	// Add extra information for crash reports
	extra := map[string]string{
		"mode":     req.NessusMode,
		"host":     req.RemoteHost,
		"user":     req.RemoteUser,
		"project":  req.ProjectName,
		"targets":  req.TargetsFile,
		"clientIP": c.ClientIP(),
	}

	go func() {
		// Add panic recovery with crash reporting
		defer reporter.RecoverWithCrashReport("NessusController", extra)

		engine.HandleNessusController(parsedArgs)
	}()

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Nessus %s operation started", req.NessusMode)})
}
func (s *Server) Run() error {
	go s.wsManager.Start()
	log.Println("WebSocket manager started on :8080/ws")
	return s.router.Run(":8080")
}
