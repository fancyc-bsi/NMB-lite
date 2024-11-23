// internal/api/server.go
package api

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"NMB/internal/args"
	"NMB/internal/engine"
	websocket "NMB/internal/ws"
)

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

type Server struct {
	router    *gin.Engine
	wsManager *websocket.WebSocketManager
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
}

func (s *Server) handleScan(c *gin.Context) {
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

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in scan goroutine: %v", r)
			}
		}()
		engine.RunNMB(parsedArgs)
	}()

	c.JSON(http.StatusOK, gin.H{"message": "Scan started successfully"})
}

func (s *Server) handleGetSupportedPlugins(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Supported plugins retrieved successfully"})
}

func (s *Server) handleNessusController(c *gin.Context) {
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

	go func() {
		engine.HandleNessusController(parsedArgs)
	}()

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Nessus %s operation started", req.NessusMode)})
}

func (s *Server) Run() error {
	go s.wsManager.Start()
	log.Println("WebSocket manager started on :8080/ws")
	return s.router.Run(":8080")
}
