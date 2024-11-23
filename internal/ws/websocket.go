// internal/ws/websocket.go
package websocket

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

type LogMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Time    string `json:"time"`
}

type WebSocketManager struct {
	clients   map[*websocket.Conn]bool
	broadcast chan LogMessage
	mutex     sync.RWMutex
	writeMu   sync.Map // Per-connection write mutex
}

var (
	instance *WebSocketManager
	once     sync.Once
)

// GetInstance returns the singleton instance of WebSocketManager
func GetInstance() *WebSocketManager {
	once.Do(func() {
		instance = &WebSocketManager{
			clients:   make(map[*websocket.Conn]bool),
			broadcast: make(chan LogMessage, 100), // Buffered channel
		}
		go instance.Start()
	})
	return instance
}

func (wsm *WebSocketManager) Start() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case message := <-wsm.broadcast:
			wsm.mutex.RLock()
			for client := range wsm.clients {
				// Get or create a write mutex for this connection
				mutex, _ := wsm.writeMu.LoadOrStore(client, &sync.Mutex{})
				writeMu := mutex.(*sync.Mutex)

				// Safe write with mutex
				go func(c *websocket.Conn, msg LogMessage) {
					writeMu.Lock()
					defer writeMu.Unlock()

					if err := c.WriteJSON(msg); err != nil {
						log.Printf("Error writing to client: %v", err)
						wsm.RemoveClient(c)
					}
				}(client, message)
			}
			wsm.mutex.RUnlock()

		case <-ticker.C:
			wsm.mutex.RLock()
			for client := range wsm.clients {
				mutex, _ := wsm.writeMu.LoadOrStore(client, &sync.Mutex{})
				writeMu := mutex.(*sync.Mutex)

				go func(c *websocket.Conn) {
					writeMu.Lock()
					defer writeMu.Unlock()

					if err := c.WriteMessage(websocket.PingMessage, nil); err != nil {
						log.Printf("Error sending ping: %v", err)
						wsm.RemoveClient(c)
					}
				}(client)
			}
			wsm.mutex.RUnlock()
		}
	}
}

func (wsm *WebSocketManager) AddClient(conn *websocket.Conn) {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()

	wsm.clients[conn] = true
	log.Printf("Client added. Total clients: %d", len(wsm.clients))

	// Initialize write mutex for this connection
	wsm.writeMu.Store(conn, &sync.Mutex{})

	// Send initial message
	msg := LogMessage{
		Type:    "info",
		Message: "Connected to WebSocket server",
		Time:    time.Now().Format("2006/01/02 15:04:05"),
	}

	if mutex, ok := wsm.writeMu.Load(conn); ok {
		writeMu := mutex.(*sync.Mutex)
		writeMu.Lock()
		if err := conn.WriteJSON(msg); err != nil {
			log.Printf("Error sending initial message: %v", err)
		}
		writeMu.Unlock()
	}
}

func (wsm *WebSocketManager) RemoveClient(conn *websocket.Conn) {
	wsm.mutex.Lock()
	defer wsm.mutex.Unlock()

	if _, ok := wsm.clients[conn]; ok {
		conn.Close()
		delete(wsm.clients, conn)
		wsm.writeMu.Delete(conn) // Clean up the write mutex
		log.Printf("Client removed. Total clients: %d", len(wsm.clients))
	}
}

// cleanMessage removes ANSI color codes and other control sequences
func cleanMessage(message string) string {
	// Remove ANSI escape codes
	cleaned := ansiRegex.ReplaceAllString(message, "")

	// Remove any remaining control characters
	cleaned = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, cleaned)

	return strings.TrimSpace(cleaned)
}

func (wsm *WebSocketManager) BroadcastMessage(msgType, message string) {
	cleanedMessage := cleanMessage(message)

	log.Printf("Broadcasting message: %s - %s", msgType, cleanedMessage)
	wsm.broadcast <- LogMessage{
		Type:    msgType,
		Message: cleanedMessage,
		Time:    time.Now().Format("2006/01/02 15:04:05"),
	}
}
