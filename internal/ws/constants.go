// internal/ws/constants.go
package websocket

import (
	"github.com/gorilla/websocket"
)

// Message type constants
const (
	// TextMessage denotes a text data message
	TextMessage = websocket.TextMessage
	// BinaryMessage denotes a binary data message
	BinaryMessage = websocket.BinaryMessage
	// CloseMessage denotes a close control message
	CloseMessage = websocket.CloseMessage
	// PingMessage denotes a ping control message
	PingMessage = websocket.PingMessage
	// PongMessage denotes a pong control message
	PongMessage = websocket.PongMessage
)

// WebSocket close codes
const (
	CloseNormalClosure    = websocket.CloseNormalClosure
	CloseGoingAway        = websocket.CloseGoingAway
	CloseError            = websocket.CloseInternalServerErr
	CloseNoStatusReceived = websocket.CloseNoStatusReceived
)

// IsUnexpectedCloseError returns true if the error is a websocket closing
// error but not one of the expected ones provided in the valid close codes
func IsUnexpectedCloseError(err error, codes ...int) bool {
	return websocket.IsUnexpectedCloseError(err, codes...)
}
