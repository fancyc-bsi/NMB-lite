package logging

import (
	websocket "NMB/internal/ws"
	"io"
	"log"
	"os"
	"sync"
)

var (
	InfoLogger    *log.Logger
	WarningLogger *log.Logger
	ErrorLogger   *log.Logger
	SuccessLogger *log.Logger
	once          sync.Once
)

const (
	InfoColor    = "\033[34m" // blue
	WarningColor = "\033[33m" // yellow
	ErrorColor   = "\033[31m" // red
	ResetColor   = "\033[0m"  // reset
	SuccessColor = "\033[32m" // green
)

type WebSocketWriter struct {
	msgType string
	writer  io.Writer
}

func (w *WebSocketWriter) Write(p []byte) (n int, err error) {
	message := string(p)
	if len(message) > 0 {
		websocket.GetInstance().BroadcastMessage(w.msgType, message)
	}
	return w.writer.Write(p)
}

func Init() {
	once.Do(func() {
		// Create writers
		infoWriter := &WebSocketWriter{msgType: "info", writer: os.Stdout}
		warningWriter := &WebSocketWriter{msgType: "warning", writer: os.Stdout}
		errorWriter := &WebSocketWriter{msgType: "error", writer: os.Stderr}
		successWriter := &WebSocketWriter{msgType: "success", writer: os.Stdout}

		// Initialize loggers with colored prefixes and no timestamps
		InfoLogger = log.New(infoWriter, InfoColor+"[-]"+ResetColor+" ", 0)
		WarningLogger = log.New(warningWriter, WarningColor+"[!]"+ResetColor+" ", 0)
		ErrorLogger = log.New(errorWriter, ErrorColor+"[x]"+ResetColor+" ", 0)
		SuccessLogger = log.New(successWriter, SuccessColor+"[+]"+ResetColor+" ", 0)
	})
}

// GetInfoLogger returns the InfoLogger, initializing it if necessary
func GetInfoLogger() *log.Logger {
	if InfoLogger == nil {
		Init()
	}
	return InfoLogger
}

// GetWarningLogger returns the WarningLogger, initializing it if necessary
func GetWarningLogger() *log.Logger {
	if WarningLogger == nil {
		Init()
	}
	return WarningLogger
}

// GetErrorLogger returns the ErrorLogger, initializing it if necessary
func GetErrorLogger() *log.Logger {
	if ErrorLogger == nil {
		Init()
	}
	return ErrorLogger
}

// GetSuccessLogger returns the SuccessLogger, initializing it if necessary
func GetSuccessLogger() *log.Logger {
	if SuccessLogger == nil {
		Init()
	}
	return SuccessLogger
}
