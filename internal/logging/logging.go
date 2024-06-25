package logging

import (
	"log"
	"os"
)

var (
	InfoLogger    *log.Logger
	WarningLogger *log.Logger
	ErrorLogger   *log.Logger
	SuccessLogger *log.Logger
)

const (
	InfoColor    = "\033[34m" // blue
	WarningColor = "\033[33m" // yellow
	ErrorColor   = "\033[31m" // red
	ResetColor   = "\033[0m"  // reset
	SuccessColor = "\033[32m" // green
)

func Init() {
	file, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	InfoLogger = log.New(file, InfoColor+"[-] "+ResetColor, 0)
	WarningLogger = log.New(file, WarningColor+"[!] "+ResetColor, 0)
	ErrorLogger = log.New(file, ErrorColor+"[x] "+ResetColor, 0)
	SuccessLogger = log.New(file, SuccessColor+"[+] "+ResetColor, 0)

	InfoLogger.SetOutput(os.Stdout)
	WarningLogger.SetOutput(os.Stdout)
	ErrorLogger.SetOutput(os.Stdout)
	SuccessLogger.SetOutput(os.Stdout)
}
