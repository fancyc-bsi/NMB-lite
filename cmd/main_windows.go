// main_windows.go
//go:build windows

package main

import (
	"embed"
)

//go:embed ui/windows/ui.exe
var uiBinary embed.FS

const binaryName = "ui/windows/ui.exe"
