// main_linux.go
//go:build linux

package main

import (
	"embed"
)

//go:embed ui/linux/ui
var uiBinary embed.FS

const binaryName = "ui/linux/ui"
