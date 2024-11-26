package main

import (
	"NMB/internal/api"
	"NMB/internal/args"
	"NMB/internal/engine"
	"context"
	"embed"
	"log"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:ui-core/build
var assets embed.FS

type App struct {
	ctx context.Context
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	os.Setenv("GOGC", "50")
	go func() {
		server := api.NewServer()
		errChan := make(chan error, 10) // Buffered channel
		go func() {
			errChan <- server.Run()
		}()
		if err := <-errChan; err != nil {
			log.Printf("API server error: %v", err)
		}
	}()
}

// SelectFile opens a file selection dialog
func (a *App) SelectFile(filter string) (string, error) {
	var dialogOptions runtime.OpenDialogOptions

	if filter == "SSH Key" {
		dialogOptions = runtime.OpenDialogOptions{
			Title: "Select SSH Key File",
			Filters: []runtime.FileFilter{
				{
					DisplayName: "SSH Key Files",
					Pattern:     "*.pem;*.key;*.pub",
				},
			},
		}
	} else {
		dialogOptions = runtime.OpenDialogOptions{
			Title: "Select File",
			Filters: []runtime.FileFilter{
				{
					DisplayName: filter,
					Pattern:     "*.*",
				},
			},
		}
	}

	return runtime.OpenFileDialog(a.ctx, dialogOptions)
}

// SelectDirectory opens a directory selection dialog
func (a *App) SelectDirectory() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select Directory",
	})
}

func main() {
	// Command line handling
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		parsedArgs := args.ParseArgs()
		if parsedArgs.NessusMode != "" {
			engine.HandleNessusController(parsedArgs)
			return
		}
		engine.RunNMB(parsedArgs)
		return
	}

	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "NMB Application",
		Width:            1200,
		Height:           800,
		Assets:           assets,
		BackgroundColour: &options.RGBA{R: 10, G: 25, B: 41, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
		Linux: &linux.Options{
			WindowIsTranslucent: false,
			WebviewGpuPolicy:    linux.WebviewGpuPolicyNever,
			ProgramName:         "NMB",
			Icon:                nil,
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: true,
		},
		CSSDragProperty: "--wails-draggable",
		CSSDragValue:    "drag",
	})

	if err != nil {
		log.Fatal(err)
	}
}
