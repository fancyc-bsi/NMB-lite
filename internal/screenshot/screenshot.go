package screenshot

import (
	"NMB/internal/logging"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
)

//go:embed template.html
var embeddedHTML string

//go:embed style.css
var embeddedCSS string

// Counter for generating unique temporary files
var tempCounter uint64

func init() {
	if _, _, err := getWkHtmlPaths(); err != nil {
		fmt.Println("Warning: wkhtmltoimage is not installed")
	}
}

func getWkHtmlPaths() (wkhtmltopdfPath, wkhtmltoimagePath string, err error) {
	switch runtime.GOOS {
	case "windows":
		wkhtmltopdfPath = `C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe`
		wkhtmltoimagePath = `C:\Program Files\wkhtmltopdf\bin\wkhtmltoimage.exe`
	default:
		wkhtmltopdfPath = "/usr/bin/wkhtmltopdf"
		wkhtmltoimagePath = "/usr/bin/wkhtmltoimage"
	}
	if _, err = os.Stat(wkhtmltoimagePath); err != nil {
		return "", "", err
	}
	return wkhtmltopdfPath, wkhtmltoimagePath, nil
}

func createHTMLContent(output, command string, verifyWords []string) string {
	// Highlight words in red
	for _, word := range verifyWords {
		output = strings.ReplaceAll(
			output,
			word,
			fmt.Sprintf("<span class='highlight'>%s</span>", word),
		)
	}

	output = "\n" + output
	commandNote := fmt.Sprintf(`
        <div class="command-note">
            <p><strong>Command Executed:</strong></p>
            <pre>%s</pre>
        </div>
    `, command)

	htmlContent := strings.ReplaceAll(embeddedHTML, "{{.Content}}", output)
	htmlContent = strings.ReplaceAll(htmlContent, "{{.CSS}}", embeddedCSS)
	htmlContent = strings.ReplaceAll(htmlContent, "{{.CommandNote}}", commandNote)
	return htmlContent
}

func Take(projectFolder, screenshotPath, output string, verifyWords []string, command string) {
	if err := os.MkdirAll(projectFolder, os.ModePerm); err != nil {
		logging.ErrorLogger.Printf("Failed to create project folder: %v", err)
		return
	}

	// Generate unique temporary HTML file name
	uniqueID := atomic.AddUint64(&tempCounter, 1)
	tmpHTML := filepath.Join(projectFolder, fmt.Sprintf("temp_%d.html", uniqueID))

	// Create HTML content and write to temporary file
	htmlContent := createHTMLContent(output, command, verifyWords)
	if err := os.WriteFile(tmpHTML, []byte(htmlContent), 0644); err != nil {
		logging.ErrorLogger.Printf("Failed to create temporary HTML file: %v", err)
		return
	}

	// Ensure temporary file is cleaned up
	defer func() {
		if err := os.Remove(tmpHTML); err != nil {
			logging.ErrorLogger.Printf("Failed to remove temporary HTML file: %v", err)
		}
	}()

	_, wkhtmltoimagePath, err := getWkHtmlPaths()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get wkhtmltoimage path: %v", err)
		return
	}

	filename := filepath.Join(projectFolder, screenshotPath)

	// Convert HTML to PNG using wkhtmltoimage
	cmd := exec.Command(wkhtmltoimagePath, "--quality", "100", tmpHTML, filename)
	if err := cmd.Run(); err != nil {
		logging.ErrorLogger.Printf("Failed to generate screenshot: %v", err)
		return
	}

	logging.SuccessLogger.Printf("Screenshot successfully saved to: %s", filename)
}
