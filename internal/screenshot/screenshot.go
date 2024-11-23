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
)

//go:embed template.html
var embeddedHTML string

//go:embed style.css
var embeddedCSS string

func init() {
	// Check if wkhtmltoimage is installed
	if _, _, err := getWkHtmlPaths(); err != nil {
		fmt.Println("Warning: wkhtmltoimage is not installed")
	}
}

func getWkHtmlPaths() (wkhtmltopdfPath, wkhtmltoimagePath string, err error) {
	// Check the operating system
	switch runtime.GOOS {
	case "windows":
		// On Windows, specify the full path to wkhtmltopdf and wkhtmltoimage
		wkhtmltopdfPath = `C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe`
		wkhtmltoimagePath = `C:\Program Files\wkhtmltopdf\bin\wkhtmltoimage.exe`
	default:
		// Default behavior for other OS (Linux/macOS)
		wkhtmltopdfPath = "/usr/bin/wkhtmltopdf"
		wkhtmltoimagePath = "/usr/bin/wkhtmltoimage"
	}

	// Check if the file exists
	if _, err = os.Stat(wkhtmltoimagePath); err != nil {
		return "", "", err
	}

	return wkhtmltopdfPath, wkhtmltoimagePath, nil
}

// createHTMLContent generates HTML content using the embedded template and applies word highlights.
func createHTMLContent(output, command string, verifyWords []string) string {
	// Highlight words in red
	for _, word := range verifyWords {
		output = strings.ReplaceAll(
			output,
			word,
			fmt.Sprintf("<span class='highlight'>%s</span>", word),
		)
	}

	// Prepend a blank line to mask unwanted indentation
	output = "\n" + output

	// Add the command note at the top
	commandNote := fmt.Sprintf(`
		<div class="command-note">
			<p><strong>Command Executed:</strong></p>
			<pre>%s</pre>
		</div>
	`, command)

	// Inject the CSS and replace content and command placeholders in the HTML template
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

	// Create temporary HTML file
	tmpHTML := filepath.Join(projectFolder, "temp.html")
	if err := os.WriteFile(tmpHTML, []byte(createHTMLContent(output, command, verifyWords)), 0644); err != nil {
		logging.ErrorLogger.Printf("Failed to create temporary HTML file: %v", err)
		return
	}

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

	// Log success message indicating the screenshot was saved
	logging.SuccessLogger.Printf("Screenshot successfully saved to: %s", filename)
}
