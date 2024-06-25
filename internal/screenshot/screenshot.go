package screenshot

import (
	"NMB/internal/logging"
	_ "embed"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

//go:embed "HackNerdFont-Regular.ttf"
var nerdFontTtf []byte

var fontFace font.Face

func init() {
	font, err := opentype.Parse(nerdFontTtf)
	if err != nil {
		log.Fatalf("[x] Failed to parse font: %v", err)
	}
	fontFace, err = opentype.NewFace(font, &opentype.FaceOptions{
		Size: 14,
		DPI:  96,
	})
	if err != nil {
		log.Fatalf("[x] Failed to create font face: %v", err)
	}
}

func drawString(img *image.RGBA, x, y int, label string, highlightWords []string) {
	col := color.RGBA{R: 255, G: 255, B: 255, A: 255}        // white color
	highlightColor := color.RGBA{R: 255, G: 0, B: 0, A: 255} // red color
	point := fixed.Point26_6{X: fixed.I(x), Y: fixed.I(y)}

	for _, word := range strings.Fields(label) {
		wordCol := col
		for _, hw := range highlightWords {
			if strings.Contains(strings.ToLower(word), strings.ToLower(hw)) {
				wordCol = highlightColor
				break
			}
		}
		d := &font.Drawer{
			Dst:  img,
			Src:  image.NewUniform(wordCol),
			Face: fontFace,
			Dot:  point,
		}
		d.DrawString(word + " ")
		point.X += d.MeasureString(word + " ")
	}
}

func wrapText(text string, maxWidth int, face font.Face) []string {
	var wrapped []string
	for _, line := range strings.Split(text, "\n") {
		var currentLine string
		for _, word := range strings.Fields(line) {
			if currentLine == "" {
				currentLine = word
			} else {
				width := font.MeasureString(face, currentLine+" "+word).Ceil()
				if width > maxWidth {
					wrapped = append(wrapped, currentLine)
					currentLine = word
				} else {
					currentLine += " " + word
				}
			}
		}
		wrapped = append(wrapped, currentLine)
	}
	return wrapped
}

func Take(projectFolder, screenshotPath, output string, verifyWords []string) {
	const maxWidth = 800
	const lineHeight = 24
	const padding = 20

	lines := wrapText(output, maxWidth-padding*2, fontFace)
	height := padding*2 + len(lines)*lineHeight
	width := maxWidth

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	darkBackground := color.RGBA{R: 30, G: 30, B: 30, A: 255} // dark grey color
	draw.Draw(img, img.Bounds(), &image.Uniform{C: darkBackground}, image.Point{}, draw.Src)

	y := padding
	for _, line := range lines {
		drawString(img, padding, y, line, verifyWords)
		y += lineHeight
	}

	if err := os.MkdirAll(projectFolder, os.ModePerm); err != nil {
		logging.ErrorLogger.Printf("[x] Failed to create project folder: %v", err)
		return
	}

	filename := filepath.Join(projectFolder, screenshotPath)
	file, err := os.Create(filename)
	if err != nil {
		logging.ErrorLogger.Printf("[x] Failed to create screenshot file: %v", err)
		return
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		logging.ErrorLogger.Printf("[x] Failed to encode screenshot to PNG: %v", err)
	}
}
