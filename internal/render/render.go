package render

import (
	"fmt"
	"strings"
	"time"

	"NMB/internal/report"
)

func Generate(r *report.Report) (string, error) {
	var sb strings.Builder

	sb.WriteString("<html><head><title>NMB Scan Report</title>")
	sb.WriteString(`<link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">`)
	sb.WriteString(`<link href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.3.1/styles/github-dark.min.css" rel="stylesheet">`)
	sb.WriteString(`<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.3.1/highlight.min.js"></script>`)
	sb.WriteString(`<script>hljs.highlightAll();</script>`)
	sb.WriteString(`<style>
		body { background-color: #1a202c; color: #cbd5e0; }
		.card { background-color: #2d3748; border-color: #4a5568; }
		.status-verified { color: #38a169; } /* Green for verified */
		.status-failed, .status-command-failed, .status-port-closed, .status-verification-failed { color: #e53e3e; } /* Red for other statuses */
	</style>`)
	sb.WriteString("</head><body>")
	sb.WriteString("<div class='container mx-auto mt-5'>")
	sb.WriteString("<h1 class='text-4xl font-bold mb-4'>NMB Scan Report</h1>")
	sb.WriteString(fmt.Sprintf("<p class='mb-4'><strong>Date:</strong> %s</p>", time.Now().Format(time.RFC1123)))

	sb.WriteString("<h2 class='text-2xl font-semibold mt-4'>Supported Plugins</h2>")
	if len(r.SupportedPlugins) > 0 {
		sb.WriteString("<ul class='list-disc list-inside'>")
		for _, plugin := range r.SupportedPlugins {
			sb.WriteString(fmt.Sprintf("<li class='mb-2'>%s</li>", plugin))
		}
		sb.WriteString("</ul>")
	} else {
		sb.WriteString("<p class='text-gray-500'>None</p>")
	}

	sb.WriteString("<h2 class='text-2xl font-semibold mt-4'>Missing Plugins</h2>")
	if len(r.MissingPlugins) > 0 {
		sb.WriteString("<ul class='list-disc list-inside'>")
		for _, plugin := range r.MissingPlugins {
			sb.WriteString(fmt.Sprintf("<li class='mb-2'>%s</li>", plugin))
		}
		sb.WriteString("</ul>")
	} else {
		sb.WriteString("<p class='text-gray-500'>None</p>")
	}

	sb.WriteString("<h2 class='text-2xl font-semibold mt-4'>Verified Scan Results</h2>")
	for _, result := range r.ScanResults {
		if result.Status == "Verified" {
			sb.WriteString("<div class='card border border-gray-600 rounded-lg p-4 mb-4'>")
			sb.WriteString("<div class='card-body'>")
			sb.WriteString(fmt.Sprintf("<p><strong>Plugin ID:</strong> %s</p>", result.PluginID))
			sb.WriteString("<div class='ml-4'>")
			sb.WriteString(fmt.Sprintf("<p><strong>Host:</strong> %s</p>", result.Host))
			sb.WriteString(fmt.Sprintf("<p><strong>Port:</strong> %s</p>", result.Port))
			sb.WriteString(fmt.Sprintf("<p><strong>Name:</strong> %s</p>", result.Name))
			sb.WriteString(fmt.Sprintf("<p class='status-verified'><strong>Status:</strong> %s</p>", result.Status))
			sb.WriteString(fmt.Sprintf("<p><strong>Command:</strong> <code>%s</code></p>", result.Command))
			sb.WriteString(fmt.Sprintf("<p><strong>Output:</strong><pre><code class='language-bash'>%s</code></pre></p>", result.Output))
			sb.WriteString("</div><br>")
			sb.WriteString("</div>")
			sb.WriteString("</div>")
		}
	}

	sb.WriteString("<h2 class='text-2xl font-semibold mt-4'>Failed Scan Results</h2>")
	for _, result := range r.ScanResults {
		if result.Status != "Verified" {
			sb.WriteString("<div class='card border border-gray-600 rounded-lg p-4 mb-4'>")
			sb.WriteString("<div class='card-body'>")
			sb.WriteString(fmt.Sprintf("<p><strong>Plugin ID:</strong> %s</p>", result.PluginID))
			sb.WriteString("<div class='ml-4'>")
			sb.WriteString(fmt.Sprintf("<p><strong>Host:</strong> %s</p>", result.Host))
			sb.WriteString(fmt.Sprintf("<p><strong>Port:</strong> %s</p>", result.Port))
			sb.WriteString(fmt.Sprintf("<p><strong>Name:</strong> %s</p>", result.Name))
			sb.WriteString(fmt.Sprintf("<p class='status-failed'><strong>Status:</strong> %s</p>", result.Status))
			sb.WriteString(fmt.Sprintf("<p><strong>Command:</strong> <code>%s</code></p>", result.Command))
			sb.WriteString(fmt.Sprintf("<p><strong>Output:</strong><pre><code class='language-bash'>%s</code></pre></p>", result.Output))
			sb.WriteString("</div><br>")
			sb.WriteString("</div>")
			sb.WriteString("</div>")
		}
	}

	sb.WriteString("</div>") // Close container
	sb.WriteString("</body></html>")

	return sb.String(), nil
}
