package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	context0 "context"

	genai "github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// API key should be set via environment variable GEMINI_API_KEY
// or in a config file. Never hardcode in production.
func getAPIKey() string {
	key := os.Getenv("GEMINI_API_KEY")
	if key == "" {
		// Fallback for development only - replace with your key or leave empty
		key = os.Getenv("PENNYWISE_API_KEY")
	}
	return key
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(`PennyWise AI Model CLI
======================

Usage:
  localmodel vuln-info <input.json>     Analyze a vulnerability
  localmodel site-audit <input.json>    Audit a website for vulnerabilities
  localmodel classify-severity <input.json>  Classify vulnerability severity

Environment:
  GEMINI_API_KEY   API key for Google Gemini (required)

Examples:
  localmodel vuln-info vuln_data.json
  localmodel site-audit site_data.json
  localmodel classify-severity findings.json`)
		return
	}

	mode := os.Args[1]

	if len(os.Args) < 3 {
		fmt.Println(`{"error":"E004","message":"Input file required"}`)
		return
	}

	inputFile := os.Args[2]

	// Read JSON input from file
	inputBytes, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf(`{"error":"E005","message":"Error reading input file: %s"}`, err.Error())
		return
	}
	input := string(inputBytes)

	switch mode {
	case "vuln-info":
		runVulnInfo(input)
	case "site-audit":
		runSiteAudit(input)
	case "classify-severity":
		runClassifier(input)
	default:
		fmt.Printf(`{"error":"E006","message":"Unknown mode: %s"}`, mode)
	}
}

func callGemini(prompt string) string {
	apiKey := getAPIKey()
	if apiKey == "" {
		return `{"error":"E007","message":"GEMINI_API_KEY environment variable not set"}`
	}

	ctx := context0.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return `{"error":"E001","message":"API client init failed"}`
	}
	defer client.Close()

	model := client.GenerativeModel("gemini-2.5-flash")

	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		if strings.Contains(err.Error(), "quota") {
			return `{"error":"E001","message":"API quota exceeded"}`
		} else if strings.Contains(err.Error(), "unsafe") {
			return `{"error":"E002","message":"Content blocked as unsafe"}`
		}
		return fmt.Sprintf(`{"error":"E008","message":"%s"}`, err.Error())
	}

	if len(resp.Candidates) == 0 {
		return `{"error":"E003","message":"No response candidates"}`
	}

	part := resp.Candidates[0].Content.Parts[0]
	return strings.TrimSpace(fmt.Sprintf("%v", part))
}

func runVulnInfo(jsonInput string) {
	var data map[string]string
	json.Unmarshal([]byte(jsonInput), &data)

	prompt := fmt.Sprintf(`
You are a security expert. Analyze the following vulnerability and return JSON output:
{
  "summary": "One-line summary of the vulnerability",
  "severity": "Low | Medium | High | Critical",
  "risks": ["List of possible risks"],
  "recommendations": ["List of secure coding best practices and fixes"]
}
Vulnerability details:
Type: %s
Subtype: %s
URL: %s
Snippet: %s`, data["type"], data["subtype"], data["url"], data["match"])

	fmt.Println(callGemini(prompt))
}

func runSiteAudit(jsonInput string) {
	var data map[string]string
	json.Unmarshal([]byte(jsonInput), &data)

	htmlSnippet := data["html"]
	if len(htmlSnippet) > 1500 {
		htmlSnippet = htmlSnippet[:1500]
	}

	prompt := fmt.Sprintf(`
You are a penetration tester. (focus on sqli,xss, etc etc) Based on this website's content which you think is vulnerable and attack focused dont gave blabbering info aboit the site like what intention they created like just focus on your aim, return JSON output:
{
  "site_summary": "Brief overview of what this site does (very short and precise) (only specify vulnerable part)",
  "recommended_tests": [ // what tests u recommend and why
    {"test": "Test name", "priority": "High/Medium/Low", "reason": "Why this is important (keep it very short , precise, technical words, and simple)"}
  ],
  "next_steps": [0 -> if SQLi potential, 1-> if XSS potential, 2-> if auth issues, etc.]
}
Website: %s
Title: %s
HTML snippet: %s`, data["url"], data["title"], htmlSnippet)

	fmt.Println(callGemini(prompt))
}

func runClassifier(jsonInput string) {
	var data map[string]string
	json.Unmarshal([]byte(jsonInput), &data)

	prompt := fmt.Sprintf(`
Classify this vulnerability based on severity and criticality.
Return JSON like:
{
  "severity": "Low | Medium | High | Critical",
  "impact": "Description of potential impact (short)",
  "quick_fixes": ["List of quick remediation steps"]
}
Input: %v`, data)

	fmt.Println(callGemini(prompt))
}
