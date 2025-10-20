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

const API_KEY = "AIzaSyBO36qGSZi_U3xPshX4w3XsDd1tBfbv8TA"

func main() {
	if len(os.Args) < 2 {
		fmt.Println(`Usage:
  model-cli vuln-info '{"type":"SQLi", "subtype":"Error based", "url":"https://test", "match":"SELECT * FROM users"}'
  model-cli site-audit '{"url":"https://mysite.com", "title":"Home", "html":"<html>...</html>"}'
  model-cli classify-severity '{"summary":"XSS vuln", "details":"Stored XSS in login page"}'`)
		return
	}

	mode := os.Args[1]
	inputFile := os.Args[2]

	// Read JSON input from file
	inputBytes, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Println("Error reading input file:", err)
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
		fmt.Println("Unknown mode:", mode)
	}
}

func callGemini(prompt string) string {
	ctx := context0.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(API_KEY))
	if err != nil {
		return `{"error":"E001","message":"API client init failed"}`
	}
	model := client.GenerativeModel("gemini-2.5-flash")

	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		if strings.Contains(err.Error(), "quota") {
			return `{"error":"E001"}`
		} else if strings.Contains(err.Error(), "unsafe") {
			return `{"error":"E002"}`
		}
		return fmt.Sprintf(`{"message":"%s"}`, err.Error())
	}

	if len(resp.Candidates) == 0 {
		return `{"error":"E003"}`
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
