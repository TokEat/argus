package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"dddd/scanner/internal/exploit"
)

type debugOutput struct {
	TemplateID string          `json:"template_id"`
	Engine     string          `json:"engine"`
	Target     string          `json:"target"`
	Mode       string          `json:"mode"`
	Result     *exploit.Result `json:"result,omitempty"`
	CleanupOK  *bool           `json:"cleanup_ok,omitempty"`
	Error      string          `json:"error,omitempty"`
}

func main() {
	filePath := flag.String("file", "", "Python EXP .py file path")
	target := flag.String("target", "", "Target URL, for example http://127.0.0.1:8080")
	paramsJSON := flag.String("params", "{}", "EXP params as JSON object")
	timeoutSec := flag.Int("timeout", 60, "Timeout in seconds")
	proxy := flag.String("proxy", "", "Optional HTTP/SOCKS proxy URL")
	cleanup := flag.Bool("cleanup", false, "Run cleanup after execution")
	cleanupOnly := flag.Bool("cleanup-only", false, "Only run cleanup")
	flag.Parse()

	out := debugOutput{Target: *target}
	exitCode := 0
	defer func() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		os.Exit(exitCode)
	}()

	if *filePath == "" {
		out.Error = "-file is required"
		exitCode = 2
		return
	}
	if *target == "" {
		out.Error = "-target is required"
		exitCode = 2
		return
	}

	content, err := os.ReadFile(*filePath)
	if err != nil {
		out.Error = fmt.Sprintf("read EXP file: %v", err)
		exitCode = 1
		return
	}
	tmpl, err := exploit.ParseTemplate(content)
	if err != nil {
		out.Error = fmt.Sprintf("parse EXP: %v", err)
		exitCode = 1
		return
	}
	out.TemplateID = tmpl.ID
	out.Engine = tmpl.RuntimeEngine

	params := map[string]interface{}{}
	if err := json.Unmarshal([]byte(*paramsJSON), &params); err != nil {
		out.Error = fmt.Sprintf("parse params JSON: %v", err)
		exitCode = 2
		return
	}

	engine := exploit.NewEngine(time.Duration(*timeoutSec)*time.Second, *proxy)
	if *cleanupOnly {
		out.Mode = "cleanup"
		err = engine.Cleanup(tmpl, *target, params)
		ok := err == nil
		out.CleanupOK = &ok
		if err != nil {
			out.Error = err.Error()
			exitCode = 1
		}
		return
	}

	out.Mode = "run"
	result, err := engine.Run(tmpl, *target, params)
	if err != nil {
		out.Error = err.Error()
		exitCode = 1
		return
	}
	out.Result = result
	if result == nil || result.Status != "Succeeded" {
		exitCode = 1
	}

	if *cleanup {
		err = engine.Cleanup(tmpl, *target, params)
		ok := err == nil
		out.CleanupOK = &ok
		if err != nil {
			out.Error = err.Error()
			exitCode = 1
		}
	}
}
