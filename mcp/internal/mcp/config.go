package mcp

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	BaseURL      string
	Token        string
	YakshaURL    string
	Transport    string
	HTTPAddr     string
	MCPAuthToken string
}

func ConfigFromEnv() (Config, error) {
	cfg := Config{
		BaseURL:      strings.TrimSpace(os.Getenv("ARGUS_BASE_URL")),
		Token:        strings.TrimSpace(os.Getenv("ARGUS_TOKEN")),
		YakshaURL:    strings.TrimSpace(os.Getenv("ARGUS_YAKSHA_URL")),
		Transport:    strings.ToLower(strings.TrimSpace(os.Getenv("ARGUS_MCP_TRANSPORT"))),
		HTTPAddr:     strings.TrimSpace(os.Getenv("ARGUS_MCP_HTTP_ADDR")),
		MCPAuthToken: strings.TrimSpace(os.Getenv("ARGUS_MCP_AUTH_TOKEN")),
	}
	if cfg.YakshaURL == "" {
		cfg.YakshaURL = "http://127.0.0.1:8790"
	}
	if cfg.Transport == "" {
		cfg.Transport = "stdio"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "127.0.0.1:8787"
	}
	if cfg.Token == "" {
		tokenFile := strings.TrimSpace(os.Getenv("ARGUS_TOKEN_FILE"))
		if tokenFile != "" {
			data, err := os.ReadFile(tokenFile)
			if err != nil {
				return Config{}, fmt.Errorf("read ARGUS_TOKEN_FILE: %w", err)
			}
			cfg.Token = strings.TrimSpace(string(data))
		}
	}
	if cfg.MCPAuthToken == "" {
		tokenFile := strings.TrimSpace(os.Getenv("ARGUS_MCP_AUTH_TOKEN_FILE"))
		if tokenFile != "" {
			data, err := os.ReadFile(tokenFile)
			if err != nil {
				return Config{}, fmt.Errorf("read ARGUS_MCP_AUTH_TOKEN_FILE: %w", err)
			}
			cfg.MCPAuthToken = strings.TrimSpace(string(data))
		}
	}
	if (cfg.Transport == "http" || cfg.Transport == "sse") && cfg.MCPAuthToken == "" {
		return Config{}, fmt.Errorf("ARGUS_MCP_AUTH_TOKEN or ARGUS_MCP_AUTH_TOKEN_FILE is required for HTTP/SSE transport")
	}
	return cfg, nil
}
