package mcp

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	BaseURL   string
	Token     string
	Transport string
	HTTPAddr  string
}

func ConfigFromEnv() (Config, error) {
	cfg := Config{
		BaseURL:   strings.TrimSpace(os.Getenv("ARGUS_BASE_URL")),
		Token:     strings.TrimSpace(os.Getenv("ARGUS_TOKEN")),
		Transport: strings.ToLower(strings.TrimSpace(os.Getenv("ARGUS_MCP_TRANSPORT"))),
		HTTPAddr:  strings.TrimSpace(os.Getenv("ARGUS_MCP_HTTP_ADDR")),
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
	return cfg, nil
}
