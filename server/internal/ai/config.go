package ai

import (
	"errors"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

const (
	ConfigKeyBaseURL = "ai_base_url"
	ConfigKeyAPIKey  = "ai_api_key"
	ConfigKeyModel   = "ai_model"

	defaultBaseURL = "https://api.openai.com/v1"
)

var ErrMissingConfig = errors.New("ai config is incomplete")

func LoadConfig(store *gorm.DB) (Config, error) {
	values := map[string]string{}
	var rows []db.SystemConfig
	if err := store.Where("key IN ?", []string{ConfigKeyBaseURL, ConfigKeyAPIKey, ConfigKeyModel}).Find(&rows).Error; err != nil {
		return Config{}, err
	}
	for _, row := range rows {
		values[row.Key] = strings.TrimSpace(row.Value)
	}

	cfg := Config{
		BaseURL: values[ConfigKeyBaseURL],
		APIKey:  values[ConfigKeyAPIKey],
		Model:   values[ConfigKeyModel],
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	if cfg.APIKey == "" || cfg.Model == "" {
		return cfg, ErrMissingConfig
	}
	return cfg, nil
}

func SaveConfig(store *gorm.DB, cfg Config) error {
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	cfg.Model = strings.TrimSpace(cfg.Model)
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}

	now := time.Now()
	rows := []db.SystemConfig{
		{Key: ConfigKeyBaseURL, Value: cfg.BaseURL, UpdatedAt: now},
		{Key: ConfigKeyModel, Value: cfg.Model, UpdatedAt: now},
	}
	if cfg.APIKey != "" && !isMaskedSecret(cfg.APIKey) {
		rows = append(rows, db.SystemConfig{Key: ConfigKeyAPIKey, Value: cfg.APIKey, UpdatedAt: now})
	}

	for _, row := range rows {
		if err := store.Save(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

func PublicConfigFromStore(store *gorm.DB) (PublicConfig, error) {
	var rows []db.SystemConfig
	if err := store.Where("key IN ?", []string{ConfigKeyBaseURL, ConfigKeyAPIKey, ConfigKeyModel}).Find(&rows).Error; err != nil {
		return PublicConfig{}, err
	}
	values := map[string]string{}
	for _, row := range rows {
		values[row.Key] = strings.TrimSpace(row.Value)
	}

	baseURL := values[ConfigKeyBaseURL]
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	apiKey := values[ConfigKeyAPIKey]
	return PublicConfig{
		BaseURL:      baseURL,
		Model:        values[ConfigKeyModel],
		HasAPIKey:    apiKey != "",
		APIKeyMasked: maskSecret(apiKey),
	}, nil
}

func maskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 8 {
		return "********"
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}

func isMaskedSecret(secret string) bool {
	secret = strings.TrimSpace(secret)
	return strings.Contains(secret, "****") || strings.Count(secret, "*") >= 4
}
