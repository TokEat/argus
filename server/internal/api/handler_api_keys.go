package api

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// ApiKeyEntry represents one API provider's key configuration.
type ApiKeyEntry struct {
	Provider string   `json:"provider"`
	Keys     []string `json:"keys"`
}

// getApiKeysConfig returns the current api-config from the Arsenal.
func getApiKeysConfig(c *gin.Context) {
	arsenal, err := db.FindTenantArsenalByTypeAndFile(currentTenantID(c), "apiconfig", "api-config.yaml")
	if err != nil {
		c.JSON(http.StatusOK, defaultApiKeyEntries())
		return
	}

	var data map[string][]string
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse api-config"})
		return
	}

	var results []ApiKeyEntry
	for provider, keys := range data {
		results = append(results, ApiKeyEntry{Provider: provider, Keys: keys})
	}
	c.JSON(http.StatusOK, results)
}

// saveApiKeysConfig updates Server-only asset discovery credentials. Agents
// never receive this configuration or a notification that it changed.
func saveApiKeysConfig(c *gin.Context) {
	tenantID := currentTenantID(c)
	var entries []ApiKeyEntry
	if err := c.ShouldBindJSON(&entries); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data := make(map[string][]string)
	for _, entry := range entries {
		provider := strings.TrimSpace(entry.Provider)
		if provider == "" {
			continue
		}
		data[provider] = entry.Keys
	}

	out, err := yaml.Marshal(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize config"})
		return
	}

	contentStr := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))
	arsenal, findErr := db.FindTenantArsenalByTypeAndFile(tenantID, "apiconfig", "api-config.yaml")
	if findErr != nil {
		arsenal = &db.Arsenal{
			ID:       db.BuildTenantArsenalID(tenantID, "apiconfig", "api-config.yaml"),
			TenantID: tenantID,
			Type:     "apiconfig",
			FileName: "api-config.yaml",
			Content:  contentStr,
			Hash:     hash,
			State:    "Approved",
			Version:  1,
		}
		if err := db.DB.Create(arsenal).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create config"})
			return
		}
	} else {
		arsenal.Content = contentStr
		arsenal.Hash = hash
		arsenal.State = "Approved"
		arsenal.Version++
		if err := db.DB.Save(arsenal).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "saved", "hash": hash})
}

func defaultApiKeyEntries() []ApiKeyEntry {
	providers := []string{
		"bevigil", "binaryedge", "bufferover", "c99", "censys",
		"certspotter", "chaos", "chinaz", "dnsdb", "dnsrepo",
		"fofa", "fullhunt", "github", "hunter", "intelx",
		"leakix", "passivetotal", "quake", "robtex", "securitytrails",
		"shodan", "threatbook", "virustotal", "whoisxmlapi", "zoomeye",
		"zoomeyeapi",
	}
	entries := make([]ApiKeyEntry, len(providers))
	for i, provider := range providers {
		entries[i] = ApiKeyEntry{Provider: provider, Keys: []string{}}
	}
	return entries
}
