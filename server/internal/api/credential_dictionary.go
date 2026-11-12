package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/credentialvault"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maximumDictionaryItems        = 100_000
	maximumDictionaryRequestBytes = 64 << 20
	maximumScanPolicyRequestBytes = 8 << 20
)

type credentialDictionaryRequest struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Values []string `json:"values"`
}

type credentialDictionaryResponse struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Revision  int       `json:"revision"`
	SHA256    string    `json:"sha256"`
	Count     int       `json:"count"`
	CreatedAt time.Time `json:"created_at"`
}

type credentialFindingResponse struct {
	ID             string    `json:"id"`
	Endpoint       string    `json:"endpoint"`
	Service        string    `json:"service"`
	Plugin         string    `json:"plugin"`
	MaskedUsername string    `json:"masked_username"`
	CreatedAt      time.Time `json:"created_at"`
}

func scanPolicyRequestBodyLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body == nil || c.Request.Method != http.MethodPost {
			c.Next()
			return
		}
		path := strings.TrimSuffix(c.Request.URL.Path, "/")
		limit := int64(0)
		switch {
		case path == "/api/v1/tasks" || path == "/api/v1/tasks/plan-preview":
			limit = maximumScanPolicyRequestBytes
		case isCredentialDictionaryWritePath(path):
			limit = maximumDictionaryRequestBytes
		case isSubdomainDictionaryWritePath(path):
			limit = maximumDictionaryRequestBytes
		}
		if limit > 0 {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

func isSubdomainDictionaryWritePath(path string) bool {
	if !strings.HasPrefix(path, "/api/v1/projects/") {
		return false
	}
	return strings.HasSuffix(path, "/subdomain-dictionaries") ||
		(strings.Contains(path, "/subdomain-dictionaries/") && strings.HasSuffix(path, "/revisions"))
}

func isCredentialDictionaryWritePath(path string) bool {
	if !strings.HasPrefix(path, "/api/v1/projects/") {
		return false
	}
	return strings.HasSuffix(path, "/credential-dictionaries") ||
		(strings.Contains(path, "/credential-dictionaries/") && strings.HasSuffix(path, "/revisions"))
}

func listTaskCredentialFindings(c *gin.Context) {
	root, ok := requireTaskAccess(c)
	if !ok {
		return
	}
	var rows []db.CredentialFindingSecret
	if err := db.DB.Select("id", "endpoint", "service", "plugin", "masked_username", "created_at").
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ?", root.TenantID, root.ProjectID, root.ID).
		Order("created_at desc, id desc").Limit(500).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load credential findings"})
		return
	}
	items := make([]credentialFindingResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, credentialFindingResponse{ID: row.ID, Endpoint: row.Endpoint, Service: row.Service, Plugin: row.Plugin, MaskedUsername: row.MaskedUsername, CreatedAt: row.CreatedAt})
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func createCredentialDictionary(c *gin.Context) {
	project, ok := requireProjectManage(c, c.Param("id"))
	if !ok {
		return
	}
	var req credentialDictionaryRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maximumDictionaryRequestBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Kind = strings.ToLower(strings.TrimSpace(req.Kind))
	if req.Name == "" || len(req.Name) > 160 || (req.Kind != "username" && req.Kind != "password") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and kind=username|password are required"})
		return
	}
	values, err := normalizeDictionaryValues(req.Values)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault unavailable"})
		return
	}
	dictionaryID := uuid.NewString()
	revision, err := sealDictionaryRevision(vault, currentTenantID(c), project.ID, dictionaryID, 1, values, currentUserID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to seal dictionary"})
		return
	}
	dictionary := db.CredentialDictionary{ID: dictionaryID, TenantID: currentTenantID(c), ProjectID: project.ID, Kind: req.Kind, Name: req.Name, CreatedBy: currentUserID(c)}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&dictionary).Error; err != nil {
			return err
		}
		return tx.Create(&revision).Error
	}); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "dictionary name already exists or could not be stored"})
		return
	}
	c.JSON(http.StatusCreated, dictionaryResponse(dictionary, revision))
}

func addCredentialDictionaryRevision(c *gin.Context) {
	project, ok := requireProjectManage(c, c.Param("id"))
	if !ok {
		return
	}
	var req struct {
		Values []string `json:"values"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maximumDictionaryRequestBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	values, err := normalizeDictionaryValues(req.Values)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault unavailable"})
		return
	}
	var dictionary db.CredentialDictionary
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND tenant_id = ? AND project_id = ?", c.Param("dictionary_id"), currentTenantID(c), project.ID).First(&dictionary).Error; err != nil {
			return err
		}
		var latest int
		if err := tx.Model(&db.CredentialDictionaryRevision{}).Where("dictionary_id = ?", dictionary.ID).Select("COALESCE(MAX(revision), 0)").Scan(&latest).Error; err != nil {
			return err
		}
		revision, err := sealDictionaryRevision(vault, dictionary.TenantID, dictionary.ProjectID, dictionary.ID, latest+1, values, currentUserID(c))
		if err != nil {
			return err
		}
		return tx.Create(&revision).Error
	})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dictionary not found or revision could not be stored"})
		return
	}
	var revision db.CredentialDictionaryRevision
	db.DB.Where("dictionary_id = ?", dictionary.ID).Order("revision desc").First(&revision)
	c.JSON(http.StatusCreated, dictionaryResponse(dictionary, revision))
}

func listCredentialDictionaries(c *gin.Context) {
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}
	var dictionaries []db.CredentialDictionary
	if err := db.DB.Where("tenant_id = ? AND project_id = ?", currentTenantID(c), project.ID).Order("kind, name").Find(&dictionaries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	items := make([]credentialDictionaryResponse, 0, len(dictionaries))
	for _, dictionary := range dictionaries {
		var revision db.CredentialDictionaryRevision
		if err := db.DB.Where("dictionary_id = ? AND tenant_id = ?", dictionary.ID, currentTenantID(c)).Order("revision desc").First(&revision).Error; err == nil {
			items = append(items, dictionaryResponse(dictionary, revision))
		}
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func deleteCredentialDictionary(c *gin.Context) {
	project, ok := requireProjectManage(c, c.Param("id"))
	if !ok {
		return
	}
	result := db.DB.Where("id = ? AND tenant_id = ? AND project_id = ?", c.Param("dictionary_id"), currentTenantID(c), project.ID).Delete(&db.CredentialDictionary{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	if result.RowsAffected != 1 {
		c.JSON(http.StatusNotFound, gin.H{"error": "dictionary not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

func normalizeDictionaryValues(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("values must not be empty")
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("dictionary contains an invalid value")
		}
		seen[value] = struct{}{}
		if len(seen) > maximumDictionaryItems {
			return nil, fmt.Errorf("dictionary exceeds %d unique items", maximumDictionaryItems)
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("values must contain at least one non-empty item")
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func sealDictionaryRevision(vault *credentialvault.Vault, tenantID, projectID, dictionaryID string, revision int, values []string, actorID string) (db.CredentialDictionaryRevision, error) {
	plaintext, err := json.Marshal(values)
	if err != nil {
		return db.CredentialDictionaryRevision{}, err
	}
	sum := sha256.Sum256(plaintext)
	aad := []byte(fmt.Sprintf("dictionary:%s:%s:%s:%d", tenantID, projectID, dictionaryID, revision))
	ciphertext, nonce, err := vault.Seal(plaintext, aad)
	if err != nil {
		return db.CredentialDictionaryRevision{}, err
	}
	return db.CredentialDictionaryRevision{TenantID: tenantID, ProjectID: projectID, DictionaryID: dictionaryID, Revision: revision, SHA256: hex.EncodeToString(sum[:]), ItemCount: len(values), Ciphertext: ciphertext, Nonce: nonce, CreatedBy: actorID}, nil
}

func dictionaryResponse(dictionary db.CredentialDictionary, revision db.CredentialDictionaryRevision) credentialDictionaryResponse {
	return credentialDictionaryResponse{ID: dictionary.ID, ProjectID: dictionary.ProjectID, Name: dictionary.Name, Kind: dictionary.Kind, Revision: revision.Revision, SHA256: revision.SHA256, Count: revision.ItemCount, CreatedAt: dictionary.CreatedAt}
}

func revealCredentialFinding(c *gin.Context) {
	if !currentUserIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "credential reveal requires tenant admin"})
		return
	}
	var finding db.CredentialFindingSecret
	if err := db.DB.Where("id = ? AND tenant_id = ?", c.Param("id"), currentTenantID(c)).First(&finding).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential finding not found"})
		return
	}
	if !canAccessProject(c, finding.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "credential vault unavailable"})
		return
	}
	plaintext, err := vault.Open(finding.Ciphertext, finding.Nonce, []byte("finding:"+finding.TenantID+":"+finding.ID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "credential finding cannot be decrypted"})
		return
	}
	if err := db.DB.Create(&db.CredentialRevealAudit{TenantID: finding.TenantID, ProjectID: finding.ProjectID, FindingID: finding.ID, ActorID: currentUserID(c), Action: "reveal"}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "credential reveal audit could not be persisted"})
		return
	}
	var secret struct {
		Username string          `json:"username"`
		Password string          `json:"password"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if json.Unmarshal(plaintext, &secret) != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "credential finding is invalid"})
		return
	}
	c.JSON(http.StatusOK, secret)
}
