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

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type subdomainDictionaryRequest struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type subdomainDictionaryResponse struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	Name      string    `json:"name"`
	Revision  int       `json:"revision"`
	SHA256    string    `json:"sha256"`
	Count     int       `json:"count"`
	CreatedAt time.Time `json:"created_at"`
}

func createSubdomainDictionary(c *gin.Context) {
	project, ok := requireProjectManage(c, c.Param("id"))
	if !ok {
		return
	}
	req, values, ok := decodeSubdomainDictionaryRequest(c, true)
	if !ok {
		return
	}
	dictionary := db.SubdomainDictionary{
		ID: uuid.NewString(), TenantID: currentTenantID(c), ProjectID: project.ID,
		Name: strings.TrimSpace(req.Name), CreatedBy: currentUserID(c),
	}
	revision, err := newSubdomainDictionaryRevision(dictionary, 1, values, currentUserID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode dictionary revision"})
		return
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&dictionary).Error; err != nil {
			return err
		}
		return tx.Create(&revision).Error
	}); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "dictionary name already exists or could not be stored"})
		return
	}
	c.JSON(http.StatusCreated, subdomainDictionaryView(dictionary, revision))
}

func addSubdomainDictionaryRevision(c *gin.Context) {
	project, ok := requireProjectManage(c, c.Param("id"))
	if !ok {
		return
	}
	_, values, ok := decodeSubdomainDictionaryRequest(c, false)
	if !ok {
		return
	}
	var dictionary db.SubdomainDictionary
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ? AND project_id = ?", c.Param("dictionary_id"), currentTenantID(c), project.ID).
			First(&dictionary).Error; err != nil {
			return err
		}
		var latest int
		if err := tx.Model(&db.SubdomainDictionaryRevision{}).Where("dictionary_id = ?", dictionary.ID).
			Select("COALESCE(MAX(revision), 0)").Scan(&latest).Error; err != nil {
			return err
		}
		revision, err := newSubdomainDictionaryRevision(dictionary, latest+1, values, currentUserID(c))
		if err != nil {
			return err
		}
		return tx.Create(&revision).Error
	})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dictionary not found or revision could not be stored"})
		return
	}
	var revision db.SubdomainDictionaryRevision
	db.DB.Where("dictionary_id = ?", dictionary.ID).Order("revision desc").First(&revision)
	c.JSON(http.StatusCreated, subdomainDictionaryView(dictionary, revision))
}

func listSubdomainDictionaries(c *gin.Context) {
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}
	var dictionaries []db.SubdomainDictionary
	if err := db.DB.Where("tenant_id = ? AND project_id = ?", currentTenantID(c), project.ID).
		Order("name").Find(&dictionaries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load dictionaries"})
		return
	}
	items := make([]subdomainDictionaryResponse, 0, len(dictionaries))
	for _, dictionary := range dictionaries {
		var revision db.SubdomainDictionaryRevision
		if err := db.DB.Where("dictionary_id = ? AND tenant_id = ?", dictionary.ID, currentTenantID(c)).
			Order("revision desc").First(&revision).Error; err == nil {
			items = append(items, subdomainDictionaryView(dictionary, revision))
		}
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func deleteSubdomainDictionary(c *gin.Context) {
	project, ok := requireProjectManage(c, c.Param("id"))
	if !ok {
		return
	}
	result := db.DB.Where("id = ? AND tenant_id = ? AND project_id = ?", c.Param("dictionary_id"), currentTenantID(c), project.ID).
		Delete(&db.SubdomainDictionary{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete dictionary"})
		return
	}
	if result.RowsAffected != 1 {
		c.JSON(http.StatusNotFound, gin.H{"error": "dictionary not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

func decodeSubdomainDictionaryRequest(c *gin.Context, requireName bool) (subdomainDictionaryRequest, []string, bool) {
	var req subdomainDictionaryRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maximumDictionaryRequestBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return req, nil, false
	}
	req.Name = strings.TrimSpace(req.Name)
	if requireName && (req.Name == "" || len(req.Name) > 160) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required and must not exceed 160 bytes"})
		return req, nil, false
	}
	values, err := normalizeSubdomainDictionaryValues(req.Values)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return req, nil, false
	}
	return req, values, true
}

func normalizeSubdomainDictionaryValues(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("values must not be empty")
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" || len(value) > 63 || !validSubdomainLabel(value) {
			return nil, fmt.Errorf("invalid single-label subdomain word %q", raw)
		}
		seen[value] = struct{}{}
		if len(seen) > maximumDictionaryItems {
			return nil, fmt.Errorf("dictionary exceeds %d unique items", maximumDictionaryItems)
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validSubdomainLabel(value string) bool {
	if strings.Contains(value, ".") || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
			return false
		}
	}
	return true
}

func newSubdomainDictionaryRevision(dictionary db.SubdomainDictionary, revision int, values []string, actorID string) (db.SubdomainDictionaryRevision, error) {
	encoded, err := json.Marshal(values)
	if err != nil {
		return db.SubdomainDictionaryRevision{}, err
	}
	sum := sha256.Sum256(encoded)
	return db.SubdomainDictionaryRevision{
		TenantID: dictionary.TenantID, ProjectID: dictionary.ProjectID, DictionaryID: dictionary.ID,
		Revision: revision, SHA256: hex.EncodeToString(sum[:]), ItemCount: len(values),
		ValuesJSON: string(encoded), CreatedBy: actorID,
	}, nil
}

func subdomainDictionaryView(dictionary db.SubdomainDictionary, revision db.SubdomainDictionaryRevision) subdomainDictionaryResponse {
	return subdomainDictionaryResponse{
		ID: dictionary.ID, ProjectID: dictionary.ProjectID, Name: dictionary.Name,
		Revision: revision.Revision, SHA256: revision.SHA256, Count: revision.ItemCount, CreatedAt: dictionary.CreatedAt,
	}
}
