package api

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"gopkg.in/yaml.v3"
)

type WorkflowEntry struct {
	Type []string `yaml:"type" json:"type"`
	Pocs []string `yaml:"pocs" json:"pocs"`
}

// WorkflowItem 是传递给前端进行编辑的完整实体结构
type WorkflowItem struct {
	Product string   `json:"product"`
	Type    []string `json:"type"`
	Pocs    []string `json:"pocs"`
}

// fetchAndParseWorkflow 获取并解析数据库中的 workflow.yaml 单体内容
func fetchAndParseWorkflow() (map[string]WorkflowEntry, *db.Arsenal, error) {
	arsenal, err := db.FindArsenalByTypeAndFile("workflow", "workflow.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("workflow dictionary not found in arsenal")
	}

	var data map[string]WorkflowEntry
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yaml: %v", err)
	}

	if data == nil {
		data = make(map[string]WorkflowEntry)
	}
	return data, arsenal, nil
}

// saveWorkflow 序列化数据并覆盖保存回数据库
func saveWorkflow(data map[string]WorkflowEntry, arsenal *db.Arsenal) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	contentStr := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))

	arsenal.Content = contentStr
	arsenal.Hash = hash
	if err := db.DB.Save(arsenal).Error; err != nil {
		return err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return err
	}

	// 通知全局客户端热重载
	GlobalArsenalReloadCounter++
	return nil
}

func getWorkflowDict(c *gin.Context) {
	data, _, err := fetchAndParseWorkflow()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var results []WorkflowItem
	for k, v := range data {
		results = append(results, WorkflowItem{
			Product: k,
			Type:    v.Type,
			Pocs:    v.Pocs,
		})
	}

	c.JSON(http.StatusOK, results)
}

func addWorkflowDict(c *gin.Context) {
	var req WorkflowItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Product = strings.TrimSpace(req.Product)
	if req.Product == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product Name is required"})
		return
	}

	data, arsenal, err := fetchAndParseWorkflow()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[req.Product]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Product already exists"})
		return
	}

	data[req.Product] = WorkflowEntry{
		Type: req.Type,
		Pocs: req.Pocs,
	}

	if err := saveWorkflow(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "added", "product": req.Product})
}

func updateWorkflowDict(c *gin.Context) {
	product := c.Param("product")
	var req WorkflowItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, arsenal, err := fetchAndParseWorkflow()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	// 允许重命名键值
	req.Product = strings.TrimSpace(req.Product)
	if req.Product != "" && req.Product != product {
		// 如果更名了，需要确保新名字不冲突
		if _, exists := data[req.Product]; exists {
			c.JSON(http.StatusConflict, gin.H{"error": "New Product Name already exists"})
			return
		}
		delete(data, product)
		product = req.Product
	}

	data[product] = WorkflowEntry{
		Type: req.Type,
		Pocs: req.Pocs,
	}

	if err := saveWorkflow(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated", "product": product})
}

func deleteWorkflowDict(c *gin.Context) {
	product := c.Param("product")

	data, arsenal, err := fetchAndParseWorkflow()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	delete(data, product)

	if err := saveWorkflow(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted", "product": product})
}

// ---------------------- Fingerprint ----------------------

type FingerprintItem struct {
	Product string   `json:"product"`
	Rules   []string `json:"rules"` // 在 yaml 中直接对应字符串数组
}

// fetchAndParseFingerprint 获取并解析数据库中的 finger.yaml 单体内容
func fetchAndParseFingerprint() (map[string][]string, *db.Arsenal, error) {
	arsenal, err := db.FindArsenalByTypeAndFile("finger", "finger.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("fingerprint dictionary not found in arsenal")
	}

	var data map[string][]string
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yaml: %v", err)
	}

	if data == nil {
		data = make(map[string][]string)
	}
	return data, arsenal, nil
}

func saveFingerprint(data map[string][]string, arsenal *db.Arsenal) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	contentStr := string(out)
	arsenal.Content = contentStr
	arsenal.Hash = fmt.Sprintf("%x", md5.Sum(out))

	if err := db.DB.Save(arsenal).Error; err != nil {
		return err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return err
	}
	GlobalArsenalReloadCounter++
	return nil
}

func getFingerprintDict(c *gin.Context) {
	data, _, err := fetchAndParseFingerprint()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var results []FingerprintItem
	for k, v := range data {
		results = append(results, FingerprintItem{
			Product: k,
			Rules:   v,
		})
	}
	c.JSON(http.StatusOK, results)
}

func addFingerprintDict(c *gin.Context) {
	var req FingerprintItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Product = strings.TrimSpace(req.Product)
	if req.Product == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product Name is required"})
		return
	}

	data, arsenal, err := fetchAndParseFingerprint()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[req.Product]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Product already exists"})
		return
	}

	data[req.Product] = req.Rules
	if err := saveFingerprint(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "added", "product": req.Product})
}

func updateFingerprintDict(c *gin.Context) {
	product := c.Param("product")
	var req FingerprintItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, arsenal, err := fetchAndParseFingerprint()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	req.Product = strings.TrimSpace(req.Product)
	if req.Product != "" && req.Product != product {
		if _, exists := data[req.Product]; exists {
			c.JSON(http.StatusConflict, gin.H{"error": "New Product Name already exists"})
			return
		}
		delete(data, product)
		product = req.Product
	}

	data[product] = req.Rules
	if err := saveFingerprint(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated", "product": product})
}

func deleteFingerprintDict(c *gin.Context) {
	product := c.Param("product")
	data, arsenal, err := fetchAndParseFingerprint()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	delete(data, product)
	if err := saveFingerprint(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "product": product})
}

// ---------------------- Dir Probe ----------------------

type DirItem struct {
	Product string   `json:"product"`
	Paths   []string `json:"paths"`
}

func fetchAndParseDir() (map[string][]string, *db.Arsenal, error) {
	arsenal, err := db.FindArsenalByTypeAndFile("dir", "dir.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("dir dictionary not found in arsenal")
	}

	var data map[string][]string
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yaml: %v", err)
	}

	if data == nil {
		data = make(map[string][]string)
	}
	return data, arsenal, nil
}

func saveDir(data map[string][]string, arsenal *db.Arsenal) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	contentStr := string(out)
	arsenal.Content = contentStr
	arsenal.Hash = fmt.Sprintf("%x", md5.Sum(out))

	if err := db.DB.Save(arsenal).Error; err != nil {
		return err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return err
	}
	GlobalArsenalReloadCounter++
	return nil
}

func getDirDict(c *gin.Context) {
	data, _, err := fetchAndParseDir()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var results []DirItem
	for k, v := range data {
		results = append(results, DirItem{
			Product: k,
			Paths:   v,
		})
	}
	c.JSON(http.StatusOK, results)
}

func addDirDict(c *gin.Context) {
	var req DirItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Product = strings.TrimSpace(req.Product)
	if req.Product == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product Name is required"})
		return
	}

	data, arsenal, err := fetchAndParseDir()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[req.Product]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Product already exists"})
		return
	}

	data[req.Product] = req.Paths
	if err := saveDir(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "added", "product": req.Product})
}

func updateDirDict(c *gin.Context) {
	product := c.Param("product")
	var req DirItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, arsenal, err := fetchAndParseDir()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	req.Product = strings.TrimSpace(req.Product)
	if req.Product != "" && req.Product != product {
		if _, exists := data[req.Product]; exists {
			c.JSON(http.StatusConflict, gin.H{"error": "New Product Name already exists"})
			return
		}
		delete(data, product)
		product = req.Product
	}

	data[product] = req.Paths
	if err := saveDir(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated", "product": product})
}

func deleteDirDict(c *gin.Context) {
	product := c.Param("product")
	data, arsenal, err := fetchAndParseDir()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	delete(data, product)
	if err := saveDir(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "product": product})
}

