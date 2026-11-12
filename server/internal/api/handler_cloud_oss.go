package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/cloud"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

const requiredAgentObjectKey = "argus/agent/argus-agent-linux-amd64"

// listReleaseFiles 列出服务器端 ./release 目录中的 Agent 二进制文件
func (h *CloudHandler) listReleaseFiles(c *gin.Context) {
	if _, ok := h.loadCloudAccountForUse(c, c.Param("id"), false); !ok {
		return
	}

	releaseDir := h.ossService().ReleaseDir

	if _, err := os.Stat(releaseDir); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{"files": []interface{}{}, "release_dir": releaseDir})
		return
	}

	entries, err := os.ReadDir(releaseDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取 release 目录失败: %v", err)})
		return
	}

	type fileInfo struct {
		Name     string    `json:"name"`
		Size     int64     `json:"size"`
		Modified time.Time `json:"modified"`
	}

	var files []fileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{
			Name:     entry.Name(),
			Size:     info.Size(),
			Modified: info.ModTime(),
		})
	}

	if files == nil {
		files = []fileInfo{}
	}

	c.JSON(http.StatusOK, gin.H{"files": files, "release_dir": releaseDir})
}

// uploadAgentToOSS 将 release 目录中的 Agent 二进制上传到指定账号的 OSS 存储桶
// 支持可选的 files 参数来指定要上传的文件名列表
func (h *CloudHandler) uploadAgentToOSS(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = h.loadCloudAccountForUse(c, accountID, false); !ok {
		return
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OSS not configured for this account. Please set oss_bucket and oss_endpoint."})
		return
	}

	uploader, err := h.OSSFactory(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create OSS client: %v", err)})
		return
	}

	// 解析可选的 files 参数
	var req struct {
		Files []string `json:"files"`
	}
	_ = c.ShouldBindJSON(&req) // 忽略解析错误，兼容无 body 的请求

	releaseDir := h.ossService().ReleaseDir
	if _, err := os.Stat(releaseDir); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "服务器本地不存在 ./release 目录，请先构建 Agent 二进制或将制品放置到该目录下"})
		return
	}

	// 如果指定了 files 列表，只上传指定文件
	if len(req.Files) > 0 {
		results := h.ossService().UploadSelectedFiles(uploader, req.Files)

		successCount := 0
		for _, r := range results {
			if r.Success {
				successCount++
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": fmt.Sprintf("已上传 %d/%d 个文件到 OSS", successCount, len(results)),
			"results": results,
		})
		return
	}

	// 默认行为：上传全部 agent 二进制
	summary, err := h.ossService().UploadAgentBinaries(uploader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Upload failed: %v", err)})
		return
	}
	if len(summary.Results) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "./release 目录下未找到 Agent 二进制文件（argus-agent-*），请先构建 Agent"})
		return
	}
	if !summary.RequiredFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Required agent binary %s was not found in ./release", requiredAgentObjectKey)})
		return
	}
	if !summary.RequiredUploaded {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   fmt.Sprintf("Agent 核心制品未上传成功，当前成功 %d/%d", summary.SuccessCount, len(summary.Results)),
			"results": summary.Results,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"message":      fmt.Sprintf("Agent 制品已在 OSS 就绪（成功上传 %d/%d，非关键文件失败 %d 个）", summary.SuccessCount, len(summary.Results), summary.FailedCount),
		"failed_count": summary.FailedCount,
		"results":      summary.Results,
	})
}

func sanitizeReleaseFilename(name string) (string, error) {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return "", fmt.Errorf("文件名不能为空")
	}
	clean = filepath.Clean(clean)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/") || strings.Contains(clean, "\\") {
		return "", fmt.Errorf("非法文件名: %s", name)
	}
	if !strings.HasPrefix(clean, "argus-agent-") {
		return "", fmt.Errorf("仅允许上传 Agent 二进制文件: %s", clean)
	}
	return clean, nil
}

// uploadLocalAgentToOSS 接收本地上传的文件，保存到 ./release 目录并推送到 OSS
func (h *CloudHandler) uploadLocalAgentToOSS(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = h.loadCloudAccountForUse(c, accountID, false); !ok {
		return
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OSS not configured for this account. Please set oss_bucket and oss_endpoint."})
		return
	}

	uploader, err := h.OSSFactory(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create OSS client: %v", err)})
		return
	}

	// 确保 ./release 目录存在
	releaseDir := h.ossService().ReleaseDir
	if err := os.MkdirAll(releaseDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 release 目录失败: %v", err)})
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("解析上传表单失败: %v", err)})
		return
	}

	uploadedFiles := form.File["files"]
	if len(uploadedFiles) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供上传文件"})
		return
	}

	var results []cloud.OSSUploadResult
	for _, fileHeader := range uploadedFiles {
		filename, safeErr := sanitizeReleaseFilename(fileHeader.Filename)
		if safeErr != nil {
			results = append(results, cloud.OSSUploadResult{
				Filename: fileHeader.Filename,
				Error:    safeErr.Error(),
			})
			continue
		}
		localPath := filepath.Join(releaseDir, filename)
		objectKey := fmt.Sprintf("argus/agent/%s", filename)

		result := cloud.OSSUploadResult{
			Filename:  filename,
			ObjectKey: objectKey,
			Size:      fileHeader.Size,
		}

		// 保存到 ./release
		if err := c.SaveUploadedFile(fileHeader, localPath); err != nil {
			result.Error = fmt.Sprintf("保存文件失败: %v", err)
			results = append(results, result)
			continue
		}

		// 推送到 OSS
		if err := uploader.UploadFile(localPath, objectKey); err != nil {
			result.Error = fmt.Sprintf("OSS 上传失败: %v", err)
		} else {
			result.Success = true
		}
		results = append(results, result)
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("%d/%d 个文件已保存到服务器并上传到 OSS", successCount, len(results)),
		"results": results,
	})
}

// listOSSFiles 列出 OSS 存储桶中 argus/agent/ 前缀下的所有文件
func (h *CloudHandler) listOSSFiles(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = h.loadCloudAccountForUse(c, accountID, false); !ok {
		return
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		c.JSON(http.StatusOK, gin.H{"files": []interface{}{}, "bucket": "", "prefix": "argus/agent/"})
		return
	}

	uploader, err := h.OSSFactory(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 OSS 客户端失败: %v", err)})
		return
	}

	prefix := c.DefaultQuery("prefix", "argus/agent/")
	files, err := uploader.ListFiles(prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("列出 OSS 文件失败: %v", err)})
		return
	}

	if files == nil {
		files = []cloud.OSSFileInfo{}
	}

	c.JSON(http.StatusOK, gin.H{
		"files":  files,
		"bucket": account.OSSBucket,
		"prefix": prefix,
	})
}

// deleteOSSFile 从 OSS 存储桶中删除指定文件
func (h *CloudHandler) deleteOSSFile(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = h.loadCloudAccountForUse(c, accountID, false); !ok {
		return
	}

	var req struct {
		ObjectKey string `json:"object_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请指定要删除的文件 object_key"})
		return
	}

	// 安全检查：只允许删除 argus/agent/ 前缀的文件
	if !strings.HasPrefix(req.ObjectKey, "argus/agent/") {
		c.JSON(http.StatusForbidden, gin.H{"error": "只允许删除 argus/agent/ 前缀下的文件"})
		return
	}

	uploader, err := h.OSSFactory(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 OSS 客户端失败: %v", err)})
		return
	}

	if err := uploader.DeleteFile(req.ObjectKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除文件失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": fmt.Sprintf("已从 OSS 删除: %s", req.ObjectKey)})
}

// testOSSConnection 测试指定账号的 OSS 连通性，返回详细检测报告
func (h *CloudHandler) testOSSConnection(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = h.loadCloudAccountForUse(c, accountID, false); !ok {
		return
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OSS not configured"})
		return
	}

	uploader, err := h.OSSFactory(&account)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Failed to create OSS client: %v", err)})
		return
	}

	// 测试连通性
	connOK := true
	connErr := ""
	if err := uploader.TestConnection(); err != nil {
		connOK = false
		connErr = err.Error()
	}

	// 列出 agent 前缀下的文件
	var fileCount int
	var totalSize int64
	var agentFound bool
	var fileDetails []map[string]interface{}

	if connOK {
		files, err := uploader.ListFiles("argus/agent/")
		if err == nil {
			fileCount = len(files)
			for _, f := range files {
				totalSize += f.Size
				if f.Key == requiredAgentObjectKey {
					agentFound = true
				}
				fileDetails = append(fileDetails, map[string]interface{}{
					"key":  f.Key,
					"size": f.Size,
				})
			}
		}
	}

	result := gin.H{
		"status":         "ok",
		"connection":     connOK,
		"connection_err": connErr,
		"bucket":         account.OSSBucket,
		"endpoint":       account.OSSEndpoint,
		"file_count":     fileCount,
		"total_size":     totalSize,
		"agent_ready":    agentFound,
		"required_agent": requiredAgentObjectKey,
		"files":          fileDetails,
	}

	if !connOK {
		result["status"] = "error"
		result["message"] = fmt.Sprintf("OSS 连接失败: %s", connErr)
		c.JSON(http.StatusOK, result) // 返回 200 但 status=error，让前端解析详情
		return
	}

	result["message"] = "OSS 连通性测试通过"
	c.JSON(http.StatusOK, result)
}
