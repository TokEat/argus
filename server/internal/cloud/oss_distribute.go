package cloud

import (
	"fmt"
	"log"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
)

// ============================================================================
// OSS 分发管理 — Agent 二进制上传与预签名 URL 生成
//
// 通过 OSSUploader 接口解耦具体云厂商实现。
// ============================================================================

// OSSFileInfo 表示 OSS 存储桶中的文件信息
type OSSFileInfo struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}

// OSSUploader OSS 操作抽象接口
type OSSUploader interface {
	UploadFile(localPath, objectKey string) error
	DownloadFile(objectKey, localPath string) error
	GeneratePresignedURL(objectKey string, expiry time.Duration) (string, error)
	UploadAgentBinaries(releaseDir string) ([]OSSUploadResult, error)
	TestConnection() error
	ListFiles(prefix string) ([]OSSFileInfo, error)
	DeleteFile(objectKey string) error
}

// OSSUploadResult 上传结果
type OSSUploadResult struct {
	Filename  string `json:"filename"`
	ObjectKey string `json:"object_key"`
	Size      int64  `json:"size"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// OSSUploaderFactory 创建 OSSUploader 的工厂函数
type OSSUploaderFactory func(akID, akSecret, endpoint, bucket string) (OSSUploader, error)

var (
	ossFactories = make(map[string]OSSUploaderFactory)
)

// RegisterOSSFactory 注册 OSS 工厂函数
func RegisterOSSFactory(provider string, factory OSSUploaderFactory) {
	ossFactories[provider] = factory
}

// NewOSSFromAccount 根据 CloudAccount 创建 OSSUploader
func NewOSSFromAccount(account *db.CloudAccount) (OSSUploader, error) {
	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		return nil, fmt.Errorf("OSS not configured for account %s (missing bucket or endpoint)", account.Name)
	}

	akID, err := DecryptSecret(account.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("decrypt access_key_id: %w", err)
	}
	akSecret, err := DecryptSecret(account.AccessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt access_key_secret: %w", err)
	}

	factory, ok := ossFactories[account.Provider]
	if !ok {
		return nil, fmt.Errorf("no OSS factory registered for provider: %s", account.Provider)
	}

	return factory(akID, akSecret, account.OSSEndpoint, account.OSSBucket)
}

// GenerateAgentDownloadURL 为指定账号生成 Agent 二进制的预签名下载 URL
func GenerateAgentDownloadURL(account *db.CloudAccount, platform, arch string) (string, error) {
	uploader, err := NewOSSFromAccount(account)
	if err != nil {
		return "", err
	}

	objectKey := fmt.Sprintf("argus/agent/argus-agent-%s-%s", platform, arch)
	url, err := uploader.GeneratePresignedURL(objectKey, 1*time.Hour)
	if err != nil {
		return "", fmt.Errorf("generate presigned URL: %w", err)
	}

	log.Printf("[OSS] Generated presigned URL for %s (expires in 1h)", objectKey)
	return url, nil
}
