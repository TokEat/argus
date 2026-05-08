package aliyun

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/user/dddd-server/internal/cloud"
)

func init() {
	cloud.RegisterOSSFactory("aliyun", func(akID, akSecret, endpoint, bucket string) (cloud.OSSUploader, error) {
		return NewOSSClient(akID, akSecret, endpoint, bucket)
	})
}

// OSSClient 封装阿里云 OSS 操作，实现 cloud.OSSUploader 接口
type OSSClient struct {
	client   *oss.Client
	bucket   *oss.Bucket
	endpoint string
}

// NewOSSClient 创建 OSS 客户端
func NewOSSClient(accessKeyID, accessKeySecret, endpoint, bucketName string) (*OSSClient, error) {
	client, err := oss.New(endpoint, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("create OSS client: %w", err)
	}

	bucket, err := client.Bucket(bucketName)
	if err != nil {
		return nil, fmt.Errorf("get OSS bucket %s: %w", bucketName, err)
	}

	return &OSSClient{
		client:   client,
		bucket:   bucket,
		endpoint: endpoint,
	}, nil
}

// UploadFile 上传本地文件到 OSS
func (o *OSSClient) UploadFile(localPath, objectKey string) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat local file %s: %w", localPath, err)
	}

	log.Printf("[OSS] Uploading %s → %s (%.1f MB)", localPath, objectKey, float64(info.Size())/(1024*1024))

	// 大文件使用分片上传（>100MB）
	if info.Size() > 100*1024*1024 {
		return o.bucket.UploadFile(objectKey, localPath, 10*1024*1024,
			oss.Routines(3),
			oss.Checkpoint(true, ""),
		)
	}

	return o.bucket.PutObjectFromFile(objectKey, localPath)
}

// DownloadFile 下载 OSS 对象到本地文件。
func (o *OSSClient) DownloadFile(objectKey, localPath string) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}
	return o.bucket.GetObjectToFile(objectKey, localPath)
}

// GeneratePresignedURL 生成带签名的临时下载 URL
func (o *OSSClient) GeneratePresignedURL(objectKey string, expiry time.Duration) (string, error) {
	url, err := o.bucket.SignURL(objectKey, oss.HTTPGet, int64(expiry.Seconds()))
	if err != nil {
		return "", fmt.Errorf("generate presigned URL: %w", err)
	}
	return url, nil
}

// UploadAgentBinaries 批量上传 release 目录中的 agent 二进制到 OSS
func (o *OSSClient) UploadAgentBinaries(releaseDir string) ([]cloud.OSSUploadResult, error) {
	entries, err := os.ReadDir(releaseDir)
	if err != nil {
		return nil, fmt.Errorf("read release dir %s: %w", releaseDir, err)
	}

	var results []cloud.OSSUploadResult
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isAgentBinary(name) {
			continue
		}

		localPath := filepath.Join(releaseDir, name)
		objectKey := fmt.Sprintf("argus/agent/%s", name)

		info, _ := entry.Info()
		result := cloud.OSSUploadResult{
			Filename:  name,
			ObjectKey: objectKey,
			Size:      info.Size(),
		}

		if err := o.UploadFile(localPath, objectKey); err != nil {
			result.Error = err.Error()
			log.Printf("[OSS] Failed to upload %s: %v", name, err)
		} else {
			result.Success = true
			log.Printf("[OSS] Uploaded %s successfully", name)
		}
		results = append(results, result)
	}

	return results, nil
}

// isAgentBinary 判断文件是否是 Agent 二进制
func isAgentBinary(name string) bool {
	return len(name) > 11 && name[:11] == "dddd-agent-"
}

// TestConnection 测试 OSS 连通性
func (o *OSSClient) TestConnection() error {
	_, err := o.bucket.ListObjects(oss.MaxKeys(1))
	return err
}

// ListFiles 列出存储桶中的文件
func (o *OSSClient) ListFiles(prefix string) ([]cloud.OSSFileInfo, error) {
	var results []cloud.OSSFileInfo
	marker := ""
	for {
		lsRes, err := o.bucket.ListObjects(oss.Prefix(prefix), oss.Marker(marker), oss.MaxKeys(100))
		if err != nil {
			return nil, err
		}
		for _, object := range lsRes.Objects {
			results = append(results, cloud.OSSFileInfo{
				Key:          object.Key,
				Size:         object.Size,
				LastModified: object.LastModified,
			})
		}
		if lsRes.IsTruncated {
			marker = lsRes.NextMarker
		} else {
			break
		}
	}
	return results, nil
}

// DeleteFile 删除存储桶中的文件
func (o *OSSClient) DeleteFile(objectKey string) error {
	return o.bucket.DeleteObject(objectKey)
}
