package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/P0lar1ght/argus/server/internal/cloud"
	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

// CloudSetupService coordinates resource discovery and one-click setup work.
type CloudSetupService struct {
	DB              *gorm.DB
	ProviderFactory CloudProviderFactory
	CatalogFactory  CloudCatalogFactory
	OSSFactory      CloudOSSFactory
}

func NewCloudSetupService(store *gorm.DB, providerFactory CloudProviderFactory, ossFactory CloudOSSFactory) *CloudSetupService {
	return &CloudSetupService{DB: store, ProviderFactory: providerFactory, OSSFactory: ossFactory}
}

type cloudServiceError struct {
	Status  int
	Message string
}

func (e *cloudServiceError) Error() string {
	return e.Message
}

type cloudResourceDiscoverer interface {
	DiscoverResources() (interface{}, error)
}

type cloudNetworkBuilder interface {
	AutoCreateNetwork() (sgID string, vswID string, err error)
	AutoCreateOSS(accountID string) (bucketName string, endpoint string, err error)
}

type cloudResourceItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type cloudInstanceTypeItem struct {
	ID          string  `json:"id"`
	CPU         int     `json:"cpu"`
	Memory      float64 `json:"memory_gb"`
	Family      string  `json:"family"`
	HourlyPrice float64 `json:"hourly_price"`
}

type cloudDiscoveryResult struct {
	SecurityGroups []cloudResourceItem     `json:"security_groups"`
	VSwitches      []cloudResourceItem     `json:"v_switches"`
	Images         []cloudResourceItem     `json:"images"`
	InstanceTypes  []cloudInstanceTypeItem `json:"instance_types"`
}

func (s *CloudSetupService) DiscoverResources(account *db.CloudAccount) (interface{}, *cloudServiceError) {
	provider, err := s.ProviderFactory(account)
	if err != nil {
		return nil, &cloudServiceError{Status: http.StatusInternalServerError, Message: fmt.Sprintf("创建 Provider 失败: %v", err)}
	}
	discoverer, ok := provider.(cloudResourceDiscoverer)
	if !ok {
		return nil, &cloudServiceError{Status: http.StatusBadRequest, Message: "该 Provider 不支持资源发现"}
	}
	result, err := discoverer.DiscoverResources()
	if err != nil {
		return nil, &cloudServiceError{Status: http.StatusInternalServerError, Message: fmt.Sprintf("资源发现失败: %v", err)}
	}
	return result, nil
}

func (s *CloudSetupService) OneClickSetup(actor RequestActor, account db.CloudAccount, oss *CloudOSSService) (map[string]interface{}, *cloudServiceError) {
	provider, err := s.ProviderFactory(&account)
	if err != nil {
		return nil, &cloudServiceError{Status: http.StatusInternalServerError, Message: fmt.Sprintf("创建 Provider 失败: %v", err)}
	}
	discoverer, ok := provider.(cloudResourceDiscoverer)
	if !ok {
		return nil, &cloudServiceError{Status: http.StatusBadRequest, Message: "该 Provider 不支持资源发现"}
	}
	rawResult, err := discoverer.DiscoverResources()
	if err != nil {
		return nil, &cloudServiceError{Status: http.StatusInternalServerError, Message: fmt.Sprintf("资源发现失败: %v", err)}
	}

	jsonBytes, _ := json.Marshal(rawResult)
	var result cloudDiscoveryResult
	_ = json.Unmarshal(jsonBytes, &result)

	var warnings []string
	updates := map[string]interface{}{}
	chosen := map[string]string{}
	if len(result.SecurityGroups) == 0 || len(result.VSwitches) == 0 {
		if builder, ok := provider.(cloudNetworkBuilder); ok {
			sgID, vswID, autoErr := builder.AutoCreateNetwork()
			if autoErr == nil {
				if len(result.SecurityGroups) == 0 && sgID != "" {
					result.SecurityGroups = []cloudResourceItem{{ID: sgID, Name: "argus-auto-sg", Desc: "Auto created"}}
				}
				if len(result.VSwitches) == 0 && vswID != "" {
					result.VSwitches = []cloudResourceItem{{ID: vswID, Name: "argus-auto-vsw", Desc: "Auto created"}}
				}
			} else {
				warnings = append(warnings, fmt.Sprintf("自动创建网络资源失败: %v", autoErr))
			}
		}
	}

	if len(result.InstanceTypes) > 0 {
		pick := chooseOneClickInstanceTypeFromDiscovery(result.InstanceTypes)
		updates["default_instance_type"] = pick
		chosen["instance_type"] = pick
	} else {
		warnings = append(warnings, "未发现可用的实例规格（可能缺少 DescribeInstanceTypes 权限）")
	}

	if len(result.Images) > 0 {
		pick := result.Images[0].ID
		pickName := result.Images[0].Name
		for _, image := range result.Images {
			if containsIgnoreCase(image.Name, "ubuntu") && containsIgnoreCase(image.Name, "22") {
				pick = image.ID
				pickName = image.Name
				break
			}
		}
		updates["default_image_id"] = pick
		chosen["image_id"] = pick
		chosen["image_name"] = pickName
	} else {
		warnings = append(warnings, "未发现可用的系统镜像（可能缺少 DescribeImages 权限）")
	}

	if len(result.SecurityGroups) > 0 {
		updates["default_security_group"] = result.SecurityGroups[0].ID
		chosen["security_group"] = result.SecurityGroups[0].ID
		chosen["security_group_name"] = result.SecurityGroups[0].Name
	} else {
		warnings = append(warnings, "未发现安全组。请确认: 1) AK/SK 有 DescribeSecurityGroups 权限 2) 该地域下已创建 VPC 和安全组")
	}
	if len(result.VSwitches) > 0 {
		updates["default_v_switch"] = result.VSwitches[0].ID
		chosen["v_switch"] = result.VSwitches[0].ID
		chosen["v_switch_name"] = result.VSwitches[0].Name
	} else {
		warnings = append(warnings, "未发现交换机 (VSwitch)。请确认: 1) AK/SK 有 DescribeVSwitches 权限 2) 该地域下已创建 VPC 和交换机")
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		if builder, ok := provider.(cloudNetworkBuilder); ok {
			bucketName, endpoint, autoErr := builder.AutoCreateOSS(account.ID)
			if autoErr == nil {
				updates["oss_bucket"] = bucketName
				updates["oss_endpoint"] = endpoint
				chosen["oss_bucket"] = bucketName
				chosen["oss_endpoint"] = endpoint
				account.OSSBucket = bucketName
				account.OSSEndpoint = endpoint
			} else {
				warnings = append(warnings, fmt.Sprintf("自动创建 OSS 存储桶失败: %v", autoErr))
			}
		}
	}

	if account.OSSBucket != "" && account.OSSEndpoint != "" {
		if err := oss.EnsureRequiredAgentArtifact(&account); err != nil {
			return nil, &cloudServiceError{Status: http.StatusInternalServerError, Message: fmt.Sprintf("Agent binary is not ready for OSS distribution: %v", err)}
		}
	}
	if len(updates) > 0 {
		if err := s.DB.Model(&db.CloudAccount{}).Where("id = ? AND tenant_id = ?", account.ID, actor.TenantID).Updates(updates).Error; err != nil {
			return nil, &cloudServiceError{Status: http.StatusInternalServerError, Message: err.Error()}
		}
	}

	policyCreated := false
	var existingPolicy db.CloudScalingPolicy
	if err := s.DB.Where("cloud_account_id = ? AND tenant_id = ?", account.ID, actor.TenantID).First(&existingPolicy).Error; err != nil {
		newPolicy := db.CloudScalingPolicy{
			ID:                 fmt.Sprintf("cp-%d", time.Now().UnixNano()),
			TenantID:           actor.TenantID,
			CloudAccountID:     account.ID,
			Name:               fmt.Sprintf("经济型弹性扫描策略 - %s", account.Name),
			Enabled:            false,
			MinInstances:       0,
			MaxInstances:       5,
			ScaleUpThreshold:   50,
			ScaleDownThreshold: 0,
			CooldownSeconds:    180,
			InstanceTTLMinutes: 60,
			SpotStrategy:       "SpotAsPriceGo",
		}
		if err := s.DB.Create(&newPolicy).Error; err == nil {
			policyCreated = true
		}
	}
	_ = s.DB.Where("id = ? AND tenant_id = ?", account.ID, actor.TenantID).First(&account).Error

	return map[string]interface{}{
		"status":         "ok",
		"message":        "一键配置完成",
		"chosen":         chosen,
		"warnings":       warnings,
		"policy_created": policyCreated,
		"current_config": map[string]interface{}{
			"region": account.Region, "instance_type": account.DefaultInstanceType,
			"image_id": account.DefaultImageID, "security_group": account.DefaultSecurityGroup,
			"v_switch": account.DefaultVSwitch, "oss_bucket": account.OSSBucket,
			"oss_endpoint": account.OSSEndpoint,
		},
		"discovery": map[string]interface{}{
			"security_groups": len(result.SecurityGroups), "v_switches": len(result.VSwitches),
			"images": len(result.Images), "instance_types": len(result.InstanceTypes),
		},
	}, nil
}

// CloudOSSService coordinates release artifact and OSS operations.
type CloudOSSService struct {
	OSSFactory CloudOSSFactory
	ReleaseDir string
}

type cloudUploadSummary struct {
	Results          []cloud.OSSUploadResult
	SuccessCount     int
	FailedCount      int
	RequiredFound    bool
	RequiredUploaded bool
}

func NewCloudOSSService(ossFactory CloudOSSFactory, releaseDir string) *CloudOSSService {
	return &CloudOSSService{OSSFactory: ossFactory, ReleaseDir: releaseDir}
}

func (s *CloudOSSService) UploadSelectedFiles(uploader cloud.OSSUploader, files []string) []cloud.OSSUploadResult {
	results := make([]cloud.OSSUploadResult, 0, len(files))
	for _, filename := range files {
		safeName, err := sanitizeReleaseFilename(filename)
		if err != nil {
			results = append(results, cloud.OSSUploadResult{Filename: filename, Error: err.Error()})
			continue
		}
		localPath := filepath.Join(s.ReleaseDir, safeName)
		objectKey := fmt.Sprintf("argus/agent/%s", safeName)
		info, err := os.Stat(localPath)
		if err != nil {
			results = append(results, cloud.OSSUploadResult{Filename: safeName, ObjectKey: objectKey, Error: fmt.Sprintf("文件不存在: %v", err)})
			continue
		}
		result := cloud.OSSUploadResult{Filename: safeName, ObjectKey: objectKey, Size: info.Size()}
		if err := uploader.UploadFile(localPath, objectKey); err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
		}
		results = append(results, result)
	}
	return results
}

func (s *CloudOSSService) UploadAgentBinaries(uploader cloud.OSSUploader) (cloudUploadSummary, error) {
	results, err := uploader.UploadAgentBinaries(s.ReleaseDir)
	if err != nil {
		return cloudUploadSummary{}, err
	}
	summary := cloudUploadSummary{Results: results}
	for _, result := range results {
		if result.Success {
			summary.SuccessCount++
		} else {
			summary.FailedCount++
		}
		if result.ObjectKey == requiredAgentObjectKey {
			summary.RequiredFound = true
			summary.RequiredUploaded = result.Success
		}
	}
	return summary, nil
}

func (s *CloudOSSService) EnsureRequiredAgentArtifact(account *db.CloudAccount) error {
	uploader, err := s.OSSFactory(account)
	if err != nil {
		return fmt.Errorf("create OSS client: %w", err)
	}
	exists, err := s.objectExists(uploader, requiredAgentObjectKey)
	if err != nil {
		return fmt.Errorf("check existing agent artifact: %w", err)
	}
	if exists {
		return nil
	}
	results, err := uploader.UploadAgentBinaries(s.ReleaseDir)
	if err != nil {
		return fmt.Errorf("upload agent binaries: %w", err)
	}
	if len(results) == 0 {
		return fmt.Errorf("no agent binaries found in %s", s.ReleaseDir)
	}
	requiredFound := false
	for _, result := range results {
		if result.ObjectKey != requiredAgentObjectKey {
			continue
		}
		requiredFound = true
		if !result.Success {
			return fmt.Errorf("upload %s failed: %s", requiredAgentObjectKey, result.Error)
		}
	}
	if !requiredFound {
		return fmt.Errorf("required agent binary %s is missing from %s", requiredAgentObjectKey, s.ReleaseDir)
	}
	exists, err = s.objectExists(uploader, requiredAgentObjectKey)
	if err != nil {
		return fmt.Errorf("verify uploaded agent artifact: %w", err)
	}
	if !exists {
		return fmt.Errorf("required agent artifact %s is still missing from OSS after upload", requiredAgentObjectKey)
	}
	return nil
}

func (s *CloudOSSService) objectExists(uploader cloud.OSSUploader, objectKey string) (bool, error) {
	files, err := uploader.ListFiles("argus/agent/")
	if err != nil {
		return false, err
	}
	for _, file := range files {
		if file.Key == objectKey {
			return true, nil
		}
	}
	return false, nil
}
