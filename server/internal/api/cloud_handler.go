package api

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/cloud/aliyun"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

// RequestActor is the authorization context used by cloud operations.
type RequestActor struct {
	TenantID string
	UserID   string
	Role     string
}

func requestActor(c *gin.Context) RequestActor {
	role := strings.TrimSpace(c.GetString("role"))
	if role == "" {
		role = "viewer"
	}
	return RequestActor{
		TenantID: currentTenantID(c),
		UserID:   strings.TrimSpace(c.GetString("user_id")),
		Role:     role,
	}
}

func (a RequestActor) IsAdmin() bool {
	return a.Role == "admin"
}

type CloudProviderFactory func(*db.CloudAccount) (cloud.CloudProvider, error)
type CloudOSSFactory func(*db.CloudAccount) (cloud.OSSUploader, error)
type CloudPermissionChecker func(string, string, string) (*aliyun.PermissionCheckResult, error)
type CloudCatalog interface {
	QueryPrice(string, string) (*aliyun.PriceInfo, error)
	QueryAvailableInstanceTypes(string) ([]aliyun.AvailableInstanceType, error)
}
type CloudCatalogFactory func(string, string, string) (CloudCatalog, error)

func defaultCloudCatalogFactory(accessKeyID, accessKeySecret, region string) (CloudCatalog, error) {
	return aliyun.NewECSProvider(accessKeyID, accessKeySecret, region)
}

// CloudHandler owns the dependencies used by Cloud API handlers.
type CloudHandler struct {
	DB              *gorm.DB
	AutoScaler      *cloud.AutoScaler
	ProviderFactory CloudProviderFactory
	OSSFactory      CloudOSSFactory
	PermissionCheck CloudPermissionChecker
	CatalogFactory  CloudCatalogFactory
	Setup           *CloudSetupService
	OSS             *CloudOSSService
}

func NewCloudHandler(store *gorm.DB, autoScaler *cloud.AutoScaler) *CloudHandler {
	handler := &CloudHandler{
		DB:              store,
		AutoScaler:      autoScaler,
		ProviderFactory: cloud.NewProviderFromAccount,
		OSSFactory:      cloud.NewOSSFromAccount,
		PermissionCheck: aliyun.CheckPermissions,
		CatalogFactory:  defaultCloudCatalogFactory,
	}
	handler.rebuildServices()
	return handler
}

func (h *CloudHandler) normalize() *CloudHandler {
	if h == nil {
		return NewCloudHandler(db.DB, nil)
	}
	if h.DB == nil {
		h.DB = db.DB
	}
	if h.ProviderFactory == nil {
		h.ProviderFactory = cloud.NewProviderFromAccount
	}
	if h.OSSFactory == nil {
		h.OSSFactory = cloud.NewOSSFromAccount
	}
	if h.PermissionCheck == nil {
		h.PermissionCheck = aliyun.CheckPermissions
	}
	if h.CatalogFactory == nil {
		h.CatalogFactory = defaultCloudCatalogFactory
	}
	h.rebuildServices()
	return h
}

func (h *CloudHandler) rebuildServices() {
	if h.Setup == nil {
		h.Setup = NewCloudSetupService(h.DB, h.ProviderFactory, h.OSSFactory)
	}
	if h.OSS == nil {
		h.OSS = NewCloudOSSService(h.OSSFactory, "./release")
	}
}

func (h *CloudHandler) setupService() *CloudSetupService {
	h.rebuildServices()
	h.Setup.DB = h.DB
	h.Setup.ProviderFactory = h.ProviderFactory
	h.Setup.CatalogFactory = h.CatalogFactory
	h.Setup.OSSFactory = h.OSSFactory
	return h.Setup
}

func (h *CloudHandler) ossService() *CloudOSSService {
	h.rebuildServices()
	h.OSS.OSSFactory = h.OSSFactory
	return h.OSS
}

func cloudRuntime() *CloudHandler {
	return routerRuntime().Cloud
}
