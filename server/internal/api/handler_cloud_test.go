package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/cloud"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type fakeCloudProvider struct {
	discovery interface{}
}

func (p *fakeCloudProvider) CreateInstance(cfg cloud.InstanceConfig) (*cloud.Instance, error) {
	return &cloud.Instance{ID: "fake-instance"}, nil
}

func (p *fakeCloudProvider) WaitReady(ctx context.Context, instanceID string, timeout time.Duration) error {
	return nil
}

func (p *fakeCloudProvider) GetInstanceIP(instanceID string) (string, error) {
	return "10.0.0.8", nil
}

func (p *fakeCloudProvider) RebootInstance(instanceID string) error {
	return nil
}

func (p *fakeCloudProvider) TerminateInstance(instanceID string) error {
	return nil
}

func (p *fakeCloudProvider) ListInstances(tags map[string]string) ([]*cloud.Instance, error) {
	return nil, nil
}

func (p *fakeCloudProvider) DiscoverResources() (interface{}, error) {
	return p.discovery, nil
}

type fakeOSSUploader struct {
	files         []cloud.OSSFileInfo
	uploadResults []cloud.OSSUploadResult
	uploadErr     error
}

func (o *fakeOSSUploader) UploadFile(localPath, objectKey string) error {
	return nil
}

func (o *fakeOSSUploader) DownloadFile(objectKey, localPath string) error {
	return nil
}

func (o *fakeOSSUploader) GeneratePresignedURL(objectKey string, expiry time.Duration) (string, error) {
	return "https://example.com/" + objectKey, nil
}

func (o *fakeOSSUploader) UploadAgentBinaries(releaseDir string) ([]cloud.OSSUploadResult, error) {
	return o.uploadResults, o.uploadErr
}

func (o *fakeOSSUploader) TestConnection() error {
	return nil
}

func (o *fakeOSSUploader) ListFiles(prefix string) ([]cloud.OSSFileInfo, error) {
	return o.files, nil
}

func (o *fakeOSSUploader) DeleteFile(objectKey string) error {
	return nil
}

var (
	registerCloudHandlerTestFactories sync.Once
	fakeProviderDiscovery             interface{}
	fakeUploader                      *fakeOSSUploader
)

func ensureCloudHandlerTestFactories() {
	registerCloudHandlerTestFactories.Do(func() {
		cloud.RegisterProviderFactory("fake-review", func(akID, akSecret, region string) (cloud.CloudProvider, error) {
			return &fakeCloudProvider{discovery: fakeProviderDiscovery}, nil
		})
		cloud.RegisterOSSFactory("fake-review", func(akID, akSecret, endpoint, bucket string) (cloud.OSSUploader, error) {
			return fakeUploader, nil
		})
	})
}

func setupCloudHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(
		&db.CloudAccount{},
		&db.CloudAccountBinding{},
		&db.CloudScalingPolicy{},
		&db.CloudInstance{},
		&db.User{},
		&db.WSEventLog{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	oldCloud := routerRuntime().Cloud
	db.DB = store
	routerRuntime().Cloud = NewCloudHandler(store, nil)
	t.Cleanup(func() {
		db.DB = old
		routerRuntime().Cloud = oldCloud
	})
	return store
}

func newTenantContext(method, target string) (*gin.Context, *httptest.ResponseRecorder) {
	return newTenantContextWithRole(method, target, "admin", "1")
}

func newTenantContextWithRole(method, target, role, userID string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, nil)
	ctx.Set("tenant", "default")
	ctx.Set("role", role)
	ctx.Set("user_id", userID)
	return ctx, recorder
}

func TestDeleteCloudAccountBlocksActiveInstances(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "ca-1", TenantID: "default", Name: "test"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.Create(&db.CloudInstance{
		ID:             "ci-1",
		TenantID:       "default",
		CloudAccountID: account.ID,
		Status:         db.CloudStatusRunning,
	}).Error; err != nil {
		t.Fatalf("seed cloud instance: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodDelete, "/cloud/accounts/"+account.ID)
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().deleteCloudAccount(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	var count int64
	store.Model(&db.CloudAccount{}).Where("id = ?", account.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected account to remain, count=%d", count)
	}
}

func TestCleanupCloudInstancesRequiresExplicitConfirmation(t *testing.T) {
	setupCloudHandlerTestDB(t)

	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/instances/cleanup")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cloud/instances/cleanup", strings.NewReader(`{"confirm":false}`))
	cloudRuntime().cleanupCloudInstances(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without confirmation, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestCleanupCloudInstancesSoftDeletesOnlyAccessibleTerminalRecords(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	accounts := []db.CloudAccount{
		{ID: "ca-owned", TenantID: "default", OwnerUserID: "2", Name: "owned"},
		{ID: "ca-other", TenantID: "default", OwnerUserID: "3", Name: "other"},
	}
	if err := store.Create(&accounts).Error; err != nil {
		t.Fatalf("seed accounts: %v", err)
	}
	instances := []db.CloudInstance{
		{ID: "terminated", TenantID: "default", CloudAccountID: "ca-owned", Status: db.CloudStatusTerminated},
		{ID: "error", TenantID: "default", CloudAccountID: "ca-owned", Status: db.CloudStatusError},
		{ID: "running", TenantID: "default", CloudAccountID: "ca-owned", Status: db.CloudStatusRunning},
		{ID: "other-user", TenantID: "default", CloudAccountID: "ca-other", Status: db.CloudStatusError},
	}
	if err := store.Create(&instances).Error; err != nil {
		t.Fatalf("seed instances: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/cloud/instances/cleanup", "operator", "2")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cloud/instances/cleanup", strings.NewReader(`{"confirm":true,"reason":"test cleanup"}`))
	cloudRuntime().cleanupCloudInstances(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"count":2`) {
		t.Fatalf("expected response count=2, got %s", recorder.Body.String())
	}

	for _, id := range []string{"terminated", "error"} {
		var count int64
		store.Unscoped().Model(&db.CloudInstance{}).Where("id = ? AND deleted_at IS NOT NULL", id).Count(&count)
		if count != 1 {
			t.Fatalf("expected %s to be soft deleted, count=%d", id, count)
		}
	}
	for _, id := range []string{"running", "other-user"} {
		var count int64
		store.Model(&db.CloudInstance{}).Where("id = ?", id).Count(&count)
		if count != 1 {
			t.Fatalf("expected %s to remain visible, count=%d", id, count)
		}
	}
	var event db.WSEventLog
	if err := store.Where("event_type = ?", "cloud.instances.cleanup").First(&event).Error; err != nil {
		t.Fatalf("expected cleanup audit event: %v", err)
	}
	if !strings.Contains(event.Payload, `"count":2`) || !strings.Contains(event.Payload, `"operator_id":"2"`) {
		t.Fatalf("unexpected cleanup audit payload: %s", event.Payload)
	}
}

func TestDeleteCloudAccountBlocksBoundPolicies(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "ca-2", TenantID: "default", Name: "test"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.Create(&db.CloudScalingPolicy{
		ID:             "cp-1",
		TenantID:       "default",
		CloudAccountID: account.ID,
		Name:           "policy",
	}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodDelete, "/cloud/accounts/"+account.ID)
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().deleteCloudAccount(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestCreateCloudPolicyBindsSnakeCasePayload(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "ca-policy", TenantID: "default", Name: "test"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	body := `{
		"name": "policy",
		"cloud_account_id": "ca-policy",
		"min_instances": 1,
		"max_instances": 7,
		"scale_up_threshold": 42,
		"scale_down_threshold": 2,
		"cooldown_seconds": 180,
		"instance_ttl_minutes": 60,
		"spot_strategy": "SpotAsPriceGo",
		"user_data_template": "cloud-init-template"
	}`
	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/policies")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cloud/policies", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("tenant", "default")
	cloudRuntime().createCloudPolicy(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	var policy db.CloudScalingPolicy
	if err := store.Where("cloud_account_id = ?", account.ID).First(&policy).Error; err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if policy.CloudAccountID != account.ID ||
		policy.MinInstances != 1 ||
		policy.MaxInstances != 7 ||
		policy.ScaleUpThreshold != 42 ||
		policy.ScaleDownThreshold != 2 ||
		policy.CooldownSeconds != 180 ||
		policy.InstanceTTLMinutes != 60 ||
		policy.SpotStrategy != "SpotAsPriceGo" ||
		policy.UserDataTemplate != "cloud-init-template" {
		t.Fatalf("policy was not bound from snake_case payload: %+v", policy)
	}
}

func TestCloudAccountBindingsRestrictOperatorAccess(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	users := []db.User{
		{ID: 1, TenantID: "default", Username: "admin", Role: "admin", Status: "active"},
		{ID: 2, TenantID: "default", Username: "op-a", Role: "operator", Status: "active"},
		{ID: 3, TenantID: "default", Username: "op-b", Role: "operator", Status: "active"},
	}
	for _, user := range users {
		if err := store.Create(&user).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	account := db.CloudAccount{ID: "ca-bound", TenantID: "default", OwnerUserID: "2", Name: "owned-by-a", Provider: "aliyun", Status: "active"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.Create(&db.CloudAccountBinding{TenantID: "default", CloudAccountID: account.ID, UserID: "2", AccessType: "owner"}).Error; err != nil {
		t.Fatalf("seed owner binding: %v", err)
	}

	ctxA, recA := newTenantContextWithRole(http.MethodGet, "/cloud/accounts", "operator", "2")
	cloudRuntime().listCloudAccounts(ctxA)
	if recA.Code != http.StatusOK || !strings.Contains(recA.Body.String(), account.ID) {
		t.Fatalf("owner should see account, code=%d body=%s", recA.Code, recA.Body.String())
	}

	ctxB, recB := newTenantContextWithRole(http.MethodGet, "/cloud/accounts", "operator", "3")
	cloudRuntime().listCloudAccounts(ctxB)
	if recB.Code != http.StatusOK || strings.Contains(recB.Body.String(), account.ID) {
		t.Fatalf("unbound operator should not see account, code=%d body=%s", recB.Code, recB.Body.String())
	}

	body := `{"name":"policy","cloud_account_id":"ca-bound"}`
	ctxBCreate, recBCreate := newTenantContextWithRole(http.MethodPost, "/cloud/policies", "operator", "3")
	ctxBCreate.Request = httptest.NewRequest(http.MethodPost, "/cloud/policies", strings.NewReader(body))
	ctxBCreate.Request.Header.Set("Content-Type", "application/json")
	ctxBCreate.Set("tenant", "default")
	ctxBCreate.Set("role", "operator")
	ctxBCreate.Set("user_id", "3")
	cloudRuntime().createCloudPolicy(ctxBCreate)
	if recBCreate.Code != http.StatusNotFound {
		t.Fatalf("unbound operator should not create policy with account, got %d (%s)", recBCreate.Code, recBCreate.Body.String())
	}

	ctxBind, recBind := newTenantContext(http.MethodPut, "/cloud/accounts/ca-bound/bindings")
	ctxBind.Params = gin.Params{{Key: "id", Value: account.ID}}
	ctxBind.Request = httptest.NewRequest(http.MethodPut, "/cloud/accounts/ca-bound/bindings", strings.NewReader(`{"user_ids":["2","3"]}`))
	ctxBind.Request.Header.Set("Content-Type", "application/json")
	ctxBind.Set("tenant", "default")
	cloudRuntime().updateCloudAccountBindings(ctxBind)
	if recBind.Code != http.StatusOK {
		t.Fatalf("admin should bind users, got %d (%s)", recBind.Code, recBind.Body.String())
	}

	ctxB2, recB2 := newTenantContextWithRole(http.MethodGet, "/cloud/accounts", "operator", "3")
	cloudRuntime().listCloudAccounts(ctxB2)
	if recB2.Code != http.StatusOK || !strings.Contains(recB2.Body.String(), account.ID) {
		t.Fatalf("bound operator should see account, code=%d body=%s", recB2.Code, recB2.Body.String())
	}

	ctxBUpdate, recBUpdate := newTenantContextWithRole(http.MethodPut, "/cloud/accounts/ca-bound", "operator", "3")
	ctxBUpdate.Params = gin.Params{{Key: "id", Value: account.ID}}
	ctxBUpdate.Request = httptest.NewRequest(http.MethodPut, "/cloud/accounts/ca-bound", strings.NewReader(`{"name":"nope"}`))
	ctxBUpdate.Request.Header.Set("Content-Type", "application/json")
	ctxBUpdate.Set("tenant", "default")
	ctxBUpdate.Set("role", "operator")
	ctxBUpdate.Set("user_id", "3")
	cloudRuntime().updateCloudAccount(ctxBUpdate)
	if recBUpdate.Code != http.StatusForbidden {
		t.Fatalf("bound non-owner should not manage account, got %d (%s)", recBUpdate.Code, recBUpdate.Body.String())
	}
}

func TestCloudAccountAccessMatrix(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{
		ID:          "ca-access-matrix",
		TenantID:    "default",
		OwnerUserID: "2",
		Name:        "access matrix",
		Provider:    "aliyun",
		Status:      "active",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.Create(&db.CloudAccountBinding{
		TenantID:       "default",
		CloudAccountID: account.ID,
		UserID:         "3",
		AccessType:     "bound",
	}).Error; err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	tests := []struct {
		name       string
		role       string
		userID     string
		tenantID   string
		manage     bool
		wantOK     bool
		wantStatus int
	}{
		{name: "tenant admin can use", role: "admin", userID: "1", tenantID: "default", wantOK: true},
		{name: "tenant admin can manage", role: "admin", userID: "1", tenantID: "default", manage: true, wantOK: true},
		{name: "owner can use", role: "operator", userID: "2", tenantID: "default", wantOK: true},
		{name: "owner can manage", role: "operator", userID: "2", tenantID: "default", manage: true, wantOK: true},
		{name: "bound operator can use", role: "operator", userID: "3", tenantID: "default", wantOK: true},
		{name: "bound operator cannot manage", role: "operator", userID: "3", tenantID: "default", manage: true, wantStatus: http.StatusForbidden},
		{name: "unbound operator cannot use", role: "operator", userID: "4", tenantID: "default", wantStatus: http.StatusNotFound},
		{name: "unbound operator cannot manage", role: "operator", userID: "4", tenantID: "default", manage: true, wantStatus: http.StatusNotFound},
		{name: "cross tenant admin cannot use", role: "admin", userID: "5", tenantID: "tenant-b", wantStatus: http.StatusNotFound},
		{name: "cross tenant admin cannot manage", role: "admin", userID: "5", tenantID: "tenant-b", manage: true, wantStatus: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, recorder := newTenantContextWithRole(http.MethodGet, "/cloud/accounts/"+account.ID, tt.role, tt.userID)
			ctx.Set("tenant", tt.tenantID)

			var ok bool
			if tt.manage {
				_, ok = cloudRuntime().loadCloudAccountForManage(ctx, account.ID)
			} else {
				_, ok = cloudRuntime().loadCloudAccountForUse(ctx, account.ID, true)
			}

			if ok != tt.wantOK {
				t.Fatalf("access result = %v, want %v (status=%d body=%s)", ok, tt.wantOK, recorder.Code, recorder.Body.String())
			}
			if !tt.wantOK && recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
		})
	}
}

func TestCloudProviderMockSmoke(t *testing.T) {
	ensureCloudHandlerTestFactories()
	fakeProviderDiscovery = map[string]interface{}{
		"security_groups": []map[string]string{{"id": "sg-smoke", "name": "default"}},
		"v_switches":      []map[string]string{{"id": "vsw-smoke", "name": "default"}},
		"images":          []map[string]string{{"id": "img-smoke", "name": "ubuntu-22"}},
		"instance_types":  []map[string]interface{}{{"id": "ecs.c6.large", "cpu": 2, "memory_gb": 4.0, "family": "ecs.c6"}},
	}
	fakeUploader = &fakeOSSUploader{uploadErr: errors.New("oss unavailable")}
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("release", 0o755); err != nil {
		t.Fatalf("create release dir: %v", err)
	}
	if err := os.WriteFile("release/argus-agent-linux-amd64", []byte("agent"), 0o644); err != nil {
		t.Fatalf("seed release artifact: %v", err)
	}

	store := setupCloudHandlerTestDB(t)
	akID, err := cloud.EncryptSecret("ak")
	if err != nil {
		t.Fatalf("encrypt ak: %v", err)
	}
	akSecret, err := cloud.EncryptSecret("sk")
	if err != nil {
		t.Fatalf("encrypt sk: %v", err)
	}
	account := db.CloudAccount{
		ID:              "ca-smoke",
		TenantID:        "default",
		Name:            "fake smoke",
		Provider:        "fake-review",
		AccessKeyID:     akID,
		AccessKeySecret: akSecret,
		Region:          "cn-test",
		OSSBucket:       "bucket",
		OSSEndpoint:     "endpoint",
		Status:          "active",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/accounts/"+account.ID+"/test")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().testCloudAccount(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("credential/provider smoke should pass, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContext(http.MethodPost, "/cloud/policies")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cloud/policies", strings.NewReader(`{
		"name":"smoke-policy",
		"cloud_account_id":"ca-smoke",
		"min_instances":0,
		"max_instances":2,
		"enabled":true
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	cloudRuntime().createCloudPolicy(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("policy smoke should create policy, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var policy db.CloudScalingPolicy
	if err := store.Where("cloud_account_id = ?", account.ID).First(&policy).Error; err != nil {
		t.Fatalf("expected policy to be persisted: %v", err)
	}

	ctx, recorder = newTenantContext(http.MethodPost, "/cloud/policies/"+policy.ID+"/toggle")
	ctx.Params = gin.Params{{Key: "id", Value: policy.ID}}
	cloudRuntime().toggleCloudPolicy(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("policy toggle smoke should pass, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContext(http.MethodPost, "/cloud/accounts/"+account.ID+"/oss/upload")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().uploadAgentToOSS(ctx)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("OSS failure smoke should surface upload failure, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "oss unavailable") {
		t.Fatalf("expected OSS failure reason, got %s", recorder.Body.String())
	}
}

func TestChooseOneClickInstanceType(t *testing.T) {
	tests := []struct {
		name      string
		available []string
		want      string
	}{
		{
			name:      "prefers e series 2c2g regardless of discovery order",
			available: []string{"ecs.g8i.large", "ecs.c6.large", "ecs.u1-c1m1.large", "ecs.e-c1m1.large"},
			want:      "ecs.e-c1m1.large",
		},
		{
			name:      "falls back to universal 2c2g",
			available: []string{"ecs.g8i.large", "ecs.c6.large", "ecs.u1-c1m1.large"},
			want:      "ecs.u1-c1m1.large",
		},
		{
			name:      "falls back to c6 2c4g",
			available: []string{"ecs.g8i.large", "ecs.c6.large"},
			want:      "ecs.c6.large",
		},
		{
			name:      "uses first discovered type when preferred types are unavailable",
			available: []string{"ecs.g8i.large", "ecs.r8i.large"},
			want:      "ecs.g8i.large",
		},
		{name: "returns empty for empty discovery", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chooseOneClickInstanceType(tt.available); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestOneClickSetupPersistsPreferred2C2GInstanceType(t *testing.T) {
	ensureCloudHandlerTestFactories()
	fakeProviderDiscovery = map[string]interface{}{
		"security_groups": []map[string]string{{"id": "sg-1", "name": "default"}},
		"v_switches":      []map[string]string{{"id": "vsw-1", "name": "default"}},
		"images":          []map[string]string{{"id": "img-1", "name": "ubuntu-22"}},
		"instance_types": []map[string]interface{}{
			{"id": "ecs.g8i.large", "cpu": 2, "memory_gb": 8.0, "family": "ecs.g8i"},
			{"id": "ecs.c6.large", "cpu": 2, "memory_gb": 4.0, "family": "ecs.c6"},
			{"id": "ecs.u1-c1m1.large", "cpu": 2, "memory_gb": 2.0, "family": "ecs.u1"},
			{"id": "ecs.e-c1m1.large", "cpu": 2, "memory_gb": 2.0, "family": "ecs.e"},
		},
	}
	fakeUploader = &fakeOSSUploader{files: []cloud.OSSFileInfo{{Key: requiredAgentObjectKey}}}

	store := setupCloudHandlerTestDB(t)
	akID, err := cloud.EncryptSecret("ak")
	if err != nil {
		t.Fatalf("encrypt ak: %v", err)
	}
	akSecret, err := cloud.EncryptSecret("sk")
	if err != nil {
		t.Fatalf("encrypt sk: %v", err)
	}
	account := db.CloudAccount{
		ID:              "ca-preferred-2c2g",
		TenantID:        "default",
		Name:            "preferred 2c2g",
		Provider:        "fake-review",
		AccessKeyID:     akID,
		AccessKeySecret: akSecret,
		Region:          "cn-test",
		OSSBucket:       "bucket",
		OSSEndpoint:     "endpoint",
		Status:          "active",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/accounts/"+account.ID+"/one-click-setup")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().oneClickSetup(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if err := store.Where("id = ?", account.ID).First(&account).Error; err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if account.DefaultInstanceType != "ecs.e-c1m1.large" {
		t.Fatalf("expected preferred 2c2g type, got %q", account.DefaultInstanceType)
	}
}

func TestSanitizeReleaseFilenameRejectsUnsafeUploads(t *testing.T) {
	badNames := []string{
		"../../release/argus-agent-linux-amd64",
		"argus-server-linux-amd64",
		"notes.txt",
		"nested/argus-agent-linux-amd64",
	}
	for _, name := range badNames {
		if _, err := sanitizeReleaseFilename(name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
	if got, err := sanitizeReleaseFilename("argus-agent-linux-amd64"); err != nil || got != "argus-agent-linux-amd64" {
		t.Fatalf("expected valid agent filename, got %q err=%v", got, err)
	}
}

func TestOneClickSetupFailsWhenRequiredAgentArtifactIsUnavailable(t *testing.T) {
	ensureCloudHandlerTestFactories()
	fakeProviderDiscovery = map[string]interface{}{
		"security_groups": []map[string]string{{"id": "sg-1", "name": "sg"}},
		"v_switches":      []map[string]string{{"id": "vsw-1", "name": "vsw"}},
		"images":          []map[string]string{{"id": "img-1", "name": "ubuntu-22"}},
		"instance_types":  []map[string]interface{}{{"id": "ecs.c6.large", "cpu": 2, "memory_gb": 4.0, "family": "ecs.c6"}},
	}
	fakeUploader = &fakeOSSUploader{}

	store := setupCloudHandlerTestDB(t)
	akID, err := cloud.EncryptSecret("ak")
	if err != nil {
		t.Fatalf("encrypt ak: %v", err)
	}
	akSecret, err := cloud.EncryptSecret("sk")
	if err != nil {
		t.Fatalf("encrypt sk: %v", err)
	}
	account := db.CloudAccount{
		ID:              "ca-3",
		TenantID:        "default",
		Name:            "fake",
		Provider:        "fake-review",
		AccessKeyID:     akID,
		AccessKeySecret: akSecret,
		Region:          "cn-test",
		OSSBucket:       "bucket",
		OSSEndpoint:     "endpoint",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/accounts/"+account.ID+"/one-click-setup")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().oneClickSetup(ctx)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Agent binary is not ready for OSS distribution") {
		t.Fatalf("expected artifact readiness error, got %s", recorder.Body.String())
	}

	var policies int64
	store.Model(&db.CloudScalingPolicy{}).Where("cloud_account_id = ?", account.ID).Count(&policies)
	if policies != 0 {
		t.Fatalf("expected no policy to be created on artifact readiness failure, got %d", policies)
	}
}

func TestUploadAgentToOSSFailsWhenRequiredArtifactMissing(t *testing.T) {
	ensureCloudHandlerTestFactories()
	fakeUploader = &fakeOSSUploader{
		uploadResults: []cloud.OSSUploadResult{
			{
				Filename:  "argus-agent-linux-arm64",
				ObjectKey: "argus/agent/argus-agent-linux-arm64",
				Success:   true,
			},
		},
	}

	store := setupCloudHandlerTestDB(t)
	akID, err := cloud.EncryptSecret("ak")
	if err != nil {
		t.Fatalf("encrypt ak: %v", err)
	}
	akSecret, err := cloud.EncryptSecret("sk")
	if err != nil {
		t.Fatalf("encrypt sk: %v", err)
	}
	account := db.CloudAccount{
		ID:              "ca-upload",
		TenantID:        "default",
		Name:            "fake",
		Provider:        "fake-review",
		AccessKeyID:     akID,
		AccessKeySecret: akSecret,
		Region:          "cn-test",
		OSSBucket:       "bucket",
		OSSEndpoint:     "endpoint",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/accounts/"+account.ID+"/oss/upload")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().uploadAgentToOSS(ctx)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Required agent binary") {
		t.Fatalf("expected required artifact error, got %s", recorder.Body.String())
	}
}

func TestUploadAgentToOSSSucceedsWhenRequiredArtifactUploadedWithNonCriticalFailure(t *testing.T) {
	ensureCloudHandlerTestFactories()
	fakeUploader = &fakeOSSUploader{
		uploadResults: []cloud.OSSUploadResult{
			{
				Filename:  "argus-agent-linux-amd64",
				ObjectKey: requiredAgentObjectKey,
				Success:   true,
			},
			{
				Filename:  "argus-agent-darwin-arm64",
				ObjectKey: "argus/agent/argus-agent-darwin-arm64",
				Success:   false,
				Error:     "not supported in this release",
			},
		},
	}

	store := setupCloudHandlerTestDB(t)
	akID, err := cloud.EncryptSecret("ak")
	if err != nil {
		t.Fatalf("encrypt ak: %v", err)
	}
	akSecret, err := cloud.EncryptSecret("sk")
	if err != nil {
		t.Fatalf("encrypt sk: %v", err)
	}
	account := db.CloudAccount{
		ID:              "ca-upload-partial",
		TenantID:        "default",
		Name:            "fake",
		Provider:        "fake-review",
		AccessKeyID:     akID,
		AccessKeySecret: akSecret,
		Region:          "cn-test",
		OSSBucket:       "bucket",
		OSSEndpoint:     "endpoint",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/accounts/"+account.ID+"/oss/upload")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().uploadAgentToOSS(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"failed_count":1`) {
		t.Fatalf("expected non-critical failure count, got %s", recorder.Body.String())
	}
}
