package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/cloud"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openIsolatedCloudStore(t *testing.T, name string) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", name)), &gorm.Config{})
	if err != nil {
		t.Fatalf("open isolated sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.CloudAccount{}, &db.CloudAccountBinding{}); err != nil {
		t.Fatalf("automigrate isolated store: %v", err)
	}
	return store
}

func TestRequestActorFromContext(t *testing.T) {
	ctx, _ := newTenantContextWithRole(http.MethodGet, "/cloud/accounts", "operator", "user-7")
	ctx.Set("tenant", "tenant-a")

	actor := requestActor(ctx)
	if actor != (RequestActor{TenantID: "tenant-a", UserID: "user-7", Role: "operator"}) {
		t.Fatalf("unexpected actor: %+v", actor)
	}
	if actor.IsAdmin() {
		t.Fatal("operator must not be treated as admin")
	}
}

func TestCloudHandlerUsesInjectedStoreForAuthorization(t *testing.T) {
	globalStore := setupCloudHandlerTestDB(t)
	injectedStore := openIsolatedCloudStore(t, "injected_cloud_handler")
	account := db.CloudAccount{
		ID:          "injected-account",
		TenantID:    "default",
		OwnerUserID: "2",
		Name:        "injected",
		Status:      "active",
	}
	if err := injectedStore.Create(&account).Error; err != nil {
		t.Fatalf("seed injected account: %v", err)
	}
	if err := globalStore.Where("id = ?", account.ID).First(&db.CloudAccount{}).Error; err == nil {
		t.Fatal("test setup error: account unexpectedly exists in global store")
	}

	handler := NewCloudHandler(injectedStore, nil)
	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/cloud/accounts/"+account.ID, "operator", "2")
	loaded, ok := handler.loadCloudAccountForUse(ctx, account.ID, true)
	if !ok {
		t.Fatalf("injected store account should be accessible, status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if loaded.ID != account.ID {
		t.Fatalf("loaded account = %q, want %q", loaded.ID, account.ID)
	}
}

func TestCloudHandlerUsesInjectedProviderFactory(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{
		ID:          "factory-account",
		TenantID:    "default",
		OwnerUserID: "2",
		Name:        "factory",
		Provider:    "injected",
		Region:      "cn-test",
		Status:      "active",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	called := false
	handler := NewCloudHandler(store, nil)
	handler.ProviderFactory = func(got *db.CloudAccount) (cloud.CloudProvider, error) {
		called = true
		if got.ID != account.ID {
			t.Fatalf("factory account = %q, want %q", got.ID, account.ID)
		}
		return &fakeCloudProvider{}, nil
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/cloud/accounts/"+account.ID+"/test", "operator", "2")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	handler.testCloudAccount(ctx)

	if !called {
		t.Fatal("injected provider factory was not called")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCloudServicesUseInjectedFactories(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{
		ID:          "service-factory-account",
		TenantID:    "default",
		OwnerUserID: "2",
		Name:        "services",
		Provider:    "injected",
		Region:      "cn-test",
		OSSBucket:   "bucket",
		OSSEndpoint: "endpoint",
		Status:      "active",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	providerCalled := false
	ossCalled := false
	handler := NewCloudHandler(store, nil)
	handler.ProviderFactory = func(*db.CloudAccount) (cloud.CloudProvider, error) {
		providerCalled = true
		return &fakeCloudProvider{discovery: map[string]interface{}{"images": []interface{}{}}}, nil
	}
	handler.OSSFactory = func(*db.CloudAccount) (cloud.OSSUploader, error) {
		ossCalled = true
		return &fakeOSSUploader{}, nil
	}

	discoverCtx, discoverRecorder := newTenantContextWithRole(http.MethodGet, "/cloud/accounts/"+account.ID+"/discover", "operator", "2")
	discoverCtx.Params = gin.Params{{Key: "id", Value: account.ID}}
	handler.discoverCloudResources(discoverCtx)
	if !providerCalled || discoverRecorder.Code != http.StatusOK {
		t.Fatalf("injected provider factory not used: called=%v status=%d body=%s", providerCalled, discoverRecorder.Code, discoverRecorder.Body.String())
	}

	ossCtx, ossRecorder := newTenantContextWithRole(http.MethodPost, "/cloud/accounts/"+account.ID+"/oss/test", "operator", "2")
	ossCtx.Params = gin.Params{{Key: "id", Value: account.ID}}
	handler.testOSSConnection(ossCtx)
	if !ossCalled || ossRecorder.Code != http.StatusOK {
		t.Fatalf("injected OSS factory not used: called=%v status=%d body=%s", ossCalled, ossRecorder.Code, ossRecorder.Body.String())
	}
}

func TestCloudRoutesKeepHandlerInjectedAtRegistration(t *testing.T) {
	storeA := openIsolatedCloudStore(t, "cloud_routes_store_a")
	storeB := openIsolatedCloudStore(t, "cloud_routes_store_b")
	account := db.CloudAccount{ID: "route-account-a", TenantID: "default", Name: "route a", Status: "active"}
	if err := storeA.Create(&account).Error; err != nil {
		t.Fatalf("seed route account: %v", err)
	}

	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	ConfigureRouterDependencies(RouterDependencies{Cloud: NewCloudHandler(storeA, nil)})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	group := router.Group("/api/v1")
	group.Use(func(c *gin.Context) {
		c.Set("tenant", "default")
		c.Set("role", "admin")
		c.Set("user_id", "1")
		c.Next()
	})
	registerAPIV1Routes(group)

	ConfigureRouterDependencies(RouterDependencies{Cloud: NewCloudHandler(storeB, nil)})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/cloud/accounts", nil))

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), account.ID) {
		t.Fatalf("registered route did not retain injected handler: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
