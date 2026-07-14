package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/cloud/aliyun"
	"github.com/user/dddd-server/internal/db"
)

type fakeCatalogProvider struct {
	typesByStrategy map[string][]aliyun.AvailableInstanceType
	typesErr        error
	prices          map[string]fakePriceResult
	strategyLog     *[]string
}

type fakePriceResult struct {
	price *aliyun.PriceInfo
	err   error
}

func (p *fakeCatalogProvider) QueryAvailableInstanceTypes(strategy string) ([]aliyun.AvailableInstanceType, error) {
	if p.strategyLog != nil {
		*p.strategyLog = append(*p.strategyLog, strategy)
	}
	return p.typesByStrategy[strategy], p.typesErr
}

func (p *fakeCatalogProvider) QueryPrice(instanceType, strategy string) (*aliyun.PriceInfo, error) {
	result, ok := p.prices[strategy+":"+instanceType]
	if !ok {
		return nil, fmt.Errorf("missing price for %s:%s", strategy, instanceType)
	}
	return result.price, result.err
}

func TestChooseOneClickInstanceTypePrefersCheapest2C2G(t *testing.T) {
	available := []cloudInstanceTypeItem{
		{ID: "ecs.u1-c1m1.large", CPU: 2, Memory: 2, HourlyPrice: 0.08},
		{ID: "ecs.e-c1m1.large", CPU: 2, Memory: 2, HourlyPrice: 0.05},
		{ID: "ecs.c6.large", CPU: 2, Memory: 4, HourlyPrice: 0.12},
	}
	if got := chooseOneClickInstanceTypeFromDiscovery(available); got != "ecs.e-c1m1.large" {
		t.Fatalf("expected cheapest 2c2g instance, got %q", got)
	}
}

func TestCheapestRecommendationsFallsBackToPostpaidForUnavailableSpotPrice(t *testing.T) {
	instance := aliyun.AvailableInstanceType{ID: "ecs.e-c1m1.small", CPU: 1, MemoryGB: 1, Family: "ecs.e", Status: "WithStock"}
	catalog := &fakeCatalogProvider{
		typesByStrategy: map[string][]aliyun.AvailableInstanceType{"SpotAsPriceGo": {instance}, "NoSpot": {instance}},
		prices: map[string]fakePriceResult{
			"SpotAsPriceGo:ecs.e-c1m1.small": {err: fmt.Errorf("spot price unavailable")},
			"NoSpot:ecs.e-c1m1.small":        {price: &aliyun.PriceInfo{TotalHourly: 0.2, Currency: "CNY", PriceUnit: "Hour"}},
		},
	}
	service := &CloudSetupService{CatalogFactory: func(_, _, region string) (CloudCatalog, error) {
		if region != "cn-a" {
			t.Fatalf("catalog region = %q, want cn-a", region)
		}
		return catalog, nil
	}}

	result, err := service.CheapestRecommendations(&db.CloudAccount{}, "ak", "sk", "cn-a", "SpotAsPriceGo")
	if err != nil {
		t.Fatalf("CheapestRecommendations returned error: %v", err)
	}
	if result.Cheapest == nil || result.Cheapest.Region != "cn-a" || result.Cheapest.TotalHourly != 0.2 {
		t.Fatalf("cheapest = %#v, want cn-a at 0.2", result.Cheapest)
	}
	if result.Cheapest.PriceSource != "postpaid" {
		t.Fatalf("cheapest price source = %q, want postpaid", result.Cheapest.PriceSource)
	}
	if len(result.Recommendations) != 1 || result.Recommendations[0].PriceSource != "postpaid" {
		t.Fatalf("fallback recommendations = %#v, want one postpaid result", result.Recommendations)
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "cn-a") {
		t.Fatalf("warnings = %#v, want cn-a fallback warning", result.Warnings)
	}
}

func TestListCloudRecommendationsUsesSavedRegion(t *testing.T) {
	ensureCloudHandlerTestFactories()
	store := setupCloudHandlerTestDB(t)
	akID, err := cloud.EncryptSecret("ak")
	if err != nil {
		t.Fatalf("encrypt ak: %v", err)
	}
	akSecret, err := cloud.EncryptSecret("sk")
	if err != nil {
		t.Fatalf("encrypt sk: %v", err)
	}
	account := db.CloudAccount{ID: "ca-regional-recommendations", TenantID: "default", Name: "regional recommendations", Provider: "fake-review", AccessKeyID: akID, AccessKeySecret: akSecret, Region: "cn-test", Status: "active"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.Create(&db.CloudScalingPolicy{ID: "cp-regional-recommendations", TenantID: "default", CloudAccountID: account.ID, Name: "NoSpot policy", SpotStrategy: "NoSpot"}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	var requestedRegions []string
	var requestedStrategies []string
	handler := cloudRuntime()
	oldCatalogFactory := handler.CatalogFactory
	handler.CatalogFactory = func(_, _, region string) (CloudCatalog, error) {
		requestedRegions = append(requestedRegions, region)
		instance := aliyun.AvailableInstanceType{ID: "ecs.e-c1m1.small", CPU: 1, MemoryGB: 1, Family: "ecs.e", Status: "WithStock"}
		return &fakeCatalogProvider{
			typesByStrategy: map[string][]aliyun.AvailableInstanceType{"NoSpot": {instance}},
			prices:          map[string]fakePriceResult{"NoSpot:ecs.e-c1m1.small": {price: &aliyun.PriceInfo{TotalHourly: 0.2, Currency: "CNY", PriceUnit: "Hour"}}},
			strategyLog:     &requestedStrategies,
		}, nil
	}
	t.Cleanup(func() { handler.CatalogFactory = oldCatalogFactory })

	ctx, recorder := newTenantContext(http.MethodGet, "/cloud/accounts/"+account.ID+"/recommendations")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	handler.listCloudRecommendations(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("regional recommendation should pass, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if len(requestedRegions) != 1 || requestedRegions[0] != account.Region {
		t.Fatalf("catalog regions = %#v, want one request for %q", requestedRegions, account.Region)
	}
	if len(requestedStrategies) != 1 || requestedStrategies[0] != "NoSpot" {
		t.Fatalf("catalog strategies = %#v, want one NoSpot request", requestedStrategies)
	}
	if !strings.Contains(recorder.Body.String(), `"regions_scanned":1`) {
		t.Fatalf("response should report one scanned region, got %s", recorder.Body.String())
	}
}

func TestListCloudRecommendationsUsesExplicitRegionAndStrategyOverride(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	akID, err := cloud.EncryptSecret("ak")
	if err != nil {
		t.Fatalf("encrypt ak: %v", err)
	}
	akSecret, err := cloud.EncryptSecret("sk")
	if err != nil {
		t.Fatalf("encrypt sk: %v", err)
	}
	account := db.CloudAccount{ID: "ca-explicit-recommendations", TenantID: "default", Name: "explicit recommendations", Provider: "fake-review", AccessKeyID: akID, AccessKeySecret: akSecret, Region: "cn-saved", Status: "active"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.Create(&db.CloudScalingPolicy{ID: "cp-explicit-recommendations", TenantID: "default", CloudAccountID: account.ID, Name: "NoSpot policy", SpotStrategy: "NoSpot"}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	var requestedRegion string
	handler := cloudRuntime()
	oldCatalogFactory := handler.CatalogFactory
	var strategyLog []string
	handler.CatalogFactory = func(_, _, region string) (CloudCatalog, error) {
		requestedRegion = region
		instance := aliyun.AvailableInstanceType{ID: "ecs.e-c1m1.small", CPU: 1, MemoryGB: 1, Family: "ecs.e", Status: "WithStock"}
		return &fakeCatalogProvider{
			typesByStrategy: map[string][]aliyun.AvailableInstanceType{"SpotAsPriceGo": {instance}},
			prices:          map[string]fakePriceResult{"SpotAsPriceGo:ecs.e-c1m1.small": {price: &aliyun.PriceInfo{SpotPrice: 0.1, TotalHourly: 0.1, Currency: "CNY", PriceUnit: "Hour"}}},
			strategyLog:     &strategyLog,
		}, nil
	}
	t.Cleanup(func() { handler.CatalogFactory = oldCatalogFactory })

	ctx, recorder := newTenantContext(http.MethodGet, "/cloud/accounts/"+account.ID+"/recommendations?region=cn-query&spot_strategy=SpotAsPriceGo")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	handler.listCloudRecommendations(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("explicit recommendation should pass, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if requestedRegion != "cn-query" {
		t.Fatalf("catalog region = %q, want cn-query", requestedRegion)
	}
	if len(strategyLog) != 1 || strategyLog[0] != "SpotAsPriceGo" {
		t.Fatalf("catalog strategies = %#v, want SpotAsPriceGo override", strategyLog)
	}
}

func TestCheapestRecommendationsReturnsEmptyWhenNoCandidates(t *testing.T) {
	service := &CloudSetupService{CatalogFactory: func(_, _, _ string) (CloudCatalog, error) {
		return &fakeCatalogProvider{typesByStrategy: map[string][]aliyun.AvailableInstanceType{"NoSpot": {}}}, nil
	}}
	result, err := service.CheapestRecommendations(&db.CloudAccount{}, "ak", "sk", "cn-empty", "NoSpot")
	if err != nil {
		t.Fatalf("CheapestRecommendations returned error: %v", err)
	}
	if result.Cheapest != nil || len(result.Recommendations) != 0 {
		t.Fatalf("empty recommendations = %#v, want no candidates", result.Recommendations)
	}
}

func TestAutoConfigureRequiresCompleteResourcesWhenChangingRegion(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "ca-region-guard", TenantID: "default", OwnerUserID: "1", Name: "region guard", Region: "cn-hangzhou", Status: "active"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/cloud/accounts/"+account.ID+"/auto-configure")
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cloud/accounts/"+account.ID+"/auto-configure", strings.NewReader(`{"region":"cn-shanghai","default_instance_type":"ecs.e-c1m1.small"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	cloudRuntime().autoConfigureCloudAccount(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", recorder.Code, recorder.Body.String())
	}
	var current db.CloudAccount
	if err := store.First(&current, "id = ?", account.ID).Error; err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if current.Region != "cn-hangzhou" {
		t.Fatalf("region changed to %q after incomplete request", current.Region)
	}
}
