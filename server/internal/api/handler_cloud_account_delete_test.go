package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestDeleteCloudAccountReportsOnlyAuthorizedPolicyDependencies(t *testing.T) {
	for _, role := range []string{"admin", "operator"} {
		t.Run(role, func(t *testing.T) {
			store := setupCloudHandlerTestDB(t)
			account := db.CloudAccount{ID: "account", TenantID: "default", OwnerUserID: "owner", Name: "Test credential", AccessKeySecret: "secret-must-not-leak"}
			if err := store.Create(&account).Error; err != nil {
				t.Fatal(err)
			}
			policies := []db.CloudScalingPolicy{
				{ID: "disabled", TenantID: "default", CloudAccountID: account.ID, Name: "A disabled policy", Enabled: false, UserDataTemplate: "script-must-not-leak"},
				{ID: "enabled", TenantID: "default", CloudAccountID: account.ID, Name: "B enabled policy", Enabled: true},
				{ID: "other-account", TenantID: "default", CloudAccountID: "another-account", Name: "other-account-must-not-leak"},
				{ID: "other-tenant", TenantID: "another-tenant", CloudAccountID: account.ID, Name: "other-tenant-must-not-leak"},
			}
			if err := store.Create(&policies).Error; err != nil {
				t.Fatal(err)
			}
			ctx, recorder := newTenantContextWithRole(http.MethodDelete, "/cloud/accounts/"+account.ID, role, "owner")
			ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
			cloudRuntime().deleteCloudAccount(ctx)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			var response struct {
				Error          string                   `json:"error"`
				Code           string                   `json:"code"`
				CloudAccountID string                   `json:"cloud_account_id"`
				PolicyCount    int                      `json:"policy_count"`
				Policies       []map[string]interface{} `json:"policies"`
				Truncated      bool                     `json:"policies_truncated"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Code != "cloud_account_has_policies" || response.CloudAccountID != account.ID || response.PolicyCount != 2 || response.Truncated || len(response.Policies) != 2 {
				t.Fatalf("unexpected dependency response: %#v", response)
			}
			if !strings.Contains(response.Error, "2 scaling policy/policies") {
				t.Fatalf("legacy error missing: %q", response.Error)
			}
			for index, want := range policies[:2] {
				got := response.Policies[index]
				if len(got) != 3 || got["id"] != want.ID || got["name"] != want.Name || got["enabled"] != want.Enabled {
					t.Fatalf("unexpected policy summary: %#v", got)
				}
			}
			for _, value := range []string{"secret-must-not-leak", "script-must-not-leak", "other-account-must-not-leak", "other-tenant-must-not-leak"} {
				if strings.Contains(recorder.Body.String(), value) {
					t.Fatalf("response leaked %q", value)
				}
			}
			var accounts, remainingPolicies int64
			store.Model(&db.CloudAccount{}).Count(&accounts)
			store.Model(&db.CloudScalingPolicy{}).Count(&remainingPolicies)
			if accounts != 1 || remainingPolicies != 4 {
				t.Fatalf("blocked deletion changed records: accounts=%d policies=%d", accounts, remainingPolicies)
			}
		})
	}
}

func TestDeleteCloudAccountHidesPolicyDependenciesFromUnauthorizedUsers(t *testing.T) {
	for _, tc := range []struct {
		name, tenantID, role, userID string
		wantStatus                   int
	}{
		{"bound user", "default", "operator", "bound", http.StatusForbidden},
		{"unrelated user", "default", "operator", "unrelated", http.StatusNotFound},
		{"other tenant admin", "other", "admin", "admin", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := setupCloudHandlerTestDB(t)
			account := db.CloudAccount{ID: "account", TenantID: "default", OwnerUserID: "owner"}
			if err := store.Create(&account).Error; err != nil {
				t.Fatal(err)
			}
			if err := store.Create(&db.CloudAccountBinding{TenantID: "default", CloudAccountID: account.ID, UserID: "bound"}).Error; err != nil {
				t.Fatal(err)
			}
			if err := store.Create(&db.CloudScalingPolicy{ID: "private-policy", TenantID: "default", CloudAccountID: account.ID, Name: "private-policy-name"}).Error; err != nil {
				t.Fatal(err)
			}
			ctx, recorder := newTenantContextWithRole(http.MethodDelete, "/cloud/accounts/"+account.ID, tc.role, tc.userID)
			ctx.Set("tenant", tc.tenantID)
			ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
			cloudRuntime().deleteCloudAccount(ctx)
			if recorder.Code != tc.wantStatus || strings.Contains(recorder.Body.String(), "private-policy") || strings.Contains(recorder.Body.String(), "policy_count") {
				t.Fatalf("unexpected unauthorized response: %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestDeleteCloudAccountBoundsPolicyDependencyDetails(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "account", TenantID: "default"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 21; index++ {
		policy := db.CloudScalingPolicy{ID: fmt.Sprintf("policy-%02d", index), TenantID: "default", CloudAccountID: account.ID, Name: fmt.Sprintf("Policy %02d", index)}
		if err := store.Create(&policy).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx, recorder := newTenantContext(http.MethodDelete, "/cloud/accounts/"+account.ID)
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().deleteCloudAccount(ctx)
	var response struct {
		PolicyCount int                      `json:"policy_count"`
		Policies    []map[string]interface{} `json:"policies"`
		Truncated   bool                     `json:"policies_truncated"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusBadRequest || response.PolicyCount != 21 || len(response.Policies) != 20 || !response.Truncated || response.Policies[0]["id"] != "policy-00" {
		t.Fatalf("unexpected bounded response: %d %#v", recorder.Code, response)
	}
}

func TestDeleteCloudAccountSucceedsAfterExplicitPolicyRemoval(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "account", TenantID: "default"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	policy := db.CloudScalingPolicy{ID: "policy", TenantID: "default", CloudAccountID: account.ID, Enabled: false}
	if err := store.Create(&policy).Error; err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		path       string
		id         string
		wantStatus int
		handler    gin.HandlerFunc
	}{
		{"/cloud/accounts/", account.ID, http.StatusBadRequest, cloudRuntime().deleteCloudAccount},
		{"/cloud/policies/", policy.ID, http.StatusOK, cloudRuntime().deleteCloudPolicy},
		{"/cloud/accounts/", account.ID, http.StatusOK, cloudRuntime().deleteCloudAccount},
	} {
		ctx, recorder := newTenantContext(http.MethodDelete, step.path+step.id)
		ctx.Params = gin.Params{{Key: "id", Value: step.id}}
		step.handler(ctx)
		if recorder.Code != step.wantStatus {
			t.Fatalf("%s: %d %s", step.path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestDeleteCloudAccountFailsClosedWhenPolicyCheckFails(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "account", TenantID: "default"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Migrator().DropTable(&db.CloudScalingPolicy{}); err != nil {
		t.Fatal(err)
	}
	ctx, recorder := newTenantContext(http.MethodDelete, "/cloud/accounts/"+account.ID)
	ctx.Params = gin.Params{{Key: "id", Value: account.ID}}
	cloudRuntime().deleteCloudAccount(ctx)
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "no such table") {
		t.Fatalf("unexpected failure: %d %s", recorder.Code, recorder.Body.String())
	}
	var remaining int64
	store.Model(&db.CloudAccount{}).Count(&remaining)
	if remaining != 1 {
		t.Fatal("credential was deleted after dependency check failed")
	}
}

func TestDeleteCloudAccountDependencyHTTPRoute(t *testing.T) {
	store := setupCloudHandlerTestDB(t)
	account := db.CloudAccount{ID: "http-account", TenantID: "default", OwnerUserID: "1"}
	if err := store.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.CloudScalingPolicy{ID: "http-policy", TenantID: "default", CloudAccountID: account.ID, Name: "HTTP policy"}).Error; err != nil {
		t.Fatal(err)
	}
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	server := httptest.NewServer(NewRouter(RouterDependencies{Cloud: cloudRuntime()}))
	defer server.Close()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "default", "role": "admin", "user_id": "1", "exp": time.Now().Add(time.Minute).Unix(),
	}).SignedString(currentJWTSecret())
	if err != nil {
		t.Fatal(err)
	}
	for _, authenticated := range []bool{false, true} {
		request, err := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/cloud/accounts/"+account.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]interface{}
		decodeErr := json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if authenticated {
			if response.StatusCode != http.StatusBadRequest || body["code"] != "cloud_account_has_policies" || body["policy_count"] != float64(1) {
				t.Fatalf("unexpected HTTP dependency response: %d %#v", response.StatusCode, body)
			}
		} else if response.StatusCode != http.StatusUnauthorized || body["policies"] != nil {
			t.Fatalf("unauthenticated HTTP request exposed dependencies: %d %#v", response.StatusCode, body)
		}
	}
}
