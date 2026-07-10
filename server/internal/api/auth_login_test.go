package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	"golang.org/x/crypto/bcrypt"
)

var loginTestUserSequence atomic.Uint64

func uniqueLoginUsername(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, loginTestUserSequence.Add(1))
}

func loginForTest(t *testing.T, payload string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")
	authLogin(ctx)
	return recorder
}

func seedLoginUser(t *testing.T, username, password, tenantID, role string) db.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := db.User{
		Username:     username,
		PasswordHash: string(hash),
		TenantID:     tenantID,
		Role:         role,
		Status:       "active",
	}
	if err := db.DB.Create(&user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return user
}

func decodeLoginClaims(t *testing.T, recorder *httptest.ResponseRecorder) jwt.MapClaims {
	t.Helper()
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if body.Token == "" {
		t.Fatal("expected login token")
	}
	token, err := jwt.Parse(body.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte(currentJWTSecret()), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		t.Fatalf("parse login token: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", token.Claims)
	}
	return claims
}

func assertLoginClaims(t *testing.T, claims jwt.MapClaims, user db.User, role, roleBase string) {
	t.Helper()
	if claims["tenant_id"] != user.TenantID {
		t.Fatalf("unexpected tenant_id claim: %+v", claims)
	}
	if claims["role"] != role || claims["role_base"] != roleBase {
		t.Fatalf("unexpected role claims: %+v", claims)
	}
	if claims["user_id"] != fmt.Sprintf("%d", user.ID) {
		t.Fatalf("unexpected user_id claim: %+v", claims)
	}
	if claims["exp_authorized"] != user.ExpAuthorized {
		t.Fatalf("unexpected exp_authorized claim: %+v", claims)
	}
	expiresAt, ok := claims["exp"].(float64)
	if !ok || int64(expiresAt) <= time.Now().Unix() {
		t.Fatalf("unexpected exp claim: %+v", claims)
	}
}

func TestAuthLoginRejectsRemovedDevelopmentPassword(t *testing.T) {
	setupAITestDB(t)
	username := uniqueLoginUsername("missing-user")
	recorder := loginForTest(t, fmt.Sprintf(`{"username":%q,"password":"8888"}`, username))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthLoginAcceptsDatabaseUser(t *testing.T) {
	setupAITestDB(t)
	username := uniqueLoginUsername("operator-user")
	user := seedLoginUser(t, username, "correct-password", "tenant-a", "operator")
	recorder := loginForTest(t, fmt.Sprintf(`{"username":%q,"password":"correct-password"}`, username))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	claims := decodeLoginClaims(t, recorder)
	assertLoginClaims(t, claims, user, "operator", "operator")
}

func TestAuthLoginRejectsWrongPassword(t *testing.T) {
	setupAITestDB(t)
	username := uniqueLoginUsername("operator-user")
	seedLoginUser(t, username, "correct-password", "tenant-a", "operator")
	recorder := loginForTest(t, fmt.Sprintf(`{"username":%q,"password":"wrong-password"}`, username))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestAuthLoginKeepsLegacyTenantIDUsername(t *testing.T) {
	setupAITestDB(t)
	username := uniqueLoginUsername("legacy-tenant")
	user := seedLoginUser(t, username, "legacy-password", "tenant-legacy", "viewer")
	recorder := loginForTest(t, fmt.Sprintf(`{"tenant_id":%q,"password":"legacy-password"}`, username))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	claims := decodeLoginClaims(t, recorder)
	assertLoginClaims(t, claims, user, "viewer", "viewer")
}

func TestAuthLoginFallsBackToViewerForEmptyRole(t *testing.T) {
	setupAITestDB(t)
	username := uniqueLoginUsername("empty-role")
	user := seedLoginUser(t, username, "correct-password", "tenant-empty-role", "viewer")
	if err := db.DB.Model(&user).UpdateColumn("role", "").Error; err != nil {
		t.Fatalf("clear user role: %v", err)
	}
	user.Role = ""

	recorder := loginForTest(t, fmt.Sprintf(`{"username":%q,"password":"correct-password"}`, username))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	claims := decodeLoginClaims(t, recorder)
	assertLoginClaims(t, claims, user, "viewer", "viewer")
}
