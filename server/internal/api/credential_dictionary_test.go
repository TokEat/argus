package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/credentialvault"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func TestCredentialDictionaryStoresOnlyEncryptedImmutableRevision(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "vault-project", TenantID: "default", OwnerUserID: "7", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/projects/vault-project/credential-dictionaries", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "vault-project"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/projects/vault-project/credential-dictionaries", strings.NewReader(`{"name":"ops users","kind":"username","values":["admin","root","admin"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	createCredentialDictionary(ctx)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create dictionary status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response credentialDictionaryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Count != 2 || response.Revision != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	var revision db.CredentialDictionaryRevision
	if err := store.Where("dictionary_id = ?", response.ID).First(&revision).Error; err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(revision.Ciphertext, []byte("admin")) || bytes.Contains(revision.Ciphertext, []byte("root")) || len(revision.Nonce) == 0 {
		t.Fatal("dictionary values were not stored as authenticated ciphertext")
	}

	revisionCtx, revisionRecorder := newTenantContextWithRole(http.MethodPost, "/projects/vault-project/credential-dictionaries/"+response.ID+"/revisions", "operator", "7")
	revisionCtx.Params = gin.Params{{Key: "id", Value: "vault-project"}, {Key: "dictionary_id", Value: response.ID}}
	revisionCtx.Request = httptest.NewRequest(http.MethodPost, revisionCtx.Request.URL.String(), strings.NewReader(`{"values":["service"]}`))
	revisionCtx.Request.Header.Set("Content-Type", "application/json")
	addCredentialDictionaryRevision(revisionCtx)
	if revisionRecorder.Code != http.StatusCreated {
		t.Fatalf("create revision status=%d body=%s", revisionRecorder.Code, revisionRecorder.Body.String())
	}
	var count int64
	if err := store.Model(&db.CredentialDictionaryRevision{}).Where("dictionary_id = ?", response.ID).Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("immutable revision count=%d err=%v", count, err)
	}
}

func TestCredentialFindingListIsMaskedAndRevealIsAudited(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "finding-project", TenantID: "default", OwnerUserID: "7", Status: "active"}
	root := db.RootTask{ID: "finding-root", TenantID: "default", ProjectID: project.ID, UserID: "7", Status: "FINISHED"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	vault, _ := credentialvault.NewFromEnvironment(true)
	plaintext := []byte(`{"username":"admin","password":"verified-secret","evidence":{"show_msg":"private"}}`)
	ciphertext, nonce, err := vault.Seal(plaintext, []byte("finding:default:finding-1"))
	if err != nil {
		t.Fatal(err)
	}
	finding := db.CredentialFindingSecret{ID: "finding-1", TenantID: "default", ProjectID: project.ID, RootTaskID: root.ID, Endpoint: "192.0.2.10:22", Service: "ssh", Plugin: "SSH-Login", MaskedUsername: "a***n", Ciphertext: ciphertext, Nonce: nonce}
	if err := store.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	listCtx, listRecorder := newTenantContextWithRole(http.MethodGet, "/tasks/finding-root/credential-findings", "viewer", "7")
	listCtx.Params = gin.Params{{Key: "id", Value: root.ID}}
	listTaskCredentialFindings(listCtx)
	if listRecorder.Code != http.StatusOK || strings.Contains(listRecorder.Body.String(), "verified-secret") || strings.Contains(listRecorder.Body.String(), "ciphertext") || !strings.Contains(listRecorder.Body.String(), "a***n") {
		t.Fatalf("unsafe masked list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}

	revealCtx, revealRecorder := newTenantContextWithRole(http.MethodPost, "/credential-findings/finding-1/reveal", "admin", "1")
	revealCtx.Params = gin.Params{{Key: "id", Value: finding.ID}}
	revealCredentialFinding(revealCtx)
	if revealRecorder.Code != http.StatusOK || !strings.Contains(revealRecorder.Body.String(), "verified-secret") {
		t.Fatalf("admin reveal status=%d body=%s", revealRecorder.Code, revealRecorder.Body.String())
	}
	var audits int64
	if err := store.Model(&db.CredentialRevealAudit{}).Where("finding_id = ? AND actor_id = ?", finding.ID, "1").Count(&audits).Error; err != nil || audits != 1 {
		t.Fatalf("reveal audit count=%d err=%v", audits, err)
	}
}

func TestCredentialDictionaryRejectsCrossProjectManagement(t *testing.T) {
	store := setupAITestDB(t)
	projects := []db.Project{
		{ID: "owned", TenantID: "default", OwnerUserID: "7", Status: "active"},
		{ID: "foreign", TenantID: "default", OwnerUserID: "8", Status: "active"},
	}
	if err := store.Create(&projects).Error; err != nil {
		t.Fatal(err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/projects/foreign/credential-dictionaries", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "foreign"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/projects/foreign/credential-dictionaries", strings.NewReader(`{"name":"blocked","kind":"password","values":["secret"]}`))
	createCredentialDictionary(ctx)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-project create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCredentialDictionaryWritePathClassification(t *testing.T) {
	for _, path := range []string{
		"/api/v1/projects/project-a/credential-dictionaries",
		"/api/v1/projects/project-a/credential-dictionaries/dict-a/revisions",
	} {
		if !isCredentialDictionaryWritePath(path) {
			t.Fatalf("expected dictionary write path: %s", path)
		}
	}
	for _, path := range []string{
		"/api/v1/projects/project-a/credential-dictionaries/dict-a",
		"/api/v1/projects/project-a/asset-discovery/queries",
		"/api/v1/tasks",
	} {
		if isCredentialDictionaryWritePath(path) {
			t.Fatalf("unexpected dictionary write path: %s", path)
		}
	}
}
