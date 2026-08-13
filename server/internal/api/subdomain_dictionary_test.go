package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func TestSubdomainDictionaryStoresCanonicalImmutableRevisions(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "subdomain-project", TenantID: "default", OwnerUserID: "7", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/projects/subdomain-project/subdomain-dictionaries", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "subdomain-project"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, ctx.Request.URL.String(), strings.NewReader(`{"name":"environment labels","values":["DEV","api","dev"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	createSubdomainDictionary(ctx)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create dictionary status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response subdomainDictionaryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Count != 2 || response.Revision != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	var stored db.SubdomainDictionaryRevision
	if err := store.Where("dictionary_id = ?", response.ID).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.ValuesJSON != `["api","dev"]` || len(stored.SHA256) != 64 {
		t.Fatalf("revision was not canonical: %+v", stored)
	}

	revisionCtx, revisionRecorder := newTenantContextWithRole(http.MethodPost, "/projects/subdomain-project/subdomain-dictionaries/"+response.ID+"/revisions", "operator", "7")
	revisionCtx.Params = gin.Params{{Key: "id", Value: "subdomain-project"}, {Key: "dictionary_id", Value: response.ID}}
	revisionCtx.Request = httptest.NewRequest(http.MethodPost, revisionCtx.Request.URL.String(), strings.NewReader(`{"values":["staging"]}`))
	revisionCtx.Request.Header.Set("Content-Type", "application/json")
	addSubdomainDictionaryRevision(revisionCtx)
	if revisionRecorder.Code != http.StatusCreated {
		t.Fatalf("create revision status=%d body=%s", revisionRecorder.Code, revisionRecorder.Body.String())
	}
	var count int64
	if err := store.Model(&db.SubdomainDictionaryRevision{}).Where("dictionary_id = ?", response.ID).Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("immutable revision count=%d err=%v", count, err)
	}
}

func TestSubdomainDictionaryRejectsMultiLabelEntries(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "single-label-project", TenantID: "default", OwnerUserID: "7", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/projects/single-label-project/subdomain-dictionaries", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "single-label-project"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, ctx.Request.URL.String(), strings.NewReader(`{"name":"invalid","values":["dev.api"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	createSubdomainDictionary(ctx)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "single-label") {
		t.Fatalf("multi-label create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSubdomainDictionaryRejectsCrossProjectManagement(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "foreign-subdomain", TenantID: "default", OwnerUserID: "8", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/projects/foreign-subdomain/subdomain-dictionaries", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "foreign-subdomain"}}
	ctx.Request = httptest.NewRequest(http.MethodPost, ctx.Request.URL.String(), strings.NewReader(`{"name":"blocked","values":["dev"]}`))
	createSubdomainDictionary(ctx)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-project create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSubdomainDictionaryWritePathClassification(t *testing.T) {
	for _, path := range []string{
		"/api/v1/projects/project-a/subdomain-dictionaries",
		"/api/v1/projects/project-a/subdomain-dictionaries/dict-a/revisions",
	} {
		if !isSubdomainDictionaryWritePath(path) {
			t.Fatalf("expected dictionary write path: %s", path)
		}
	}
	if isSubdomainDictionaryWritePath("/api/v1/projects/project-a/subdomain-dictionaries/dict-a") {
		t.Fatal("delete path must not be classified as a request-body write path")
	}
}
