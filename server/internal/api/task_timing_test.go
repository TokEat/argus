package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func TestTaskDetailReturnsScopedTimingAndLegacyUnavailable(t *testing.T) {
	store := setupAITestDB(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	project := db.Project{ID: "project-timing-" + suffix, TenantID: "default", OwnerUserID: "viewer-timing-" + suffix, Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	root := db.RootTask{ID: "task-timing-" + suffix, TenantID: "default", ProjectID: project.ID, Name: "timing", Status: "FINISHED", Config: `{}`}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	attempts := []db.SubTask{
		{ID: "attempt-timed-" + suffix, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Status: "Done", AgentID: "agent-timing-" + suffix},
		{ID: "attempt-legacy-" + suffix, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Status: "Done", AgentID: "agent-legacy-" + suffix},
		{ID: "attempt-empty-" + suffix, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Status: "Done"},
	}
	if err := store.Create(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 8, 10, 2, 0, 0, 0, time.UTC)
	if err := store.Create(&db.ScanTimingEvent{
		SchemaVersion: db.ScanTimingEventSchemaVersion, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID,
		BatchID: "batch-timing-" + suffix, AttemptID: attempts[0].ID, AgentID: "agent-timing-" + suffix, SourceEventID: fmt.Sprintf("%064x", time.Now().UnixNano()),
		Kind: "context_init", Outcome: "success", StartedAt: started, FinishedAt: started.Add(500 * time.Microsecond), DurationNS: int64(500 * time.Microsecond),
		ConfigVersion: 1, RuleVersion: "rules-timing", CreatedAt: started,
	}).Error; err != nil {
		t.Fatal(err)
	}
	// A colliding task ID in another project must never enter this projection.
	if err := store.Create(&db.ScanTimingEvent{
		SchemaVersion: db.ScanTimingEventSchemaVersion, TenantID: root.TenantID, ProjectID: "project-other-" + suffix, RootTaskID: root.ID,
		BatchID: "batch-other-" + suffix, AttemptID: attempts[0].ID, AgentID: "agent-other-" + suffix, SourceEventID: fmt.Sprintf("%064x", time.Now().UnixNano()+1),
		Kind: "rule_prepare", Outcome: "success", StartedAt: started, FinishedAt: started.Add(time.Second), DurationNS: int64(time.Second),
		ConfigVersion: 1, RuleVersion: "rules-other", CreatedAt: started,
	}).Error; err != nil {
		t.Fatal(err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/tasks/"+root.ID, "viewer", project.OwnerUserID)
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskDetail(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("task detail status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Timing db.TaskTimingProjection `json:"timing"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Timing.Truncated || len(response.Timing.Attempts) != 3 {
		t.Fatalf("unexpected timing projection: %+v", response.Timing)
	}
	if !response.Timing.Attempts[0].Available || response.Timing.Attempts[0].UnavailableReason != "" || len(response.Timing.Attempts[0].Events) != 1 || response.Timing.Attempts[0].Events[0].DurationNS != int64(500*time.Microsecond) {
		t.Fatalf("timed attempt projection lost precise evidence: %+v", response.Timing.Attempts[0])
	}
	if response.Timing.Attempts[1].Available || response.Timing.Attempts[1].UnavailableReason != db.TimingUnavailableNotReported || len(response.Timing.Attempts[1].Events) != 0 {
		t.Fatalf("executed attempt without timing was presented as measured: %+v", response.Timing.Attempts[1])
	}
	if response.Timing.Attempts[2].Available || response.Timing.Attempts[2].UnavailableReason != db.TimingUnavailableNotExecuted || len(response.Timing.Attempts[2].Events) != 0 {
		t.Fatalf("locally completed attempt was presented as measured: %+v", response.Timing.Attempts[2])
	}
	if strings.Contains(recorder.Body.String(), "rules-other") || strings.Contains(recorder.Body.String(), "project-other-") {
		t.Fatalf("cross-project timing leaked into response: %s", recorder.Body.String())
	}
}
