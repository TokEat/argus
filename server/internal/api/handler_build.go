package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/storage"
	"github.com/gin-gonic/gin"
)

func listBuildArtifacts(c *gin.Context) {
	type Artifact struct {
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
		ModTime  string `json:"mod_time"`
	}

	artifacts := make([]Artifact, 0)
	store, err := storage.NewLocalStore("./release")
	if err != nil {
		c.JSON(http.StatusOK, artifacts)
		return
	}
	objects, err := store.List(c.Request.Context(), "")
	if err != nil {
		c.JSON(http.StatusOK, artifacts)
		return
	}
	for _, obj := range objects {
		if strings.Contains(obj.Key, "/") {
			continue
		}
		name := obj.Key
		if !isSupportedBuildArtifactName(name) {
			continue
		}
		platform, arch := parseBinaryName(name)
		artifacts = append(artifacts, Artifact{
			Name:     name,
			Size:     obj.Size,
			Platform: platform,
			Arch:     arch,
			ModTime:  obj.ModTime.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, artifacts)
}

func isSupportedBuildArtifactName(name string) bool {
	if name == "server-ui-dist.tar.gz" {
		return true
	}

	for _, component := range []string{"argus-agent", "argus-server", "argus"} {
		prefix := component + "-"
		if !strings.HasPrefix(name, prefix) {
			continue
		}

		rest := strings.TrimPrefix(name, prefix)
		packaged := strings.HasSuffix(rest, ".tar.gz")
		windowsExecutable := strings.HasSuffix(rest, ".exe")
		switch {
		case packaged:
			if component != "argus" {
				return false
			}
			rest = strings.TrimSuffix(rest, ".tar.gz")
		case windowsExecutable:
			rest = strings.TrimSuffix(rest, ".exe")
		}

		parts := strings.Split(rest, "-")
		if len(parts) != 2 || !isSupportedReleaseTarget(parts[0], parts[1]) {
			return false
		}
		if packaged {
			return true
		}
		if parts[0] == "windows" {
			return windowsExecutable
		}
		return !windowsExecutable
	}
	return false
}

func isSupportedReleaseTarget(platform, arch string) bool {
	switch platform {
	case "linux", "darwin":
		return arch == "amd64" || arch == "arm64"
	case "windows":
		return arch == "amd64" || arch == "arm64" || arch == "386"
	default:
		return false
	}
}

func parseBinaryName(name string) (platform, arch string) {
	parts := strings.Split(name, "-")
	for _, p := range parts {
		switch p {
		case "linux", "darwin", "windows":
			platform = p
		case "amd64", "arm64", "386":
			arch = p
		}
	}
	if platform == "" {
		platform = "unknown"
	}
	if arch == "" {
		arch = "unknown"
	}
	return
}

func listBuildJobs(c *gin.Context) {
	limit := 20
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 100 {
		limit = 100
	}
	var jobs []db.BuildJob
	db.DB.Select("id", "platform", "arch", "components", "pack", "status", "artifact", "artifacts", "log_tail", "error", "started_at", "finished_at", "created_at", "updated_at").
		Order("created_at DESC").Limit(limit).Find(&jobs)
	c.JSON(http.StatusOK, buildJobResponses(jobs))
}

func getBuildJob(c *gin.Context) {
	var job db.BuildJob
	if err := db.DB.Select("id", "platform", "arch", "components", "pack", "status", "artifact", "artifacts", "log_tail", "error", "started_at", "finished_at", "created_at", "updated_at").
		First(&job, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	c.JSON(http.StatusOK, buildJobResponse(job))
}

func buildJobResponses(jobs []db.BuildJob) []gin.H {
	out := make([]gin.H, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, buildJobResponse(job))
	}
	return out
}

func buildJobResponse(job db.BuildJob) gin.H {
	return gin.H{
		"id": job.ID, "platform": job.Platform, "arch": job.Arch, "pack": job.Pack,
		"components": buildComponentsFromJSON(job.Components),
		"status":     job.Status, "artifact": job.Artifact, "artifacts": buildArtifactsFromJSON(job.Artifacts, job.Artifact),
		"log_tail": job.LogTail, "error": job.Error, "started_at": job.StartedAt, "finished_at": job.FinishedAt,
		"created_at": job.CreatedAt, "updated_at": job.UpdatedAt,
	}
}

func getBuildJobLogs(c *gin.Context) {
	var job db.BuildJob
	if err := db.DB.Select("id", "log_tail", "log_text").First(&job, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	logText := job.LogText
	if logText == "" {
		logText = job.LogTail
	}
	c.String(http.StatusOK, logText)
}

func cancelBuildJob(c *gin.Context) {
	jobID, err := parseBuildJobID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid build job id"})
		return
	}

	routerRuntime().Build.mu.Lock()
	defer routerRuntime().Build.mu.Unlock()

	var job db.BuildJob
	if err := db.DB.Select("id", "status").First(&job, "id = ?", jobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	if job.Status != "queued" && job.Status != "running" {
		c.JSON(http.StatusConflict, gin.H{"error": "build job is already finished"})
		return
	}

	cancelRegisteredBuild(jobID)
	finishedAt := time.Now()
	result := db.DB.Model(&db.BuildJob{}).
		Where("id = ? AND status IN ?", jobID, []string{"queued", "running"}).
		Updates(map[string]interface{}{
			"status":      "canceled",
			"error":       "build canceled by user",
			"finished_at": &finishedAt,
		})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "build job is already finished"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "canceled", "job_id": jobID})
}

func retryBuildJob(c *gin.Context) {
	jobID, err := parseBuildJobID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid build job id"})
		return
	}

	var oldJob db.BuildJob
	if err := db.DB.Select("id", "platform", "arch", "pack", "status").First(&oldJob, "id = ?", jobID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Build job not found"})
		return
	}
	if oldJob.Status == "queued" || oldJob.Status == "running" {
		c.JSON(http.StatusConflict, gin.H{"error": "build job is still active"})
		return
	}
	if !isSupportedBuildTarget(oldJob.Platform, oldJob.Arch) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported build target"})
		return
	}

	if _, err := os.Stat("./build.sh"); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "build.sh not found in project root"})
		return
	}
	job, err := createBuildJobIfIdle(oldJob.Platform, oldJob.Arch, oldJob.Pack, buildComponentsFromJSON(oldJob.Components))
	if errors.Is(err, errBuildAlreadyQueued) {
		c.JSON(http.StatusConflict, gin.H{"error": "another build job is already queued or running"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	routerRuntime().Build.start(job.ID)

	c.JSON(http.StatusAccepted, gin.H{
		"status":      "queued",
		"message":     fmt.Sprintf("Build job retried: %s/%s (pack=%v)", oldJob.Platform, oldJob.Arch, oldJob.Pack),
		"job_id":      job.ID,
		"retry_of_id": oldJob.ID,
	})
}

func triggerBuild(c *gin.Context) {
	var req struct {
		Platform   string   `json:"platform"` // linux, darwin, windows
		Arch       string   `json:"arch"`     // amd64, arm64
		Pack       bool     `json:"pack"`     // 是否 UPX 压缩
		Components []string `json:"components"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Platform == "" {
		req.Platform = "linux"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}
	if !isSupportedBuildTarget(req.Platform, req.Arch) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported build target"})
		return
	}

	components, err := normalizeBuildComponents(req.Components)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查 build.sh 是否存在
	buildScript := "./build.sh"
	if _, err := os.Stat(buildScript); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "build.sh not found in project root"})
		return
	}

	job, err := createBuildJobIfIdle(req.Platform, req.Arch, req.Pack, components)
	if errors.Is(err, errBuildAlreadyQueued) {
		c.JSON(http.StatusConflict, gin.H{"error": "another build job is already queued or running"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	routerRuntime().Build.start(job.ID)

	c.JSON(http.StatusAccepted, gin.H{
		"status":     "queued",
		"message":    fmt.Sprintf("Build job queued: %s/%s (pack=%v)", req.Platform, req.Arch, req.Pack),
		"job_id":     job.ID,
		"platform":   req.Platform,
		"arch":       req.Arch,
		"components": components,
	})
}

func createBuildJobIfIdle(platform, arch string, pack bool, componentSets ...[]string) (db.BuildJob, error) {
	routerRuntime().Build.mu.Lock()
	defer routerRuntime().Build.mu.Unlock()

	var running int64
	if err := db.DB.Model(&db.BuildJob{}).Where("status IN ?", []string{"queued", "running"}).Count(&running).Error; err != nil {
		return db.BuildJob{}, err
	}
	if running > 0 {
		return db.BuildJob{}, errBuildAlreadyQueued
	}

	components := []string(nil)
	if len(componentSets) > 0 {
		components = componentSets[0]
	}
	components, err := normalizeBuildComponents(components)
	if err != nil {
		return db.BuildJob{}, err
	}
	componentJSON, _ := json.Marshal(components)
	job := db.BuildJob{
		Platform:   platform,
		Arch:       arch,
		Components: string(componentJSON),
		Pack:       pack,
		Status:     "queued",
	}
	if err := db.DB.Create(&job).Error; err != nil {
		return db.BuildJob{}, err
	}
	return job, nil
}

func parseBuildJobID(raw string) (uint, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("invalid build job id")
	}
	return uint(id), nil
}

func registerBuildCancel(jobID uint, cancel context.CancelFunc) {
	routerRuntime().Build.cancelMu.Lock()
	defer routerRuntime().Build.cancelMu.Unlock()
	routerRuntime().Build.cancels[jobID] = cancel
}

func unregisterBuildCancel(jobID uint) {
	routerRuntime().Build.cancelMu.Lock()
	defer routerRuntime().Build.cancelMu.Unlock()
	delete(routerRuntime().Build.cancels, jobID)
}

func cancelRegisteredBuild(jobID uint) {
	routerRuntime().Build.cancelMu.Lock()
	cancel := routerRuntime().Build.cancels[jobID]
	routerRuntime().Build.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func isSupportedBuildTarget(platform, arch string) bool {
	switch platform {
	case "linux", "darwin":
		return arch == "amd64" || arch == "arm64"
	case "windows":
		return arch == "amd64" || arch == "386"
	default:
		return false
	}
}

func normalizeBuildComponents(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{"argus-agent"}, nil
	}
	allowed := map[string]bool{"argus": true, "argus-agent": true, "argus-server": true, "server-ui": true}
	seen := map[string]struct{}{}
	components := make([]string, 0, len(raw))
	for _, item := range raw {
		component := strings.TrimSpace(item)
		if component == "" {
			continue
		}
		if !allowed[component] {
			return nil, fmt.Errorf("unsupported build component: %s", component)
		}
		if _, ok := seen[component]; ok {
			continue
		}
		seen[component] = struct{}{}
		components = append(components, component)
	}
	if len(components) == 0 {
		return []string{"argus-agent"}, nil
	}
	return components, nil
}

func buildComponentsFromJSON(raw string) []string {
	var components []string
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &components)
	}
	components, _ = normalizeBuildComponents(components)
	return components
}

func buildArtifactsFromJSON(raw, fallback string) []string {
	var artifacts []string
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &artifacts)
	}
	if len(artifacts) == 0 && strings.TrimSpace(fallback) != "" {
		artifacts = []string{fallback}
	}
	return artifacts
}

func expectedBuildArtifacts(components []string, platform, arch string) []string {
	artifacts := make([]string, 0, len(components))
	for _, component := range components {
		if component == "server-ui" {
			artifacts = append(artifacts, "server-ui-dist.tar.gz")
			continue
		}
		name := fmt.Sprintf("%s-%s-%s", component, platform, arch)
		if platform == "windows" {
			name += ".exe"
		}
		artifacts = append(artifacts, name)
	}
	return artifacts
}

func runBuildJob(jobID uint) {
	var job db.BuildJob
	if err := db.DB.First(&job, jobID).Error; err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	registerBuildCancel(jobID, cancel)
	defer func() {
		cancel()
		unregisterBuildCancel(jobID)
	}()

	startedAt := time.Now()
	result := db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "queued").Updates(map[string]interface{}{
		"status":     "running",
		"started_at": &startedAt,
		"log_tail":   "",
		"log_text":   "",
		"error":      "",
	})
	if result.Error != nil || result.RowsAffected == 0 {
		return
	}

	var output bytes.Buffer
	components := buildComponentsFromJSON(job.Components)
	nativeComponents := make([]string, 0, len(components))
	hasServerUI := false
	for _, component := range components {
		if component == "server-ui" {
			hasServerUI = true
		} else {
			nativeComponents = append(nativeComponents, component)
		}
	}
	var err error
	if len(nativeComponents) > 0 {
		args := []string{"--component", strings.Join(nativeComponents, ","), "--target", fmt.Sprintf("%s/%s", job.Platform, job.Arch)}
		if job.Pack {
			args = append([]string{"--pack"}, args...)
		}
		cmd := exec.CommandContext(ctx, "./build.sh", args...)
		cmd.Dir = "."
		cmd.Stdout = &output
		cmd.Stderr = &output
		err = cmd.Run()
	}
	if err == nil && hasServerUI {
		npm := exec.CommandContext(ctx, "npm", "--prefix", "server-ui", "run", "build")
		npm.Dir = "."
		npm.Stdout = &output
		npm.Stderr = &output
		err = npm.Run()
		if err == nil {
			_ = os.MkdirAll("./release", 0755)
			tarCmd := exec.CommandContext(ctx, "tar", "-czf", "release/server-ui-dist.tar.gz", "-C", "server-ui", "dist")
			tarCmd.Dir = "."
			tarCmd.Stdout = &output
			tarCmd.Stderr = &output
			err = tarCmd.Run()
		}
	}
	logText := output.String()
	logTail := truncateBuildLog(logText, 20000)
	finishedAt := time.Now()
	updates := map[string]interface{}{
		"finished_at": &finishedAt,
		"log_tail":    logTail,
		"log_text":    logText,
	}
	if err != nil {
		status := "failed"
		errMsg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			errMsg = "build timed out after 30 minutes"
		} else if ctx.Err() == context.Canceled {
			status = "canceled"
			errMsg = "build canceled by user"
		}
		updates["status"] = status
		updates["error"] = errMsg
		db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "running").Updates(updates)
		return
	}

	artifacts := expectedBuildArtifacts(components, job.Platform, job.Arch)
	store, storeErr := storage.NewLocalStore("./release")
	if storeErr != nil {
		updates["status"] = "failed"
		updates["error"] = fmt.Sprintf("build artifact storage is unavailable: %v", storeErr)
	} else {
		missing := make([]string, 0)
		for _, artifact := range artifacts {
			if _, ok, statErr := store.Exists(context.Background(), artifact); statErr != nil || !ok {
				missing = append(missing, artifact)
			}
		}
		if len(missing) > 0 {
			updates["status"] = "failed"
			updates["error"] = "build completed but expected artifacts were not found: " + strings.Join(missing, ", ")
			db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "running").Updates(updates)
			return
		}
		artifactJSON, _ := json.Marshal(artifacts)
		updates["status"] = "success"
		updates["artifact"] = artifacts[0]
		updates["artifacts"] = string(artifactJSON)
		updates["error"] = ""
	}
	db.DB.Model(&db.BuildJob{}).Where("id = ? AND status = ?", jobID, "running").Updates(updates)
}

func expectedBuildArtifact(platform, arch string) string {
	name := fmt.Sprintf("argus-agent-%s-%s", platform, arch)
	if platform == "windows" {
		name += ".exe"
	}
	return name
}

func truncateBuildLog(logText string, maxLen int) string {
	if len(logText) <= maxLen {
		return logText
	}
	return logText[len(logText)-maxLen:]
}
