package api

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	projectDataExportBatchSize     = 500
	projectDataImportBatchSize     = 500
	projectDataImportMaxBytes      = 512 << 20 // 512 MiB 压缩包上限
	projectDataExportFormatVersion = 1

	projectDataModeNew   = "new"
	projectDataModeMerge = "merge"
)

// ---------------------------------------------------------------------------
// 导出：GET /api/v1/projects/:id/export
// ---------------------------------------------------------------------------

type projectDataExportMeta struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Tags          string `json:"tags"`
	SeedTargets   string `json:"seed_targets"`
	Scope         string `json:"scope"`
	DefaultConfig string `json:"default_config"`
	NodeAffinity  string `json:"node_affinity"`
}

type projectDataImportMeta struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Tags          string `json:"tags"`
	SeedTargets   string `json:"seed_targets"`
	Scope         string `json:"scope"`
	DefaultConfig string `json:"default_config"`
	NodeAffinity  string `json:"node_affinity"`
}

// jsonArrayStreamer 自增式写 JSON 数组（逗号由 elem 维护），保证 O(1) 内存。
type jsonArrayStreamer struct {
	w   io.Writer
	enc *json.Encoder
	n   int
}

func (s *jsonArrayStreamer) begin() {
	_, _ = s.w.Write([]byte("["))
}

func (s *jsonArrayStreamer) elem(v interface{}) error {
	if s.n > 0 {
		if _, err := s.w.Write([]byte(",")); err != nil {
			return err
		}
	}
	if err := s.enc.Encode(v); err != nil { // Encode 追加的换行是合法 JSON 空白
		return err
	}
	s.n++
	return nil
}

func (s *jsonArrayStreamer) end() {
	_, _ = s.w.Write([]byte("]"))
}

func sanitizeProjectDataFilename(name string) string {
	name = strings.TrimSpace(name)
	name = strings.NewReplacer(
		"/", "_", "\\", "_", `"`, "", "\r", "", "\n", "", " ", "_",
	).Replace(name)
	if name == "" {
		name = "project"
	}
	return name + ".argus.json.gz"
}

// streamProjectEntities 按 id ASC 分批（Offset/Limit）读出某实体的本项目行并写入数组。
func streamProjectEntities[T any](base *gorm.DB, tenantID, projectID string, s *jsonArrayStreamer) (int64, error) {
	query := base.Model(new(T)).
		Where("tenant_id = ? AND project_id = ?", tenantID, projectID).
		Order("id ASC")
	var total int64
	for offset := 0; ; offset += projectDataExportBatchSize {
		var rows []T
		if err := query.Session(&gorm.Session{}).
			Limit(projectDataExportBatchSize).Offset(offset).
			Find(&rows).Error; err != nil {
			return total, err
		}
		if len(rows) == 0 {
			break
		}
		for i := range rows {
			if err := s.elem(&rows[i]); err != nil {
				return total, err
			}
		}
		total += int64(len(rows))
		if len(rows) < projectDataExportBatchSize {
			break
		}
	}
	return total, nil
}

func exportProjectData(c *gin.Context) {
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}
	tenantID := currentTenantID(c)
	filename := sanitizeProjectDataFilename(project.Name)

	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	gz := gzip.NewWriter(c.Writer)
	defer gz.Close() // 即使中途失败也收尾，客户端靠 gzip/JSON 解析失败发现截断
	enc := json.NewEncoder(gz)

	counts := map[string]int64{}
	write := func() error {
		if _, err := fmt.Fprintf(gz, `{"format_version":%d,"exported_at":%q,"project":`,
			projectDataExportFormatVersion, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		meta := projectDataExportMeta{
			Name:          project.Name,
			Description:   project.Description,
			Tags:          project.Tags,
			SeedTargets:   project.SeedTargets,
			Scope:         project.Scope,
			DefaultConfig: project.DefaultConfig,
			NodeAffinity:  project.NodeAffinity,
		}
		if err := enc.Encode(meta); err != nil {
			return err
		}

		sections := []struct {
			key string
			run func(*jsonArrayStreamer) (int64, error)
		}{
			{"assets", func(s *jsonArrayStreamer) (int64, error) {
				return streamProjectEntities[db.Asset](db.DB, tenantID, project.ID, s)
			}},
			{"vulnerabilities", func(s *jsonArrayStreamer) (int64, error) {
				return streamProjectEntities[db.Vulnerability](db.DB, tenantID, project.ID, s)
			}},
			{"fingerprint_hits", func(s *jsonArrayStreamer) (int64, error) {
				return streamProjectEntities[db.FingerprintHit](db.DB, tenantID, project.ID, s)
			}},
			{"domains", func(s *jsonArrayStreamer) (int64, error) {
				return streamProjectEntities[db.Domain](db.DB, tenantID, project.ID, s)
			}},
		}
		for _, section := range sections {
			if _, err := gz.Write([]byte(",\"" + section.key + "\":")); err != nil {
				return err
			}
			streamer := &jsonArrayStreamer{w: gz, enc: enc}
			streamer.begin()
			n, err := section.run(streamer)
			if err != nil {
				return err
			}
			streamer.end()
			counts[section.key] = n
		}
		_, err := gz.Write([]byte("}"))
		return err
	}

	if err := write(); err != nil {
		// 状态码/响应头已发出，无法改状态；仅记日志。
		log.Printf("project data export failed: project=%s err=%v", project.ID, err)
		return
	}

	recordProjectDataAudit(c, project, "project_data_export", map[string]interface{}{
		"filename": filename,
		"counts":   counts,
	})
}

// ---------------------------------------------------------------------------
// 导入：POST /api/v1/projects/import  (multipart field "file"; mode/project_id 走 query string)
// ---------------------------------------------------------------------------

type projectDataEntityCounts struct {
	Received int64 `json:"received"`
	Inserted int64 `json:"inserted"`
	Updated  int64 `json:"updated"`
}

type projectDataImportResult struct {
	ProjectID string                            `json:"project_id"`
	Mode      string                            `json:"mode"`
	Counts    map[string]projectDataEntityCounts `json:"counts"`
}

// entityImportPlan 描述一类实体的导入策略：重定租户/项目、自然去重键、upsert。
type entityImportPlan[T any] struct {
	rescope  func(row T, tenantID, projectID string) T
	keyOf    func(row T) string
	columns  []string // 自然去重键列（count existing 用）
	valsOf   func(row T) []interface{}
	upsert   func(tx *gorm.DB, rows []T) error
}

func importProjectData(c *gin.Context) {
	mode := strings.ToLower(strings.TrimSpace(c.Query("mode")))
	if mode != projectDataModeNew && mode != projectDataModeMerge {
		c.JSON(http.StatusBadRequest, gin.H{"error": `mode must be "new" or "merge"`})
		return
	}
	tenantID := currentTenantID(c)

	result := projectDataImportResult{
		Mode: mode,
		Counts: map[string]projectDataEntityCounts{
			"assets":           {},
			"vulnerabilities":  {},
			"fingerprint_hits": {},
			"domains":          {},
		},
	}

	targetProjectID := ""
	if mode == projectDataModeMerge {
		project, ok := requireProjectManage(c, c.Query("project_id"))
		if !ok {
			return
		}
		targetProjectID = project.ID
		result.ProjectID = project.ID
	}

	if c.Request.ContentLength > projectDataImportMaxBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds size limit"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, projectDataImportMaxBytes)

	mr, err := c.Request.MultipartReader()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request must be multipart/form-data"})
		return
	}

	var dec *json.Decoder
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "read upload failed: " + err.Error()})
			return
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		gzr, err := gzip.NewReader(part)
		if err != nil {
			_ = part.Close()
			c.JSON(http.StatusBadRequest, gin.H{"error": "file is not a valid gzip archive"})
			return
		}
		dec = json.NewDecoder(gzr)
		break
	}
	if dec == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": `multipart field "file" is required`})
		return
	}

	if err := runProjectDataImport(c, dec, tenantID, &targetProjectID, &result); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if result.ProjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid bundle: missing project metadata"})
		return
	}

	recordProjectDataAudit(c, db.Project{ID: result.ProjectID, TenantID: tenantID}, "project_data_import", map[string]interface{}{
		"mode":   mode,
		"counts": result.Counts,
	})

	c.JSON(http.StatusOK, result)
}

// runProjectDataImport 流式遍历顶层对象，按 key 分发；未知字段跳过（前向兼容）。
func runProjectDataImport(c *gin.Context, dec *json.Decoder, tenantID string, targetProjectID *string, result *projectDataImportResult) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("bundle root must be a JSON object")
	}

	var meta projectDataImportMeta
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read bundle key: %w", err)
		}
		key, _ := keyTok.(string)
		switch key {
		case "format_version":
			var v int
			if err := dec.Decode(&v); err != nil {
				return fmt.Errorf("format_version: %w", err)
			}
			if v != projectDataExportFormatVersion {
				return fmt.Errorf("unsupported format_version %d", v)
			}
		case "project":
			if err := dec.Decode(&meta); err != nil {
				return fmt.Errorf("project metadata: %w", err)
			}
			if result.Mode == projectDataModeNew && *targetProjectID == "" {
				project, err := createImportedProject(c, tenantID, meta)
				if err != nil {
					return fmt.Errorf("create project: %w", err)
				}
				*targetProjectID = project.ID
				result.ProjectID = project.ID
			}
		case "assets":
			n, err := importEntityRows(dec, tenantID, *targetProjectID, assetImportPlan)
			if err != nil {
				return fmt.Errorf("assets: %w", err)
			}
			result.Counts["assets"] = n
		case "vulnerabilities":
			n, err := importEntityRows(dec, tenantID, *targetProjectID, vulnerabilityImportPlan)
			if err != nil {
				return fmt.Errorf("vulnerabilities: %w", err)
			}
			result.Counts["vulnerabilities"] = n
		case "fingerprint_hits":
			n, err := importEntityRows(dec, tenantID, *targetProjectID, fingerprintImportPlan)
			if err != nil {
				return fmt.Errorf("fingerprint_hits: %w", err)
			}
			result.Counts["fingerprint_hits"] = n
		case "domains":
			n, err := importEntityRows(dec, tenantID, *targetProjectID, domainImportPlan)
			if err != nil {
				return fmt.Errorf("domains: %w", err)
			}
			result.Counts["domains"] = n
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return fmt.Errorf("skip field %q: %w", key, err)
			}
		}
	}
	return nil
}

// importEntityRows 流式读一个实体数组，分批（500）重定→去重→计数→事务 upsert。
func importEntityRows[T any](dec *json.Decoder, tenantID, projectID string, plan entityImportPlan[T]) (projectDataEntityCounts, error) {
	counts := projectDataEntityCounts{}
	if strings.TrimSpace(projectID) == "" {
		return counts, errors.New("target project not resolved (missing project metadata)")
	}
	tok, err := dec.Token()
	if err != nil {
		return counts, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return counts, errors.New("expected a JSON array")
	}

	base := db.DB.Model(new(T)).Where("tenant_id = ? AND project_id = ?", tenantID, projectID)

	for dec.More() {
		var batch []T
		for dec.More() && len(batch) < projectDataImportBatchSize {
			var row T
			if err := dec.Decode(&row); err != nil {
				return counts, fmt.Errorf("decode row: %w", err)
			}
			batch = append(batch, plan.rescope(row, tenantID, projectID))
		}
		if len(batch) == 0 {
			continue
		}
		counts.Received += int64(len(batch))

		uniq := make(map[string]T, len(batch))
		var order []string
		for _, row := range batch {
			k := plan.keyOf(row)
			if _, seen := uniq[k]; !seen {
				order = append(order, k)
			}
			uniq[k] = row
		}
		rows := make([]T, 0, len(uniq))
		for _, k := range order {
			rows = append(rows, uniq[k])
		}

		existing, err := countExistingEntityRows(base, rows, plan)
		if err != nil {
			return counts, err
		}
		if err := db.DB.Transaction(func(tx *gorm.DB) error {
			return plan.upsert(tx, rows)
		}); err != nil {
			return counts, err
		}
		counts.Inserted += int64(len(rows)) - existing
		counts.Updated += existing
	}

	// 消费收尾的 ']'
	if _, err := dec.Token(); err != nil {
		return counts, err
	}
	return counts, nil
}

func countExistingEntityRows[T any](base *gorm.DB, rows []T, plan entityImportPlan[T]) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	var conds []string
	var args []interface{}
	for _, row := range rows {
		parts := make([]string, len(plan.columns))
		for i, col := range plan.columns {
			parts[i] = col + " = ?"
		}
		conds = append(conds, "("+strings.Join(parts, " AND ")+")")
		args = append(args, plan.valsOf(row)...)
	}
	var n int64
	err := base.Session(&gorm.Session{}).
		Where(strings.Join(conds, " OR "), args...).
		Count(&n).Error
	return n, err
}

func upsertImportAssets(tx *gorm.DB, rows []db.Asset) error {
	if len(rows) == 0 {
		return nil
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}, {Name: "target"}, {Name: "protocol"}},
		DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "port", "url", "title", "service", "cert_subject", "cert_expiry", "status", "updated_at"}),
	}).CreateInBatches(rows, projectDataImportBatchSize).Error
}

func upsertImportVulnerabilities(tx *gorm.DB, rows []db.Vulnerability) error {
	if len(rows) == 0 {
		return nil
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}, {Name: "target"}, {Name: "plugin"}},
		DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "severity", "payload", "request", "response", "description", "reference", "matched_at", "updated_at", "status"}),
	}).CreateInBatches(rows, projectDataImportBatchSize).Error
}

func upsertImportFingerprints(tx *gorm.DB, rows []db.FingerprintHit) error {
	if len(rows) == 0 {
		return nil
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "project_id"}, {Name: "target"}, {Name: "product_name"}},
		DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "rule_name", "evidence", "updated_at"}),
	}).CreateInBatches(rows, projectDataImportBatchSize).Error
}

func upsertImportDomains(tx *gorm.DB, rows []db.Domain) error {
	if len(rows) == 0 {
		return nil
	}
	// 注意：domains 的去重唯一索引是 (tenant_id, project_id, name)，与 asset/fp/vuln 不同，
	// ON CONFLICT 列必须与唯一索引一致（Postgres 仲裁器 + sqlite 均如此）。
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"task_id", "tags", "records", "icp", "whois", "status", "updated_at"}),
	}).CreateInBatches(rows, projectDataImportBatchSize).Error
}

var assetImportPlan = entityImportPlan[db.Asset]{
	rescope: func(row db.Asset, tenantID, projectID string) db.Asset {
		row.ID, row.TenantID, row.ProjectID = 0, tenantID, projectID
		return row
	},
	keyOf:   func(row db.Asset) string { return row.ProjectID + "|" + row.Target + "|" + row.Protocol },
	columns: []string{"target", "protocol"},
	valsOf:  func(row db.Asset) []interface{} { return []interface{}{row.Target, row.Protocol} },
	upsert:  upsertImportAssets,
}

var vulnerabilityImportPlan = entityImportPlan[db.Vulnerability]{
	rescope: func(row db.Vulnerability, tenantID, projectID string) db.Vulnerability {
		row.ID, row.TenantID, row.ProjectID = 0, tenantID, projectID
		return row
	},
	keyOf:   func(row db.Vulnerability) string { return row.ProjectID + "|" + row.Target + "|" + row.Plugin },
	columns: []string{"target", "plugin"},
	valsOf:  func(row db.Vulnerability) []interface{} { return []interface{}{row.Target, row.Plugin} },
	upsert:  upsertImportVulnerabilities,
}

var fingerprintImportPlan = entityImportPlan[db.FingerprintHit]{
	rescope: func(row db.FingerprintHit, tenantID, projectID string) db.FingerprintHit {
		row.ID, row.TenantID, row.ProjectID = 0, tenantID, projectID
		return row
	},
	keyOf:   func(row db.FingerprintHit) string { return row.ProjectID + "|" + row.Target + "|" + row.ProductName },
	columns: []string{"target", "product_name"},
	valsOf:  func(row db.FingerprintHit) []interface{} { return []interface{}{row.Target, row.ProductName} },
	upsert:  upsertImportFingerprints,
}

var domainImportPlan = entityImportPlan[db.Domain]{
	rescope: func(row db.Domain, tenantID, projectID string) db.Domain {
		row.ID, row.TenantID, row.ProjectID = 0, tenantID, projectID
		return row
	},
	keyOf:   func(row db.Domain) string { return row.ProjectID + "|" + row.Name },
	columns: []string{"name"},
	valsOf:  func(row db.Domain) []interface{} { return []interface{}{row.Name} },
	upsert:  upsertImportDomains,
}

func validJSONOr(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" || !json.Valid([]byte(v)) {
		return fallback
	}
	return v
}

func createImportedProject(c *gin.Context, tenantID string, meta projectDataImportMeta) (db.Project, error) {
	now := time.Now()
	name := strings.TrimSpace(meta.Name)
	if name == "" {
		name = "Imported Project"
	}
	project := db.Project{
		ID:            fmt.Sprintf("proj-%d", now.UnixNano()),
		TenantID:      tenantID,
		OwnerUserID:   currentUserID(c),
		Name:          name + " (导入)",
		Description:   meta.Description,
		Tags:          validJSONOr(meta.Tags, "[]"),
		SeedTargets:   validJSONOr(meta.SeedTargets, "[]"),
		Scope:         validJSONOr(meta.Scope, "[]"),
		DefaultConfig: validJSONOr(meta.DefaultConfig, "{}"),
		NodeAffinity:  validJSONOr(meta.NodeAffinity, "{}"),
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&project).Error; err != nil {
			return err
		}
		return upsertProjectMember(tx, tenantID, project.ID, currentUserID(c), "owner")
	})
	return project, err
}

// recordProjectDataAudit 写一条 TaskAudit 留痕（best-effort，不阻断主流程）。
func recordProjectDataAudit(c *gin.Context, project db.Project, action string, details map[string]interface{}) {
	payload := "{}"
	if len(details) > 0 {
		if encoded, err := json.Marshal(details); err == nil {
			payload = string(encoded)
		}
	}
	entry := db.TaskAudit{
		TenantID:   project.TenantID,
		ProjectID:  project.ID,
		OperatorID: taskOperatorID(c),
		Action:     action,
		Details:    payload,
		CreatedAt:  time.Now(),
	}
	if err := db.DB.Create(&entry).Error; err != nil {
		log.Printf("record project data audit failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 项目数据浏览：GET /api/v1/domains
// ---------------------------------------------------------------------------

func getDomains(c *gin.Context) {
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.Domain{}).Where("tenant_id = ?", tenantID)
	query, _ = applyProjectScope(c, query, "project_id")
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		like := "%" + search + "%"
		query = query.Where("name LIKE ? OR records LIKE ?", like, like)
	}
	var domains []db.Domain
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.Domain{}, &domains)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(domains, total, page, pageSize, ""))
}
