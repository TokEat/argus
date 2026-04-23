# Argus 项目隔离与资产入库 - 数据库 schema 演进方案 (P8 历史稿)

本文保留为“Argus 从早期任务级入库，演进到项目级隔离与资产归档”的设计过程记录，主要解释当时为什么要引入 `Project`、为什么要把结果去重键从 `task_id` 调整到 `project_id`。

当前完整且可对照代码的数据库设计，请以 [db_schema.md](./db_schema.md) 为准。相比本历史稿，现行设计已经继续补充了以下内容：

- `reports` 报表元数据表
- `rule_catalog_bootstraps`、`fingerprint_rules`、`poc_rules`、`workflow_rules`、`dir_rules` 结构化规则治理表
- `nodes`、`users`、`system_configs` 的扩展字段
- `sub_tasks` / `root_tasks` 的完整状态机与调度补充字段

以下内容仍可作为理解 schema 演进背景的参考。

---

## 1. 顶层容器：项目与权限体系

### 1.1 `Project` (项目) 表
引入 `gorm.DeletedAt` 软删除，防止千万级资产的项目被误删导致线上灾难。配置和标签改用 `jsonb` 以支持数据库内的高效检索。
```go
type Project struct {
	ID            string `gorm:"primaryKey"`
	TenantID      string `gorm:"default:'default';index"`
	Name          string `gorm:"index"`
	Description   string `gorm:"type:text"`
	Tags          string `gorm:"type:jsonb"`                 // 业务标签 (改为 JSONB)
	SeedTargets   string `gorm:"type:jsonb"`                 // 初始资产种子 (改为 JSONB)
	Scope         string `gorm:"type:jsonb"`                 // 授权扫描边界 (改为 JSONB)
	DefaultConfig string `gorm:"type:jsonb"`                 // 项目默认扫描配置 (改为 JSONB)
	NodeAffinity  string `gorm:"type:jsonb"`                 // 节点亲和性标签 (改为 JSONB)
	Status        string `gorm:"default:'active';index"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`              // 新增：软删除护城河
}
```

### 1.2 `ProjectMember` (项目成员关联表)
```go
type ProjectMember struct {
	ProjectID string `gorm:"primaryKey"`
	UserID    string `gorm:"primaryKey"`
	Role      string `gorm:"default:'operator'"` 
	CreatedAt time.Time
}
```

---

## 2. 调度控制面：持续巡航与通知闭环

### 2.1 `CronTask` (定时巡航任务表)
```go
type CronTask struct {
	ID            string `gorm:"primaryKey"`
	ProjectID     string `gorm:"index"`
	Name          string 
	CronExpr      string `gorm:"index"`
	Targets       string `gorm:"type:jsonb"`
	Config        string `gorm:"type:jsonb"`
	NextRunAt     *time.Time `gorm:"index"`
	Status        string `gorm:"default:'active';index"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`
}
```

### 2.2 `RootTask` 和 `SubTask` (执行任务表)
```diff
 type RootTask struct {
 	ID              string `gorm:"primaryKey"`
 	TenantID        string `gorm:"default:'default';index"`
+	ProjectID       string `gorm:"index"` 
+	CronTaskID      string `gorm:"index"` 
 	UserID          string `gorm:"index"`
 	// ... 
 }
```

### 2.3 `NotificationRule` (告警路由表)
```go
type NotificationRule struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	ProjectID string `gorm:"index"`
	Event     string `gorm:"index"`
	Channel   string
	Config    string `gorm:"type:jsonb"`
	Status    string `gorm:"default:'enabled'"`
	CreatedAt time.Time
}
```

---

## 3. 资产模型：联合索引与凭证

联合唯一索引不仅要求准确，还需要在 GORM 中使用 `,uniqueIndex:idx_name` 复合声明，避免数据竞争。

### 3.1 独立域名表 (`Domain`)
```go
type Domain struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index:idx_domain_dedupe"`
	ProjectID   string `gorm:"index:idx_domain_dedupe,unique"` // 复合唯一索引
	Name        string `gorm:"index:idx_domain_dedupe,unique"` // 复合唯一索引
	TaskID      string `gorm:"index"`
	Tags        string `gorm:"type:jsonb"`
	Records     string `gorm:"type:jsonb"`
	ICP         string
	Whois       string `gorm:"type:jsonb"`
	Status      string `gorm:"default:'alive';index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
```

### 3.2 主机/服务资产表 (`Asset`)
```diff
 type Asset struct {
 	ID          uint   `gorm:"primaryKey;autoIncrement"`
-	TaskID      string `gorm:"uniqueIndex:idx_asset_dedupe"`
+	ProjectID   string `gorm:"index:idx_asset_dedupe,unique"`
+	TaskID      string `gorm:"index"`
-	Target      string `gorm:"uniqueIndex:idx_asset_dedupe"`
+	Target      string `gorm:"index:idx_asset_dedupe,unique"`
-	Protocol    string `gorm:"uniqueIndex:idx_asset_dedupe"`
+	Protocol    string `gorm:"index:idx_asset_dedupe,unique"`
 	// ...
+	Tags        string `gorm:"type:jsonb"`
+	Status      string `gorm:"default:'alive';index"` 
+	OwnerID     string `gorm:"index"`
+	CredID      string `gorm:"index"`
 	// ...
+	UpdatedAt   time.Time 
 }
```

### 3.3 扫描凭证表 (`Credential`)
```go
type Credential struct {
	ID          string `gorm:"primaryKey"`
	ProjectID   string `gorm:"index"`
	Name        string
	Type        string `gorm:"index"`
	Content     string `gorm:"type:text"` // 凭证必须加密存储，不能用 JSONB 明文查询
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"` // 软删除
}
```

---

## 4. 漏洞与流水

### 4.1 漏洞表 (`Vulnerability`)
```diff
 type Vulnerability struct {
-	TaskID       string `gorm:"uniqueIndex:idx_vuln_new_dedupe"`
+	ProjectID    string `gorm:"index:idx_vuln_new_dedupe,unique"`
+	TaskID       string `gorm:"index"`
 	// ...
+	Status       string `gorm:"default:'open';index"`            
+	Assignee     string `gorm:"index"`                           
+	IgnoreReason string `gorm:"type:text"`                       
+	VerifyTaskID string `gorm:"index"`                           
 	// ...
+	UpdatedAt    time.Time                                       
 }
```

### 4.2 变更流水表 (`AssetChangeLog`)
```go
type AssetChangeLog struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	ProjectID  string `gorm:"index"`
	TaskID     string `gorm:"index"`
	EntityType string `gorm:"index"` 
	EntityID   uint   `gorm:"index"` 
	ChangeType string `gorm:"index"` 
	Details    string `gorm:"type:jsonb"` // 变更详情采用 JSONB，极大方便后续通过 SQL 查询旧值
	CreatedAt  time.Time
}
```
