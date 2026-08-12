package db

import (
	"fmt"

	"gorm.io/gorm"
)

func schemaModels() []interface{} {
	return []interface{}{
		&Project{},
		&ProjectMember{},
		&CronTask{},
		&RootTask{},
		&SubTask{},
		&TaskBatch{},
		&TaskConfigRevision{},
		&TaskAudit{},
		&AssetDiscoveryAudit{},
		&AssetDiscoverySnapshot{},
		&AssetDiscoverySnapshotItem{},
		&AssetDiscoveryNotebookItem{},
		&AssetDiscoveryNotebookSource{},
		&AssetDiscoveryNotebookTag{}, &AssetDiscoveryNotebookItemTag{},
		&AssetDiscoveryNotebookDistributionIntent{},
		&AssetDiscoveryNotebookDistributionIntentItem{},
		&AssetDiscoveryNotebookDistributionMaterialization{},
		&TaskCreationIdempotency{},
		&TaskAppendIdempotency{},
		&TaskRetryIdempotency{},
		&TaskBatchRetryIdempotency{},
		&RiskValidationExecutionIdempotency{},
		&ScanObservation{},
		&ScanCoverage{},
		&ScanWorkClaim{},
		&TaskCoverageLink{},
		&ScanTimingEvent{},
		&NotificationRule{},
		&Domain{},
		&Asset{},
		&Credential{},
		&FingerprintHit{},
		&Vulnerability{},
		&AssetChangeLog{},
		&Report{},
		&Node{},
		&AgentSessionAudit{},
		&WSEventLog{},
		&Arsenal{},
		&ArsenalAIReview{},
		&AIToolInvocation{},
		&User{},
		&CustomRole{},
		&TenantQuota{},
		&SystemConfig{},
		&AgentLog{},
		&AgentLogAlertRule{},
		&AgentLogAlertEvent{},
		&AgentLogArchive{},
		&BuildJob{},
		&RuleCatalogBootstrap{},
		&FingerprintRule{},
		&PocRule{},
		&WorkflowRule{},
		&WorkflowProductSummary{},
		&DirRule{},
		&ExploitRule{},
		&ExploitAudit{},
		&ExploitRiskWaiver{},
		&ExploitRun{},
		&ExploitArtifact{},
		&ExpEgressAudit{},
		&Exp{},
		&ExpRevision{},
		&ExpDependency{},
		&ExpAsset{},
		&ExpAssetRef{},
		&ExpTestCase{},
		&ExpRun{},
		&ExpAudit{},
		&ExpRiskWaiver{},
		&AgentPyenvJob{},
		// 云资源编排
		&CloudAccount{},
		&CloudAccountBinding{},
		&CloudScalingPolicy{},
		&CloudInstance{},
	}
}

func autoMigrateSchema(db *gorm.DB) error {
	return db.AutoMigrate(schemaModels()...)
}

func ensureRuntimeIndexes(db *gorm.DB) error {
	ddls := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_dedupe ON assets (project_id, target, protocol)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_dedupe ON fingerprint_hits (project_id, target, product_name)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_new_dedupe ON vulnerabilities (project_id, target, plugin)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_dedupe ON domains (tenant_id, project_id, name)`,
	}
	for _, ddl := range ddls {
		if err := db.Exec(ddl).Error; err != nil {
			return fmt.Errorf("ensure runtime index failed: %s: %w", ddl, err)
		}
	}
	return nil
}
