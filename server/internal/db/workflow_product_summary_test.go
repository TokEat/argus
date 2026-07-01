package db

import (
	"testing"

	"gorm.io/gorm"
)

func TestRefreshWorkflowProductSummariesMarksGeneralPoc(t *testing.T) {
	store := setupRuleCatalogSyncTestDB(t)
	workflows := []WorkflowRule{
		{
			TenantID:    "default",
			ProductName: "General-Poc-TongWeb",
			PocName:     "tongweb-probe",
			MatchType:   "root",
			State:       "Approved",
			Enabled:     true,
			Version:     2,
		},
		{
			TenantID:    "default",
			ProductName: "SpecificProduct",
			PocName:     "specific-poc",
			MatchType:   "root",
			State:       "Approved",
			Enabled:     true,
			Version:     2,
		},
	}
	pocs := []PocRule{
		{TenantID: "default", SourceFile: "tongweb-probe.yaml", Name: "tongweb-probe", State: "Approved", Enabled: true},
		{TenantID: "default", SourceFile: "specific-poc.yaml", Name: "specific-poc", State: "Approved", Enabled: true},
	}

	if err := store.Transaction(func(tx *gorm.DB) error {
		return refreshWorkflowProductSummaries(tx, nil, workflows, pocs)
	}); err != nil {
		t.Fatalf("refresh summaries: %v", err)
	}

	var general WorkflowProductSummary
	if err := store.Where("tenant_id = ? AND product_name = ?", "default", "General-Poc-TongWeb").First(&general).Error; err != nil {
		t.Fatalf("find general summary: %v", err)
	}
	if !general.IsGeneralPoc || general.FingerprintBound || general.MissingPocCount != 0 {
		t.Fatalf("unexpected general summary: %+v", general)
	}

	var specific WorkflowProductSummary
	if err := store.Where("tenant_id = ? AND product_name = ?", "default", "SpecificProduct").First(&specific).Error; err != nil {
		t.Fatalf("find specific summary: %v", err)
	}
	if specific.IsGeneralPoc || specific.FingerprintBound || specific.MissingPocCount != 0 {
		t.Fatalf("unexpected specific summary: %+v", specific)
	}
}
