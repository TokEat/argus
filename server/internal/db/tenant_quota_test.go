package db

import "testing"

func TestTenantQuotaTableName(t *testing.T) {
	if got := (TenantQuota{}).TableName(); got != "tenant_quotas" {
		t.Fatalf("TenantQuota table name = %q, want tenant_quotas", got)
	}
}
