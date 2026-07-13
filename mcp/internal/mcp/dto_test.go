package mcp

import (
	"encoding/json"
	"testing"
)

func TestArsenalRecordAcceptsCurrentAndLegacyFields(t *testing.T) {
	var rows []arsenalRecord
	if err := json.Unmarshal([]byte(`[
		{"id":"poc-a","file_name":"a.yaml","hash":"ha","version":2,"state":"Draft","content":"id: a"},
		{"ID":"poc-b","FileName":"b.yaml","Hash":"hb","Version":3,"State":"Approved","Content":"id: b"}
	]`), &rows); err != nil {
		t.Fatalf("decode arsenal rows: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != "poc-a" || rows[1].ID != "poc-b" || rows[1].FileName != "b.yaml" {
		t.Fatalf("unexpected arsenal rows: %#v", rows)
	}
	if rows[0].VersionInt() != 2 || rows[1].VersionInt() != 3 {
		t.Fatalf("unexpected versions: %#v", rows)
	}
}

func TestCatalogRecordAcceptsRelationshipAliasesAndMissingFields(t *testing.T) {
	var rows []catalogRecord
	if err := json.Unmarshal([]byte(`[
		{"product":"Current","type":["root"],"pocs":["current.yaml"]},
		{"ProductName":"Legacy","WorkflowTypes":["base"],"WorkflowPOCs":["legacy.yaml"]},
		{}
	]`), &rows); err != nil {
		t.Fatalf("decode catalog rows: %v", err)
	}
	products, refs := workflowProductSetAndRefs(rows)
	if products["Current"] != "Current" || products["Legacy"] != "Legacy" {
		t.Fatalf("unexpected products: %#v", products)
	}
	if len(refs) != 2 || refs[0].POCName != "current.yaml" || refs[1].POCName != "legacy.yaml" {
		t.Fatalf("unexpected refs: %#v", refs)
	}
}

func TestCatalogRecordPreservesRawOutputFields(t *testing.T) {
	var record catalogRecord
	if err := json.Unmarshal([]byte(`{"rule_id":"exp-a","LinkedPOCs":["linked.yaml"],"custom_field":"keep-me"}`), &record); err != nil {
		t.Fatalf("decode catalog row: %v", err)
	}
	if record.RuleID != "exp-a" || len(stringSliceFromAny(record.LinkedPOCs)) != 1 || record.Raw["custom_field"] != "keep-me" {
		t.Fatalf("typed fields or raw payload lost: %#v", record)
	}
}

func TestArsenalEffectiveFileNameFallsBackToSourceFile(t *testing.T) {
	var record arsenalRecord
	if err := json.Unmarshal([]byte(`{"ID":"poc-source","SourceFile":"source-only.yaml"}`), &record); err != nil {
		t.Fatalf("decode source-only arsenal row: %v", err)
	}
	if record.EffectiveFileName() != "source-only.yaml" {
		t.Fatalf("effective file name = %q", record.EffectiveFileName())
	}
}

func TestCatalogFileNameFallbackReachesProductSearchOutput(t *testing.T) {
	var record catalogRecord
	if err := json.Unmarshal([]byte(`{"FileName":"file-only.yaml"}`), &record); err != nil {
		t.Fatalf("decode file-only catalog row: %v", err)
	}
	item := productSearchPOCItem(record)
	if item["source_file"] != "file-only.yaml" || item["name"] != "file-only.yaml" {
		t.Fatalf("product search fallback missing: %#v", item)
	}
	expItem := productSearchEXPItem(record)
	if expItem["source_file"] != "file-only.yaml" || expItem["name"] != "file-only.yaml" {
		t.Fatalf("EXP search fallback missing: %#v", expItem)
	}
}

func TestRelationshipSortingIsStableAndMissingSearchFieldsAreSafe(t *testing.T) {
	items := []map[string]interface{}{
		{"product_name": "same", "marker": "first"},
		{"product_name": "same", "marker": "second"},
	}
	sortRelationshipItems(items)
	if items[0]["marker"] != "first" || items[1]["marker"] != "second" {
		t.Fatalf("equal relationship keys lost stable order: %#v", items)
	}
	if score, reasons := scoreProductSearchBucket("spring", &productSearchBucket{}); score != 0 || reasons != nil {
		t.Fatalf("empty product bucket should not match: score=%v reasons=%v", score, reasons)
	}
}
