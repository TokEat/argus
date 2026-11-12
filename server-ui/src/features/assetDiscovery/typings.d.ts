declare namespace API {
  type AssetDiscoveryProvider = 'fofa' | 'hunter' | 'quake';

  interface AssetDiscoveryQueryAsset {
    position?: number;
    target: string;
    ip?: string;
    port: number;
    domain?: string;
    protocol?: string;
    title?: string;
    icp?: string;
    country?: string;
    city?: string;
    company?: string;
    status_code?: number;
    source: string;
    observed_at?: string;
  }

  interface AssetDiscoveryQueryHistoryAsset extends AssetDiscoveryQueryAsset {
    id: number;
  }

  interface AssetDiscoveryQueryPreview {
    schema_version: 'argus.asset-discovery-query-preview/v1' | string;
    project_id: string;
    audit_id: number;
    snapshot_id?: number;
    provider: AssetDiscoveryProvider | string;
    provider_total: number;
    returned_count?: number;
    page?: number;
    page_size?: number;
    has_more?: boolean;
    skipped_rows: number;
    truncated: boolean;
    assets: AssetDiscoveryQueryAsset[];
  }

  interface AssetDiscoveryQuerySummary {
    id: number;
    audit_id: number;
    provider: AssetDiscoveryProvider | string;
    expression: string;
    config_version: number;
    requested_limit: number;
    provider_total: number;
    returned_count: number;
    skipped_rows: number;
    truncated: boolean;
    created_by: string;
    created_at: string;
  }

  interface AssetDiscoveryQueryHistory {
    schema_version: 'argus.asset-discovery-query-history/v1' | string;
    project_id: string;
    items: AssetDiscoveryQuerySummary[];
    total: number;
    page: number;
    page_size: number;
    has_more: boolean;
    generated_at: string;
  }

  interface AssetDiscoveryQueryDetail {
    schema_version: 'argus.asset-discovery-query-history/v1' | string;
    project_id: string;
    query: AssetDiscoveryQuerySummary;
    assets: AssetDiscoveryQueryHistoryAsset[];
    total: number;
    page: number;
    page_size: number;
    has_more: boolean;
    generated_at: string;
  }

  interface AssetDiscoveryNotebookItem {
    id: number;
    project_id?: string;
    project_name?: string;
    target: string;
    source_count: number;
    first_archived_at: string;
    last_archived_at: string;
    created_by: string;
    updated_by?: string;
    tags?: string[];
    note?: string;
    removed_at?: string;
    removed_by?: string;
  }

  interface AssetDiscoveryNotebookList {
    schema_version: 'argus.asset-discovery-notebook/v1' | string;
    project_id: string;
    items: AssetDiscoveryNotebookItem[];
    total: number;
    page: number;
    page_size: number;
    has_more: boolean;
    generated_at: string;
  }

  interface AssetDiscoveryNotebookUpdateRequest {
    tags?: string[];
    note?: string;
  }

  interface AssetDiscoveryArchiveNotebookItemsResult {
    schema_version: 'argus.asset-discovery-notebook/v1' | string;
    project_id: string;
    snapshot_id: number;
    requested_count: number;
    created_count: number;
    linked_source_count: number;
    already_archived_count: number;
    total_count: number;
  }

  interface AssetDiscoveryNotebookDistributionPreview {
    schema_version: 'argus.asset-discovery-notebook-distribution-preview/v1' | string;
    project: { id: string; status: string };
    task: { id: string; name: string; status: string; config_version: number; rule_version?: string };
    counts: { requested: number; selected: number; fresh: number; duplicates: number; project_scope_added: number; project_seed_targets_added: number };
    items: Array<{ item_id: number; target: string; disposition: 'new' | 'duplicate' }>;
    target_summary: { mode: string; total: number; ips: number; ip_ports: number; cidrs: number; ip_ranges: number; domains: number; domain_ports: number; urls: number; search_inputs: number };
    batch_profile: { total_targets: number; total_batches: number; batches_by_type: Record<string, number>; batch_size: Record<string, number> };
    plan_hash: string;
    generated_at: string;
  }

  interface AssetDiscoveryNotebookDistributionMaterializeRequest {
    task_id: string;
    item_ids: number[];
    plan_hash: string;
  }

  interface AssetDiscoveryNotebookDistributionMaterializeResult {
    schema_version: 'argus.asset-discovery-notebook-distribution/v1' | string;
    project_id: string;
    task: { id: string; status: string };
    intent_id: number;
    replayed: boolean;
    outcome: 'materialized' | 'unchanged';
    counts: { requested: number; fresh: number; duplicates: number; project_scope_added: number; project_seed_targets_added: number; batches_created: number; attempts_created: number };
    batch_ids: string[];
    attempt_ids: string[];
    dispatch: { dispatched: number; pending: number };
  }
}
