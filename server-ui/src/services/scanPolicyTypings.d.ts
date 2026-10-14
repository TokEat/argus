declare namespace API {
  type ScanPreset = 'quick' | 'standard' | 'deep' | 'custom';
  type ScanPortProfile = 'common-100' | 'top-1000' | 'all' | 'custom';
  type ScanMethod = 'tcp' | 'syn';
  type ScanIntensity = 'low' | 'balanced' | 'high';

  interface ScanDictionaryRef { id: string; revision: number; sha256: string; count: number; }
  interface ScanPolicy {
    schema_version: 'argus.scan-policy/v1'; preset: ScanPreset; port_profile: ScanPortProfile;
    custom_ports?: string; scan_method: ScanMethod; intensity: ScanIntensity;
    capabilities: {
      subdomain_discovery: boolean; subdomain_bruteforce: boolean; allow_cdn_assets: boolean;
      allow_private_resolved_domains: boolean; host_binding: boolean; behavior_probe: boolean; directory_probe: boolean;
      risk_validation: boolean; credential_validation: boolean;
      web_crawl: boolean; sensitive_info: boolean;
    };
    selector?: { match?: Record<string, string[]>; not_match?: Record<string, string[]> };
	 subdomains: { wordlists?: ScanDictionaryRef[]; bruteforce_depth: number };
    credentials: { username_books?: ScanDictionaryRef[]; password_books?: ScanDictionaryRef[]; pair_limit: number };
    authorization: { validation_confirmed: boolean };
    web_crawl?: { max_depth?: number; max_pages?: number; path_app_limit?: number };
    ai_control?: { crawl?: boolean; sensitive_info?: boolean };
  }
  interface ScanPlanStage {
    id: string; depends_on?: string[]; enabled: boolean; targets?: number; reason?: string;
    matched_agents?: number; available_slots?: number; agent_reasons?: string[];
  }
  interface ScanPlanPreviewRequest {
    project_id: string; targets: string | string[]; policy: ScanPolicy; priority?: number;
    timeout_sec?: number; skip_unsupported?: boolean;
  }
  interface ScanPlanPreview {
    policy: ScanPolicy; policy_hash: string; plan_hash: string; rule_version: string; port_count: number;
    target_summary: Record<string, number>; stages: ScanPlanStage[]; matched_agents: number;
    available_slots: number; agent_reasons?: string[]; estimated_requests: number;
    custom_credential_pairs: number; credential_pair_limit: number; custom_subdomain_words: number;
    validation_budget: { target_concurrency: number; rate_limit: number; credential_max_per_target: number; risk_budget_basis: string };
    skipped_targets?: InvalidTarget[];
  }
  interface CredentialDictionary {
    id: string; project_id: string; name: string; kind: 'username' | 'password'; revision: number;
    sha256: string; count: number; created_at: string;
  }
	interface SubdomainDictionary {
		id: string; project_id: string; name: string; revision: number;
		sha256: string; count: number; created_at: string;
	}
  interface CredentialFinding {
    id: string; endpoint: string; service: string; plugin: string; masked_username: string; created_at: string;
  }
  interface RevealedCredentialFinding { username: string; password: string; evidence?: unknown; }

  interface CreateTaskRequest { policy?: ScanPolicy; plan_hash?: string; }
  interface CreateTaskResponse { policy_hash?: string; plan_hash?: string; stages?: ScanPlanStage[]; }
  interface TaskDetailResponse {
    scan_policy?: {
      schema_version: string; policy: ScanPolicy; policy_hash: string; plan_hash: string;
      risk_status: string; credential_status: string; authorized_at: string;
    } | null;
    stage_derivations?: {
      ID?: number; Stage?: string; Status?: string; BatchID?: string; AttemptID?: string; ItemCount?: number; Summary?: string;
      stage?: string; status?: string; batch_id?: string; attempt_id?: string; item_count?: number; summary?: string;
    }[];
  }
}
