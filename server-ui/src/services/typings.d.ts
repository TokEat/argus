// ===========================
// 类型定义 — 对齐 Server 端实际数据模型
// ===========================
declare namespace API {

  // ======================== Auth ========================
  interface PaginatedResponse<T> {
    data: T[];
    page: number;
    page_size: number;
    total: number;
  }


  /** 登录请求 (Server: tenant_id + password) */
  interface LoginRequest {
    tenant_id: string;
    password: string;
  }

  /** 登录响应 */
  interface LoginResponse {
    token: string;
  }

  // ======================== Stats ========================

  /** Dashboard 统计数据 (GET /api/v1/stats) */
  interface DashboardStats {
    tasks: number;
    nodes: number;
    assets: number;
    fingerprints: number;
    vulns: number;
  }

  // ======================== Project ========================

  interface Project {
    ID: string;
    TenantID: string;
    OwnerUserID?: string;
    Name: string;
    Description: string;
    Status: string;
    owner_username?: string;
    access_level?: 'admin' | 'owner' | 'operator' | 'viewer' | 'member';
    member_user_ids?: string[];
    members?: ProjectMember[];
    CreatedAt: string;
  }

  interface ProjectMember {
    user_id: string;
    role: 'viewer' | 'operator' | 'owner';
  }

  // ======================== Task ========================

  /** RootTask (GET /api/v1/tasks) */
  interface RootTask {
    ID: string;
    TenantID: string;
    UserID: string;
    Name: string;
    OriginalTargets: string;
    Status: string;            // Queued, Pending, Running, PartialDone, FINISHED, Failed, Timeout, CancelPending, Cancelled
    TotalChunks: number;       // 批次总数
    CompletedChunks: number;   // 已完成批次数
    TotalTargets: number;      // 原始目标总数
    CompletedTargets: number;  // 已完成目标数
    Config: string;
    Priority?: number;
    Capacity?: number;
    RunningTasks?: number;
    RuleVersion?: string;
    CreatedAt: string;
    UpdatedAt: string;
  }

  /** 创建任务请求 (POST /api/v1/tasks) */
  interface CreateTaskRequest {
    project_id: string;
    name: string;
    targets: string | string[];               // 多行文本或 JSON 数组
    config?: Record<string, unknown> | string; // JSON 对象或 JSON 字符串
    priority?: number;
    timeout_sec?: number;
    agent_selector?: Record<string, string>;
    agent_selector_rules?: AgentSelectorRules;
  }

  /** 调度选择器预览 (POST /api/v1/tasks/preview-selector) */
  interface TaskSelectorPreviewRequest {
    project_id: string;
    targets: string | string[];
    config?: Record<string, unknown> | string;
    agent_selector?: Record<string, string>;
    agent_selector_rules?: AgentSelectorRules;
  }

  interface AgentSelectorRules {
    match?: Record<string, string | string[]>;
    not_match?: Record<string, string | string[]>;
  }

  interface TaskSelectorPreview {
    matched_nodes: number;
    available_slots: number;
    reasons: string[];
    effective_selectors: Record<string, string>[];
    groups?: TaskSelectorPreviewGroup[];
    target_summary?: Record<string, unknown>;
  }

  interface TaskSelectorPreviewGroup {
    target_type: string;
    target_count: number;
    batch_count: number;
    selector: Record<string, string>;
    selector_rules?: AgentSelectorRules;
    matched_nodes: number;
    available_slots: number;
    immediate_batches?: number;
    waiting_batches?: number;
    reasons: string[];
    nodes: TaskSelectorPreviewNode[];
  }

  interface TaskSelectorPreviewNode {
    agent_id: string;
    status: string;
    capacity: number;
    running_tasks: number;
    available_slots: number;
    matched: boolean;
    reason?: string;
  }

  /** 子任务摘要 (GET /api/v1/tasks/:id) */
  interface SubTaskSummary {
    id: string;
    status: string;
    agent_id: string;
    target_count: number;
    retry_count: number;
    max_retry: number;
    priority: number;
    timeout_sec: number;
    created_at: string;
    updated_at: string;
  }

  /** 任务详情响应 (GET /api/v1/tasks/:id) */
  interface TaskDetailResponse {
    task: {
      id: string;
      name: string;
      status: string;
      priority: number;
      total_chunks: number;
      completed_chunks: number;
      total_targets: number;
      completed_targets: number;
      timeout_sec: number;
      original_targets: string;
      config: Record<string, unknown> | string;
      rule_version: string;
      created_at: string;
      updated_at: string;
    };
    sub_tasks: SubTaskSummary[];
    status_distribution: Record<string, number>;
    reason_stats: {
      status: string;
      reason: string;
      count: number;
      target_count: number;
    }[];
    result_stats: {
      assets: number;
      fingerprints: number;
      vulns: number;
      severity: Record<string, number>;
    };
  }

  // ======================== Node ========================

  /** Agent 节点 (GET /api/v1/nodes) */
  interface AgentNode {
    AgentID: string;
    IP: string;
    Status: string;        // Alive, Offline
    Token: string;
    TokenExpiresAt?: string;
    TokenRevokedAt?: string;
    LastTokenRotatedAt?: string;
    Tags: string;          // JSON: 节点标签
    Version: string;       // Agent 版本
    Capacity: number;      // 并发容量
    RunningTasks: number;  // 当前运行任务数
    RunningTaskIDs?: string; // JSON array of task IDs (Server GORM field)
    RunningTaskIds?: string; // 兼容历史字段命名
    RunningTaskDetails?: {
      task_id: string;
      targets: string[];
      target_count: number;
      target_preview: string[];
    }[];
    RuleVersion: string;   // 规则版本
    OS?: string;
    Arch?: string;
    CPUUsage?: number;
    MemUsage?: number;
    LastBeat: number;
    CreatedAt: string;
  }

  // ======================== Results ========================

  /** 漏洞 (GET /api/v1/vulns) */
  interface Vulnerability {
    ID: number;
    TenantID: string;
    TaskID: string;
    Target: string;
    Plugin: string;
    Severity: string;
    Payload: string;
    Request: string;
    Response: string;
    Description: string;
    Reference: string;
    MatchedAt: string;
    CreatedAt: string;
  }

  /** 资产 (GET /api/v1/assets) */
  interface Asset {
    ID: number;
    TenantID: string;
    TaskID: string;
    Target: string;
    Protocol: string;
    Port: number;
    URL: string;
    Title: string;
    Service: string;
    CreatedAt: string;
  }

  /** 指纹 (GET /api/v1/fingerprints) */
  interface FingerprintHit {
    ID: number;
    TenantID: string;
    TaskID: string;
    Target: string;
    ProductName: string;
    RuleName: string;
    Evidence: string;
    CreatedAt: string;
  }

  interface FingerprintGroupTarget {
    Target: string;
    RuleName: string;
    Evidence?: string;
    CreatedAt?: string;
    UpdatedAt?: string;
  }

  interface FingerprintGroup {
    ProductName: string;
    TargetCount: number;
    Targets: FingerprintGroupTarget[];
    FirstSeen?: string;
    LastSeen?: string;
  }

  /** 端口信息 */
  interface PortInfo {
    port: number;
    protocol: string;
    service: string;
    title: string;
    url: string;
  }

  /** 融合画像 (GET /api/v1/profiles) — 以主机为单位聚合 */
  interface Profile {
    host: string;
    ports: PortInfo[];
    assets: Asset[];
    fingerprints: FingerprintHit[];
    vulns: Vulnerability[];
  }

  // ======================== Arsenal ========================

  /** 弹药库规则 (GET /api/v1/arsenals/:type) */
  interface Arsenal {
    ID: string;
    TenantID: string;
    Type: string;     // poc, finger, dir, workflow
    FileName: string;
    Content: string;
    Hash: string;
    PreviousHash: string;
    Version: number;  // 自增版本号
    State: string;    // Draft, Approved
    CreatedAt: string;
    UpdatedAt: string;
  }

  interface PagedResponse<T> {
    items: T[];
    total: number;
    page: number;
    page_size: number;
    has_more: boolean;
    rule_version?: string;
    generated_at?: string;
  }

  interface CopilotPendingAction {
    action_type: string;
    title: string;
    summary: string;
    risk_level: 'low' | 'medium' | 'high' | string;
    params: Record<string, unknown>;
    preview?: string;
    required_role?: string;
    confirm_label?: string;
  }

  interface CopilotActionResult {
    status: string;
    message: string;
    action_type: string;
    object?: Record<string, unknown>;
  }

  interface CopilotPromptProfile {
    module: string;
    label: string;
    description: string;
    aliases?: string[];
    max_turns: number;
    tools: string[];
    prompt: string;
    system_prompt: string;
  }

  interface CopilotActionSpec {
    action_type: string;
    risk_level: string;
    required_role: string;
    params: string[];
    description: string;
  }

  interface CopilotPromptRegistry {
    version: number;
    base_prompt: string;
    default: CopilotPromptProfile;
    profiles: CopilotPromptProfile[];
    actions?: CopilotActionSpec[];
    source: string;
    reference: string;
  }

  interface AIToolInvocation {
    id: number;
    user_id: string;
    module: string;
    tool_name: string;
    args_summary: string;
    agent_id?: string;
    target_url?: string;
    duration_ms: number;
    status: string;
    error_summary?: string;
    created_at: string;
  }

  interface AIToolInvocationList {
    total: number;
    items: AIToolInvocation[];
  }

  interface DebugPocRequest {
    agent_id: string;
    poc_content: string;
    target_url: string;
    proxy?: string;
    timeout_sec?: number;
  }

  interface DebugFingerprintRequest {
    agent_id: string;
    target_url: string;
    proxy?: string;
    timeout_sec?: number;
    include_dir?: boolean;
    include_poc?: boolean;
    custom_only?: boolean;
    custom_product?: string;
    custom_rule?: string;
    custom_rules?: string[];
    custom_wf_product?: string;
    custom_wf_types?: string;
    custom_wf_pocs?: string;
    custom_poc_content?: string;
  }

  interface DebugEvent {
    type: 'debug_log' | 'debug_result' | 'debug_complete';
    session_id: string;
    agent_id?: string;
    tenant_id?: string;
    timestamp: number;
    level?: string;
    message?: string;
    matched?: boolean;
    template_id?: string;
    severity?: string;
    matched_at?: string;
    request?: string;
    response?: string;
    extracted?: string[];
    duration_ms?: number;
    error?: string;
  }

  interface AIAnalysisIssue {
    severity: 'info' | 'warning' | 'error' | 'critical' | string;
    category: string;
    message: string;
    line?: number;
    suggestion?: string;
  }

  interface AIDuplicateCandidate {
    file_name: string;
    name: string;
    severity?: string;
    content_hash?: string;
    reason: string;
    score: number;
  }

  interface AIAnalyzeRequest {
    action?: 'review' | 'generate' | 'debug';
    type?: string;
    file_name?: string;
    content: string;
    force?: boolean;
    context?: any;
  }

  interface AIAnalysisResult {
    suggestion: 'Approve' | 'Revise' | 'Reject' | string;
    confidence: number;
    summary: string;
    reason: string;
    issues: AIAnalysisIssue[];
    duplicate_candidates: AIDuplicateCandidate[];
    content_hash: string;
    cached: boolean;
    provider: string;
    model: string;
  }

  interface AIConfig {
    base_url: string;
    api_key?: string;
    model: string;
    has_api_key?: boolean;
    api_key_masked?: string;
  }

  interface AIModelInfo {
    id: string;
    object?: string;
    owned_by?: string;
  }

  // ======================== Dictionary API ========================

  interface WorkflowItem {
    product: string;
    type: string[];
    pocs: string[];
  }

  interface WorkflowSummary extends WorkflowItem {
    poc_count: number;
    missing_pocs: string[];
    missing_poc_count: number;
    fingerprint_bound: boolean;
    fingerprint_rule_count: number;
    is_general_poc: boolean;
    state: string;
    enabled: boolean;
    content_hash: string;
    version: number;
    updated_at: string;
  }

  interface WorkflowStats {
    total: number;
    fp_missing: number;
    poc_missing: number;
    total_pocs: number;
    fingerprint_rules: number;
  }

  interface WorkflowSummaryPage extends PagedResponse<WorkflowSummary> {
    stats?: WorkflowStats;
  }

  interface FingerprintItem {
    product: string;
    rules: string[];
  }

  interface FingerprintSummary {
    product: string;
    rules?: string[];
    rule_count: number;
    state: string;
    enabled: boolean;
    version: number;
    updated_at: string;
  }

  interface DirItem {
    product: string;
    paths: string[];
  }

  interface ApiKeyEntry {
    provider: string;
    keys: string[];
  }

  // ======================== Agent Commands ========================

  /** Agent 轮询命令 (GET /api/v1/agents/:id/commands) */
  interface AgentCommands {
    cancel_tasks: string[];
    reload_rules: boolean;
  }

  // ======================== Common ========================

  /** 通用消息响应 */
  interface MessageResponse {
    message?: string;
    status?: string;
    error?: string;
    job_id?: number;
  }

  // ======================== User Management ========================

  interface User {
    id: number;
    tenant_id: string;
    username: string;
    role: string;       // admin, operator, viewer
    status: string;     // active, disabled
    exp_authorized: boolean;
    created_at: string;
    updated_at: string;
  }

  interface CreateUserRequest {
    username: string;
    password: string;
    role?: string;
    tenant_id?: string;
    exp_authorized?: boolean;
  }

  interface UpdateUserRequest {
    role?: string;
    status?: string;
    password?: string;
    exp_authorized?: boolean;
  }

  interface RoleDefinition {
    id?: number;
    name: string;
    label: string;
    description: string;
    base_role: 'viewer' | 'operator' | 'admin' | string;
    permissions: string[];
    builtin: boolean;
    created_at?: string;
    updated_at?: string;
  }

  interface RoleListResponse {
    roles: RoleDefinition[];
    matrix: Record<string, string[]>;
    base_roles: string[];
  }

  interface RoleRequest {
    name?: string;
    label?: string;
    description?: string;
    base_role: 'viewer' | 'operator' | 'admin' | string;
    permissions?: string[];
  }

  interface TenantQuotaUsage {
    active_tasks: number;
    running_subtasks: number;
    tasks_today: number;
  }

  interface TenantQuota {
    tenant_id: string;
    max_concurrent_tasks: number;
    max_running_sub_tasks: number;
    daily_task_limit: number;
    usage: TenantQuotaUsage;
    created_at?: string;
    updated_at?: string;
  }

  interface TenantQuotaRequest {
    max_concurrent_tasks: number;
    max_running_sub_tasks: number;
    daily_task_limit: number;
  }

  interface PocRuleMetadata {
    id: number;
    tenant_id: string;
    artifact_id: string;
    source_file: string;
    name: string;
    target_product: string;
    cve: string;
    compatibility_status: string;
    source_version: string;
    content_hash: string;
    severity: string;
    tags: string;
    author: string;
    description: string;
    version: number;
    state: string;
    enabled: boolean;
    created_at: string;
    updated_at: string;
  }

  // ======================== Cloud Resource Scheduling ========================

  interface CloudAccount {
    id: string;
    tenant_id: string;
    owner_user_id?: string;
    owner_username?: string;
    access_level?: 'admin' | 'owner' | 'bound' | string;
    bound_user_ids?: string[];
    name: string;
    provider: string;
    access_key_id?: string;
    region?: string;
    default_image_id?: string;
    default_instance_type?: string;
    default_security_group?: string;
    default_v_switch?: string;
    oss_bucket?: string;
    oss_endpoint?: string;
    status: string;
    created_at: string;
    updated_at: string;
  }

  interface CloudScalingPolicy {
    id: string;
    tenant_id: string;
    cloud_account_id: string;
    name: string;
    enabled: boolean;
    min_instances: number;
    max_instances: number;
    scale_up_threshold: number;
    scale_down_threshold: number;
    cooldown_seconds: number;
    instance_ttl_minutes: number;
    spot_strategy: string;
    max_spot_price: number;
    user_data_template: string;
    last_scale_action?: string;
    created_at: string;
    updated_at: string;
  }

  interface CloudInstance {
    id: string;
    tenant_id: string;
    cloud_account_id: string;
    policy_id: string;
    provider_instance_id: string;
    agent_id: string;
    ip: string;
    region: string;
    status: string;
    spot: boolean;
    reboot_count: number;
    error_message?: string;
    launched_at?: string;
    ready_at?: string;
    terminated_at?: string;
    created_at: string;
    updated_at: string;
  }

  interface CloudDashboard {
    active_accounts: number;
    enabled_policies: number;
    running_instances: number;
    total_instances: number;
    recent_events: CloudInstance[];
  }

  interface CreateCloudAccountRequest {
    name: string;
    provider: string;
    access_key_id: string;
    access_key_secret: string;
    bound_user_ids?: string[];
    region?: string;
    default_image_id?: string;
    default_instance_type?: string;
    default_security_group?: string;
    default_v_switch?: string;
    oss_bucket?: string;
    oss_endpoint?: string;
  }

  interface CloudAccountBindingsResponse {
    cloud_account_id: string;
    owner_user_id: string;
    user_ids: string[];
    bindings: {
      id: number;
      tenant_id: string;
      cloud_account_id: string;
      user_id: string;
      access_type: string;
      created_at: string;
      updated_at: string;
    }[];
  }

  interface RegionInfo {
    region_id: string;
    local_name: string;
    endpoint: string;
  }

  interface ReleaseFileInfo {
    name: string;
    size: number;
    modified: string;
  }

  interface OSSFileInfo {
    key: string;
    size: number;
    last_modified: string;
  }

  interface CreateCloudInstanceRequest {
    account_id: string;
    count: number;
    instance_type?: string;
    region?: string;
  }

  // ======================== Build Artifacts ========================

  interface BuildArtifact {
    name: string;
    size: number;
    platform: string;
    arch: string;
    mod_time: string;
  }

  interface BuildRequest {
    platform: string;
    arch: string;
    pack?: boolean;
    components?: string[];
  }

  interface BuildJob {
    id: number;
    platform: string;
    arch: string;
    pack: boolean;
    components?: string[];
    status: 'queued' | 'running' | 'success' | 'failed' | 'canceled';
    artifact?: string;
    artifacts?: string[];
    log_tail?: string;
    error?: string;
    started_at?: string;
    finished_at?: string;
    created_at: string;
    updated_at: string;
  }

  // ======================== MCP Keys ========================

  interface McpKey {
    id: string;
    provider: string;
    key: string;
    status: string;
  }

  // ======================== Arsenal Manifest ========================

  interface ManifestItem {
    type: string;
    file_name: string;
    hash: string;
    updated_at: string;
  }

  interface ArsenalManifest {
    rule_version: string;
    items: ManifestItem[];
  }

  // ======================== 数据增强统计 ========================

  interface TrendPoint {
    date: string;
    count: number;
  }

  interface SeverityCount {
    severity: string;
    count: number;
  }

  interface TaskStats {
    task_id: string;
    task_name: string;
    asset_count: number;
    fp_count: number;
    vuln_count: number;
  }

  // ======================== Agent 日志 ========================

  interface AgentLog {
    ID: number;
    TenantID?: string;
    AgentID: string;
    Level: string;
    Message: string;
    Timestamp: number;
    CreatedAt: string;
  }

  interface AgentLogSummary {
    agents?: string[];
    level_counts: {
      level: string;
      count: number;
    }[];
    recent_errors: AgentLog[];
    retention_days: number;
  }

  interface AgentLogRetention {
    retention_days: number;
    deleted?: number;
  }

  interface AgentLogAlertRule {
    id: number;
    tenant_id: string;
    name: string;
    agent_id?: string;
    level?: string;
    keyword?: string;
    enabled: boolean;
    created_at: string;
    updated_at: string;
  }

  interface AgentLogAlertEvent {
    id: number;
    tenant_id: string;
    rule_id: number;
    agent_id: string;
    level: string;
    message: string;
    log_id: number;
    created_at: string;
  }

  interface AgentLogArchive {
    id: number;
    tenant_id: string;
    day: string;
    storage_key: string;
    log_count: number;
    status: string;
    error?: string;
    created_at: string;
  }

  // ======================== EXP 规则 ========================

  interface DryRunResponse {
    exploit_id: string;
    target: string;
    risk_level: string;
    requires_auth: boolean;
    side_effects: string[];
    cleanup_supported: boolean;
    cleanup_required: boolean;
    timeout_sec: number;
    capabilities: string[];
    execution_plan: {
      mode: string;
      engine?: string;
      entry?: string;
      script_preview?: string;
      cleanup_preview?: string;
      steps?: unknown[];
      cleanup?: unknown[];
      requirements?: string[];
      requirements_hash?: string;
      sandbox_profile?: string;
    };
    params_valid: boolean;
    params_errors: string[];
    normalized_params?: Record<string, unknown>;
  }

  interface ExploitDebugRequest {
    agent_id: string;
    target_url: string;
    params?: Record<string, unknown>;
    proxy?: string;
    timeout_sec?: number;
    action?: 'run' | 'cleanup';
  }

  interface ExploitDebugPayload {
    run_id?: string;
    status: string;
    evidence?: Record<string, unknown>;
    side_effects?: string[];
    duration_ms?: number;
    error_message?: string;
  }

  interface SourceExploitValidateResponse {
    valid: boolean;
    error?: string;
    id?: string;
    rule_id?: string;
    name?: string;
    description?: string;
    target_product?: string;
    cve?: string;
    linked_pocs?: string[];
    risk_level?: string;
    params_schema?: Record<string, unknown>;
    requirements?: string[];
    requirements_hash?: string;
    has_run?: boolean;
    has_main?: boolean;
    has_cleanup?: boolean;
    policy?: Record<string, unknown>;
  }

  interface SourceExploitDebugRequest extends ExploitDebugRequest {
    source: string;
    action?: 'run';
  }

  interface SourceExploitDebugResponse {
    status: string;
    matched?: boolean;
    error?: string;
    execution_result?: ExploitDebugPayload;
    logs?: Record<string, unknown>[];
    result?: Record<string, unknown>;
    complete?: Record<string, unknown>;
  }

  interface ExploitRun {
    id: number;
    tenant_id: string;
    project_id: string;
    asset_id: string;
    target: string;
    exploit_id: string;
    operator_id: string;
    agent_id: string;
    risk_level: string;
    status: 'Pending' | 'Running' | 'CancelPending' | 'Cancelled' | 'CleanupRequired' | 'CleanupFailed' | 'Succeeded' | 'Failed';
    credential_ref: string;
    started_at: string;
    finished_at: string;
    evidence: string;
    side_effects: string;
    cleanup_status: '' | 'Pending' | 'CleanupRunning' | 'CleanupSucceeded' | 'CleanupFailed' | 'NotRequired';
    cleanup_evidence: string;
    error_message: string;
    created_at: string;
    updated_at: string;
  }

  interface ExploitRiskWaiver {
    id: number;
    tenant_id: string;
    rule_id: string;
    reason: string;
    created_by: string;
    expires_at: string;
    active: boolean;
    created_at: string;
    updated_at: string;
  }

  interface ExploitRule {
    id: number;
    tenant_id: string;
    artifact_id: string;
    source_file: string;
    rule_id: string;
    name: string;
    description: string;
    target_product: string;
    cve: string;
    risk_level: string;
    requires_auth: boolean;
    side_effects: string[];
    cleanup_supported: boolean;
    cleanup_required: boolean;
    dry_run_supported: boolean;
    capabilities: string[];
    linked_pocs: string[];
    params_schema: Record<string, unknown>;
    requirements: string[];
    requirements_hash: string;
    sandbox_profile: string;
    timeout_sec: number;
    runtime_engine: string;
    content_hash: string;
    version: number;
    state: string;
    enabled: boolean;
    risk_waiver?: ExploitRiskWaiver;
    created_at: string;
    updated_at: string;
  }

  interface AgentPyenvJob {
    id: string;
    tenant_id: string;
    agent_id: string;
    operator_id: string;
    exploit_rule_id: number;
    requirements: string[];
    requirements_hash: string;
    status: string;
    logs: string;
    error: string;
    started_at?: string;
    finished_at?: string;
    created_at: string;
    updated_at: string;
  }

  interface AgentPyenv {
    agent_id: string;
    status: string;
    python_path: string;
    python_version: string;
    pip_available: boolean;
    install_available: boolean;
    last_job?: AgentPyenvJob;
    tags: Record<string, string>;
  }

  interface AgentPyenvNoopResponse {
    status: 'no_op';
    message: string;
    agent_id: string;
    exploit_rule_id: number;
  }

  interface ExploitBatchReviewResult {
    id: number;
    status: string;
    error?: string;
  }

  interface ExploitBatchReviewResponse {
    status: string;
    changed: number;
    results: ExploitBatchReviewResult[];
  }

  interface ExploitAudit {
    id: number;
    tenant_id: string;
    exploit_rule_id: number;
    rule_id: string;
    action: string;
    reason: string;
    operator_id: string;
    metadata: string;
    created_at: string;
  }
}
