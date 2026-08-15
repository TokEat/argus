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
    SeedTargets?: string;
    Scope?: string;
    DefaultConfig?: string;
    NodeAffinity?: string;
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
    Status: string;            // Legacy and canonical task states; normalize through utils/taskStatus
    TotalChunks: number;       // 批次总数
    CompletedChunks: number;   // 已完成批次数
    TotalTargets: number;      // 原始目标总数
    CompletedTargets: number;  // 已完成目标数
    Config: string;
    Priority?: number;
    Capacity?: number;
    RunningTasks?: number;
    RuleVersion?: string;
    CurrentConfigVersion?: number;
    CreatedAt: string;
    UpdatedAt: string;
    ArchivedAt?: string | null;
  }

  /** 创建任务请求 (POST /api/v1/tasks) */
  interface CreateTaskRequest {
    project_id: string;
    name?: string;
    targets: string | string[];               // 多行文本或 JSON 数组
    config?: Record<string, unknown> | string; // JSON 对象或 JSON 字符串
    priority?: number;
    timeout_sec?: number;
    agent_selector?: Record<string, string>;
    agent_selector_rules?: AgentSelectorRules;
    skip_unsupported?: boolean;
  }

  interface InvalidTarget {
    target: string;
    reason: string;
  }

  interface ValidateTargetsRequest {
    targets: string | string[];
    config?: Record<string, unknown> | string;
  }

  interface ValidateTargetsResponse {
    valid: string[];
    invalid: InvalidTarget[];
    summary: Record<string, unknown>;
  }

  interface CreateTaskResponse {
    status: string;
    task_id: string;
    replayed: boolean;
    config_version?: number;
    skipped_targets?: InvalidTarget[];
  }

  interface AppendTargetsResponse {
    status: 'appended' | 'unchanged';
    /** True when the Server replayed the first completed append request. */
    replayed: boolean;
    new_subtasks: number;
    new_batches: number;
    new_targets: number;
    duplicate_targets: number;
    config_version: number;
    total_chunks: number;
    total_targets: number;
    project_scope_added?: number;
    project_seeds_added?: number;
    dispatched?: number;
    dispatch_pending?: number;
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
    batch_id?: string;
    attempt_no?: number;
    parent_attempt_id?: string;
    trigger?: string;
    status: string;
    agent_id: string;
    failure_reason?: string;
    target_count: number;
    retry_count: number;
    max_retry: number;
    priority: number;
    timeout_sec: number;
    config_version: number;
    rule_version?: string;
    started_at?: string | null;
    finished_at?: string | null;
    created_at: string;
    updated_at: string;
  }

  interface TaskBatchSummary {
    id: string;
    sequence: number;
    kind: string;
    target_type: string;
    target_count: number;
    status: string;
    display_status: string;
    control_state: 'active' | 'paused' | 'stopping' | 'stopped' | string;
    config_version: number;
    rule_version?: string;
    priority: number;
    timeout_sec: number;
    current_attempt_no: number;
    attempt_count: number;
    latest_attempt_id: string;
    agent_id?: string;
    failure_reason?: string;
    retry_count: number;
    max_retry: number;
    started_at?: string | null;
    finished_at?: string | null;
    created_at: string;
    updated_at: string;
    archived_at?: string | null;
  }

  interface TaskBatchList {
    task_id: string;
    items: TaskBatchSummary[];
  }

  interface TaskBatchMutationResponse extends MessageResponse {
    status: string;
    attempt_id?: string;
    attempt_no?: number;
    dispatch_pending?: number;
    archived_at?: string;
    already_archived?: boolean;
    already_paused?: boolean;
    already_stopped?: boolean;
  }

  interface TaskBatchRetryResponse extends TaskBatchMutationResponse {
    /** True when the Server replayed the first completed batch retry request. */
    replayed: boolean;
  }

  interface TaskCoverageExplanationSource {
    task_id: string;
    task_name: string;
    batch_id: string;
    attempt_id: string;
  }

  interface TaskCoverageExplanationItem {
    link_type: 'executed' | 'reused' | 'in_flight' | string;
    status: string;
    normalized_target: string;
    stage: string;
    network_zone: string;
    source: TaskCoverageExplanationSource;
    reason: string;
    created_at: string;
  }

  interface TaskCoverageInvalidationItem {
    normalized_target: string;
    stage: string;
    status: string;
    reason: string;
    source: TaskCoverageExplanationSource;
    invalidated_at: string;
    valid_until?: string | null;
  }

  interface TaskCoverageExplanation {
    schema_version: 'argus.task-coverage-explanation/v1' | string;
    summary: {
      executed_work_items: number;
      reused_stages: number;
      in_flight_work_items: number;
      invalidated_stages: number;
      expired_stages: number;
      saved_stages: number;
      saved_targets: number;
    };
    items: TaskCoverageExplanationItem[];
    invalidations: TaskCoverageInvalidationItem[];
    items_truncated: boolean;
    invalidations_truncated: boolean;
  }

  interface TaskRetryResponse extends MessageResponse {
    status: string;
    /** True when the Server replayed the first completed retry request. */
    replayed: boolean;
    retried_batches: number;
    completed_skipped: number;
    paused_skipped: number;
    dispatch_pending: number;
  }

  /** 任务详情响应 (GET /api/v1/tasks/:id) */
  interface TaskTimingEvent {
    kind: 'process_startup' | 'rule_prepare' | 'context_init' | 'stage' | string;
    stage?: string;
    outcome: 'success' | 'negative' | 'failed' | 'skipped' | string;
    duration_ns?: number;
    duration_ms?: number;
    started_at?: string;
    finished_at?: string;
  }

  interface TaskTimingAttempt {
    attempt_id: string;
    available: boolean;
    events?: TaskTimingEvent[];
  }

  interface TaskTimingProjection {
    attempts: TaskTimingAttempt[];
    truncated: boolean;
  }

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
      current_config_version: number;
      created_at: string;
      updated_at: string;
      archived_at?: string | null;
    };
    sub_tasks: SubTaskSummary[];
    batches?: TaskBatchSummary[];
    attempts?: SubTaskSummary[];
    status_distribution: Record<string, number>;
    reason_stats: {
      status: string;
      reason: string;
      count: number;
      target_count: number;
    }[];
    coverage_explanation?: TaskCoverageExplanation;
    /** Optional so newer UI remains compatible with servers that do not return timing. */
    timing?: TaskTimingProjection;
    audits: {
      id: number;
      operator_id: string;
      batch_id?: string;
      attempt_id?: string;
      action: 'pause' | 'resume' | 'stop' | 'archive' | 'config_update' | 'batch_append' | string;
      before_status: string;
      after_status: string;
      details: Record<string, unknown>;
      created_at: string;
    }[];
    result_stats: {
      assets: number;
      fingerprints: number;
      vulns: number;
      severity: Record<string, number>;
    };
  }

  interface RiskValidationPreviewAsset {
    target: string;
    url: string;
    protocol: string;
    port: number;
    title: string;
    service: string;
  }

  interface RiskValidationPreviewCandidate {
    asset: RiskValidationPreviewAsset;
    endpoint: string;
    products: string[];
    match_types: string[];
    workflow_sources: string[];
    poc_name: string;
    poc_file: string;
    severity: string;
    execution_class: 'detection' | 'verification';
    risk_level: 'unknown' | 'low' | 'medium' | 'high';
    requires_second_confirmation: boolean;
    poc_content_hash: string;
    template_request_estimate: number;
    estimated_requests: number;
    estimate_basis: 'template_upper_bound' | 'fallback_one_request' | string;
  }

  interface RiskValidationPreviewExcluded {
    product: string;
    poc_name: string;
    reason: 'missing_poc' | 'poc_not_approved' | 'invalid_poc_governance' | 'unsupported_match_type' | string;
    workflow: string;
  }

  interface RiskValidationPreviewResponse {
    task: { id: string; name: string; project_id: string };
    task_rule_version: string;
    rule_version: string;
    config_version: number;
    generated_at: string;
    plan_hash: string;
    summary: {
      fingerprint_hits: number;
      unique_assets: number;
      products: number;
      workflow_rules: number;
      poc_rules: number;
      candidates: number;
      estimated_requests: number;
      second_confirmation_required: boolean;
      second_confirmation_items: number;
      unmatched_products: number;
      excluded_mappings: number;
    };
    items: RiskValidationPreviewCandidate[];
    unmatched_products: string[];
    excluded: RiskValidationPreviewExcluded[];
    page: number;
    page_size: number;
    total: number;
    has_more: boolean;
  }

  interface RiskValidationPreviewRequest {
    specified_pocs?: string[];
  }

  interface RiskValidationSelection {
    endpoint: string;
    poc_file: string;
    poc_content_hash: string;
  }

  interface ExecuteRiskValidationRequest {
    plan_hash: string;
    specified_pocs?: string[];
    selected?: RiskValidationSelection[];
    confirmed: boolean;
    second_confirmation: boolean;
  }

  interface ExecuteRiskValidationResponse extends MessageResponse {
    status: 'scheduled' | string;
    task_id: string;
    batch_id: string;
    attempt_id: string;
    candidate_count: number;
    target_count: number;
    poc_count: number;
    estimated_requests: number;
    config_version: number;
    rule_version: string;
    dispatch_pending: number;
    replayed: boolean;
  }

  interface TaskConfigRevision {
    version: number;
    config: Record<string, unknown>;
    config_hash: string;
    priority: number;
    timeout_sec: number;
    agent_selector: Record<string, string>;
    agent_selector_rules: AgentSelectorRules;
    created_by: string;
    change_note: string;
    created_at: string;
  }

  interface TaskConfigRevisionList {
    task_id: string;
    current_config_version: number;
    items: TaskConfigRevision[];
  }

  interface UpdateTaskConfigRequest {
    config?: Record<string, unknown>;
    priority?: number;
    timeout_sec?: number;
    agent_selector?: Record<string, string>;
    agent_selector_rules?: AgentSelectorRules;
    change_note?: string;
  }

  interface UpdateTaskConfigResponse {
    status: string;
    unchanged: boolean;
    current_config_version: number;
    revision: TaskConfigRevision;
  }

  // ======================== Node ========================

  /** Agent 节点 (GET /api/v1/nodes) */
  interface AgentNode {
    AgentID: string;
    IP: string;
    Status: string;        // Alive, Offline
    EgressOnline?: boolean; // 原生 EXP 出口隧道是否在线
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
	PreviousContent?: string;
    Version: number;  // 自增版本号
    State: string;    // Draft, Approved
    CreatedAt: string;
    UpdatedAt: string;
  }

  interface ActiveFingerprintClassification {
    id: string;
    product: string;
    behavior_kind: 'cookie' | 'header' | 'query';
    declared_profile?: string;
    computed_profile: 'safe' | 'controlled';
    auto_eligible: boolean;
    max_requests: number;
    reasons?: string[];
  }

  interface ActiveFingerprintRule {
    ArtifactID: string;
    SourceFile: string;
    Name: string;
    ProductName: string;
    ContentHash: string;
    Version: number;
    State: string;
    Enabled: boolean;
    DeclaredAutoProfile: string;
    ComputedAutoProfile: 'safe' | 'controlled';
    AutoEligible: boolean;
    MaxRequests: number;
    ClassificationReason: string;
    DownstreamValidations: string[];
    UpdatedAt: string;
  }

  interface ArsenalEvent {
    ID: number;
    ArtifactID: string;
    Type: string;
    FileName: string;
    Version: number;
    Hash: string;
    State: string;
    Action: string;
    ActorID: string;
    Content: string;
    Details: string;
    CreatedAt: string;
  }

  interface BehaviorProbeDebugResponse {
    classification: ActiveFingerprintClassification;
    transcript: {
      status: string;
      logs?: Record<string, unknown>[];
      results?: Record<string, unknown>[];
      complete?: Record<string, unknown>;
      matched_products?: string[];
    };
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
    execution_class: 'detection' | 'verification';
    risk_level: 'unknown' | 'low' | 'medium' | 'high';
    requires_confirmation: boolean;
    requires_second_confirmation: boolean;
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
    spot_duration_hours?: number;
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

  // ======================== Yaksha EXP ========================

  interface Exp {
    id: string;
    name: string;
    product_name?: string;
    parent_exp_id?: string;
    variant_key?: string;
    description: string;
    risk_level: 'low' | 'medium' | 'high' | 'critical';
    status: 'draft' | 'published' | 'deprecated';
    active_revision?: number;
    created_by: string;
    created_at: string;
    updated_at: string;
  }

  interface ExpList { items: Exp[]; total: number; page: number; page_size: number; }
  interface CreateExpRequest { name: string; product_name?: string; parent_exp_id?: string; variant_key?: string; description?: string; risk_level: Exp['risk_level']; }
  interface ExpDependencyRef { exp_id: string; revision: number; source_sha256: string; }
  interface ExpAssetRef { asset_id: string; version: number; sha256: string; }
  interface CreateExpRevisionRequest { source: string; dependencies: ExpDependencyRef[]; assets: ExpAssetRef[]; test_cases: ExpTestCaseInput[]; test_receipt: string; }

  interface ExpControlFlowStep {
    id: string;
    kind: string;
    operation: string;
    label: string;
    expression?: string;
    inputs?: string[];
    outputs?: string[];
    depends_on?: string[];
    line: number;
    column: number;
  }

  interface ExpInspection {
    valid: boolean;
    source_sha256: string;
    parameters: ExpCLIParam[];
    dependencies: Array<{ exp_id: string; revision: number }>;
    asset_refs: Array<{ asset_id: string }>;
    control_flow: ExpControlFlowStep[];
    diagnostics: Array<{ severity: string; code: string; message: string; line: number; column: number }>;
  }

  interface ExpDraftPackage { source: string; dependencies: ExpDependencyRef[]; assets: ExpAssetRef[]; test_cases: ExpTestCaseInput[]; }
  interface ExpDraftTestResult { runtime_response: YakshaResult; test_receipt: string; expires_at: string; }

  interface ExpCLIParam {
    name: string;
    type?: string;
	input_type?: 'host_port' | 'url';
    required?: boolean;
    default?: unknown;
	has_default?: boolean;
    help?: string;
	verbose_name?: string;
	group?: string;
	multiple_select?: boolean;
	options?: Array<{ label: string; value: string }>;
  }

  interface ExpRevision {
    exp_id: string;
    revision: number;
    status: string;
    source_sha256: string;
    source_size: number;
    cli_schema: ExpCLIParam[];
    inspect_summary: Record<string, unknown>;
    validate_summary: Record<string, unknown>;
    test_cases_sha256?: string;
    tests_passed_at?: string;
    published_at?: string;
    created_at: string;
  }

  interface ExpSealedPackage {
    exp_id: string;
    revision: number;
    source_sha256: string;
    script: string;
	dependency_refs: ExpDependencyRef[];
	asset_refs: ExpAssetRef[];
    dependencies: Array<ExpDependencyRef & { script: string }>;
    assets: Array<{ asset_id: string; sha256: string; encoding: string; content: string }>;
  }

  interface ExpAsset {
    asset_id: string;
    version: number;
    sha256: string;
    size: number;
    media_type: string;
    created_at: string;
  }

  interface CreateExpAssetRequest { asset_id: string; media_type?: string; encoding: 'utf8' | 'base64'; content: string; }
  interface ExpTestCase { id: string; exp_id: string; revision: number; name: string; params: Record<string, unknown>; fixture: Record<string, unknown>; expect: Record<string, unknown>; enabled: boolean; }
  interface ExpTestCaseInput { name: string; params: Record<string, unknown>; fixture: Record<string, unknown>; expect: Record<string, unknown>; enabled: boolean; }
  interface ExpEgress { mode: 'disabled' | 'direct' | 'socks5' | 'agent'; socks5_proxy?: string; agent_id?: string; risk_confirmed?: boolean; }
  interface ExpRunRequest { action: 'test' | 'debug' | 'run'; source_sha256: string; params?: Record<string, unknown>; timeout_ms?: number; network_targets?: string[]; egress: ExpEgress; risk_confirmed?: boolean; }
  interface YakshaResult { status?: string; result?: unknown; logs?: unknown[]; evidence?: unknown[]; trace?: unknown; calls?: unknown[]; [key: string]: unknown; }
  interface ExpRun { id: string; exp_id: string; revision: number; action: string; status: string; egress_mode: string; agent_id?: string; result_summary: Record<string, unknown>; artifact_sha256?: string; artifact_expires_at?: string; error_code?: string; created_at: string; }
  interface ExpRunList { items: ExpRun[]; total: number; page: number; page_size: number; }
}
