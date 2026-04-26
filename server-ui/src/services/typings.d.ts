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
    Name: string;
    Description: string;
    Status: string;
    CreatedAt: string;
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

  /** 融合画像 (GET /api/v1/profiles) */
  interface Profile {
    target: string;
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

  interface DebugPocRequest {
    agent_id: string;
    poc_content: string;
    target_url: string;
    proxy?: string;
    timeout_sec?: number;
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

  interface FingerprintItem {
    product: string;
    rules: string[];
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
  }

  // ======================== User Management ========================

  interface User {
    id: number;
    tenant_id: string;
    username: string;
    role: string;       // admin, operator, viewer
    status: string;     // active, disabled
    created_at: string;
    updated_at: string;
  }

  interface CreateUserRequest {
    username: string;
    password: string;
    role?: string;
    tenant_id?: string;
  }

  interface UpdateUserRequest {
    role?: string;
    status?: string;
    password?: string;
  }

  // ======================== Cloud Resource Scheduling ========================

  interface CloudAccount {
    id: string;
    tenant_id: string;
    name: string;
    provider: string;
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
    recent_events: {
      timestamp: string;
      message: string;
      level: string;
    }[];
  }

  interface CreateCloudAccountRequest {
    name: string;
    provider: string;
    access_key_id: string;
    access_key_secret: string;
    region?: string;
    default_image_id?: string;
    default_instance_type?: string;
    default_security_group?: string;
    default_v_switch?: string;
  }

  interface CreateCloudInstanceRequest {
    account_id: string;
    count: number;
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
    AgentID: string;
    Level: string;
    Message: string;
    Timestamp: number;
    CreatedAt: string;
  }
}
