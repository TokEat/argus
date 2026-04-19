// ===========================
// 类型定义 — 对齐 Server 端实际数据模型
// ===========================
declare namespace API {

  // ======================== Auth ========================

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

  // ======================== Task ========================

  /** RootTask (GET /api/v1/tasks) */
  interface RootTask {
    ID: string;
    TenantID: string;
    UserID: string;
    Name: string;
    OriginalTargets: string;
    Status: string;            // Pending, Running, FINISHED, Cancelled
    TotalChunks: number;
    CompletedChunks: number;
    Config: string;
    Priority: number;
    TimeoutSec: number;
    RuleVersion: string;
    CreatedAt: string;
    UpdatedAt: string;
  }

  /** 创建任务请求 (POST /api/v1/tasks) */
  interface CreateTaskRequest {
    name: string;
    targets: string;       // 多行文本或 JSON 数组
    config?: string;       // JSON 字符串
  }

  // ======================== Node ========================

  /** Agent 节点 (GET /api/v1/nodes) */
  interface AgentNode {
    AgentID: string;
    IP: string;
    Status: string;    // Alive, Offline
    Token: string;
    Tags: string;
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
    State: string;    // Draft, Approved
    CreatedAt: string;
    UpdatedAt: string;
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

  // ======================== Cloud Instance ========================

  interface CloudInstance {
    id: string;
    ip: string;
    status: string;
    provider: string;
    created_at: string;
  }

  interface CreateInstanceRequest {
    provider: string;
    region?: string;
    instance_type?: string;
    image_id?: string;
    server_addr?: string;
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
}
