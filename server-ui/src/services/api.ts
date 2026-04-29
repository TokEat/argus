import axios from 'axios';
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

// 创建 axios 实例 — 对齐 Server 端路由前缀 /api/v1
const request: AxiosInstance = axios.create({
    baseURL: '/api/v1',
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// 请求拦截器
request.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        (config as AxiosRequestConfig & { __authTokenSnapshot?: string }).__authTokenSnapshot = token || '';
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// 响应拦截器
request.interceptors.response.use(
    (response: AxiosResponse) => {
        return response.data;
    },
    (error) => {
        if (error.response?.status === 401) {
            // 防止竞态：
            // 某些旧请求（例如登录前发出的请求）晚到 401，不应清掉新登录后的 token。
            const currentToken = localStorage.getItem('token') || '';
            const snapshotToken = ((error.config as AxiosRequestConfig & { __authTokenSnapshot?: string })?.__authTokenSnapshot || '') as string;
            const isStale401 = snapshotToken !== '' && currentToken !== '' && snapshotToken !== currentToken;

            if (!isStale401 && !window.location.pathname.includes('/login')) {
                localStorage.removeItem('token');
                window.location.href = '/login';
            }
        }
        const data = error.response?.data;
        const msg = typeof data === 'string' ? data.trim() : data?.error || data?.message || error.message;
        return Promise.reject(msg);
    }
);

// ===========================
// Auth API
// ===========================

export async function login(data: API.LoginRequest): Promise<API.LoginResponse> {
    return request.post('/auth/login', data);
}

// ===========================
// Dashboard API
// ===========================

export async function getDashboardStats(): Promise<API.DashboardStats> {
    return request.get('/stats');
}

// ===========================
// Project API
// ===========================

export async function listProjects(): Promise<API.Project[]> {
    return request.get('/projects');
}

export async function createProject(data: { name: string; description?: string }): Promise<API.Project> {
    return request.post('/projects', data);
}

// ===========================
// Task API
// ===========================

export async function listTasks(projectId?: string): Promise<API.RootTask[]> {
    return request.get('/tasks', { params: projectId ? { project_id: projectId } : {} });
}

export async function createTask(data: API.CreateTaskRequest): Promise<{ status: string; task_id: string }> {
    return request.post('/tasks', data);
}

export async function deleteTask(taskId: string): Promise<API.MessageResponse> {
    return request.delete(`/tasks/${taskId}`);
}

export async function cancelTask(taskId: string): Promise<API.MessageResponse> {
    return request.post(`/tasks/${taskId}/cancel`);
}

export async function getTaskDetail(taskId: string): Promise<API.TaskDetailResponse> {
    return request.get(`/tasks/${taskId}`);
}

export async function appendTargets(taskId: string, targets: string): Promise<{ status: string; new_subtasks: number; new_targets: number; total_chunks: number }> {
    return request.post(`/tasks/${taskId}/append`, { targets });
}

export async function getQueueDepth(): Promise<{
    depth: Record<string, number>;
    pending: Record<string, number>;
    mode: string;
    ready_batches: number;
    pending_batches: number;
    ready_targets: number;
    pending_targets: number;
}> {
    return request.get('/queue/depth');
}

// ===========================
// Results API
// ===========================

export async function getVulns(taskId?: string): Promise<API.Vulnerability[]> {
    return request.get('/vulns', { params: taskId ? { task_id: taskId } : {} });
}

export async function getAssets(taskId?: string): Promise<API.Asset[]> {
    return request.get('/assets', { params: taskId ? { task_id: taskId } : {} });
}

export async function getFingerprints(taskId?: string): Promise<API.FingerprintHit[]> {
    return request.get('/fingerprints', { params: taskId ? { task_id: taskId } : {} });
}

export async function getProfiles(page: number = 1, pageSize: number = 50, search: string = ''): Promise<API.PaginatedResponse<API.Profile>> {
    return request.get('/profiles', { params: { page, page_size: pageSize, search } });
}

export async function exportVulns(): Promise<Blob> {
    const response = await axios.get('/api/v1/reports/export/vulns', {
        responseType: 'blob',
        headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
    });
    return response.data;
}

// ===========================
// Node API
// ===========================

export async function getNodes(): Promise<API.AgentNode[]> {
    return request.get('/nodes');
}

export async function deleteNode(agentId: string): Promise<API.MessageResponse> {
    return request.delete(`/nodes/${encodeURIComponent(agentId)}`);
}

export async function cleanOfflineNodes(): Promise<{ status: string; count: number }> {
    return request.post('/nodes/clean');
}

export async function getAgentCommands(agentId: string): Promise<API.AgentCommands> {
    return request.get(`/agents/${agentId}/commands`);
}

// ===========================
// Arsenal API (POC / Finger / Dir / Workflow)
// ===========================

export async function listArsenals(type: string, all: boolean = true, lite: boolean = false): Promise<API.Arsenal[]> {
    const params: Record<string, string> = {};
    if (all) params.all = '1';
    if (lite) params.lite = '1';
    return request.get(`/arsenals/${type}`, { params });
}

export async function saveArsenal(type: string, filename: string, content: string): Promise<{ status: string; hash: string; state: string }> {
    return request.post(`/arsenals/${type}/${filename}`, { content });
}

export async function approveArsenal(type: string, filename: string): Promise<API.MessageResponse> {
    return request.post(`/arsenals/${type}/${filename}/approve`);
}

export async function deleteArsenal(type: string, filename: string): Promise<API.MessageResponse> {
    return request.delete(`/arsenals/${type}/${filename}`);
}

export async function aiAnalyzeArsenal(data: API.AIAnalyzeRequest | string): Promise<API.AIAnalysisResult> {
    const payload: API.AIAnalyzeRequest = typeof data === 'string' ? { type: 'poc', content: data } : data;
    return request.post('/ai/arsenal/analyze', payload, { timeout: 90000 });
}

/** SSE streaming version of AI analysis — real-time token output */
export function aiAnalyzeArsenalStream(
    data: API.AIAnalyzeRequest | string,
    callbacks: {
        onStatus?: (phase: string, message: string) => void;
        onToken?: (content: string) => void;
        onToolStart?: (toolName: string, args: string) => void;
        onToolEnd?: (toolName: string, result: string) => void;
        onResult?: (result: API.AIAnalysisResult) => void;
        onError?: (message: string) => void;
    },
): { abort: () => void } {
    const payload: API.AIAnalyzeRequest = typeof data === 'string' ? { type: 'poc', content: data } : data;
    const controller = new AbortController();
    const token = localStorage.getItem('token');

    (async () => {
        try {
            const resp = await fetch('/api/v1/ai/arsenal/analyze/stream', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
                body: JSON.stringify(payload),
                signal: controller.signal,
            });

            if (!resp.ok || !resp.body) {
                const text = await resp.text();
                callbacks.onError?.(text || `HTTP ${resp.status}`);
                return;
            }

            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            let currentEvent = '';
            let finishedNormally = false;

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (const line of lines) {
                    if (line.startsWith('event: ')) {
                        currentEvent = line.slice(7).trim();
                    } else if (line.startsWith('data: ') && currentEvent) {
                        const jsonStr = line.slice(6);
                        try {
                            const data = JSON.parse(jsonStr);
                            switch (currentEvent) {
                                case 'status':
                                    callbacks.onStatus?.(data.phase, data.message);
                                    break;
                                case 'token':
                                    callbacks.onToken?.(data.content);
                                    break;
                                case 'tool_start':
                                    callbacks.onToolStart?.(data.name, data.args);
                                    break;
                                case 'tool_end':
                                    callbacks.onToolEnd?.(data.name, data.result);
                                    break;
                                case 'result':
                                    finishedNormally = true;
                                    callbacks.onResult?.(data);
                                    break;
                                case 'error':
                                    finishedNormally = true;
                                    callbacks.onError?.(data.message);
                                    break;
                            }
                        } catch (e) {
                            console.error('Failed to parse SSE data:', jsonStr, e);
                        }
                        currentEvent = '';
                    }
                }
            }

            if (!finishedNormally) {
                callbacks.onError?.('流式传输意外断开');
            }
        } catch (err: unknown) {
            if ((err as Error)?.name !== 'AbortError') {
                callbacks.onError?.(err instanceof Error ? err.message : 'Stream failed');
            }
        }
    })();

    return { abort: () => controller.abort() };
}

export async function getAIConfig(): Promise<API.AIConfig> {
    return request.get('/ai/config');
}

export async function saveAIConfig(data: API.AIConfig): Promise<API.AIConfig> {
    return request.put('/ai/config', data);
}

export async function listAIModels(params?: { base_url?: string; api_key?: string }): Promise<{ models: API.AIModelInfo[] }> {
    return request.get('/ai/models', { params });
}

export async function testAIConnection(): Promise<{ success: boolean; response?: string; error?: string; elapsed_ms: number; base_url: string; model: string }> {
    return request.post('/ai/test', {}, { timeout: 60000 });
}

export async function debugPoc(data: API.DebugPocRequest): Promise<{ session_id: string; status: string }> {
    return request.post('/arsenals/debug', data);
}

export async function cancelDebugSession(sessionId: string): Promise<API.MessageResponse> {
    return request.post(`/arsenals/debug/${encodeURIComponent(sessionId)}/cancel`);
}

// ===========================
// Dictionary API
// ===========================

export async function getWorkflowDict(): Promise<API.WorkflowItem[]> {
    return request.get('/dictionaries/workflow');
}

export async function addWorkflowDict(data: API.WorkflowItem): Promise<API.MessageResponse> {
    return request.post('/dictionaries/workflow', data);
}

export async function updateWorkflowDict(oldProduct: string, data: API.WorkflowItem): Promise<API.MessageResponse> {
    return request.put(`/dictionaries/workflow/${encodeURIComponent(oldProduct)}`, data);
}

export async function deleteWorkflowDict(product: string): Promise<API.MessageResponse> {
    return request.delete(`/dictionaries/workflow/${encodeURIComponent(product)}`);
}

export async function getFingerprintDict(): Promise<API.FingerprintItem[]> {
    return request.get('/dictionaries/fingerprint');
}

export async function addFingerprintDict(data: API.FingerprintItem): Promise<API.MessageResponse> {
    return request.post('/dictionaries/fingerprint', data);
}

export async function updateFingerprintDict(oldProduct: string, data: API.FingerprintItem): Promise<API.MessageResponse> {
    return request.put(`/dictionaries/fingerprint/${encodeURIComponent(oldProduct)}`, data);
}

export async function deleteFingerprintDict(product: string): Promise<API.MessageResponse> {
    return request.delete(`/dictionaries/fingerprint/${encodeURIComponent(product)}`);
}

export async function getDirDict(): Promise<API.DirItem[]> {
    return request.get('/dictionaries/dir');
}

export async function addDirDict(data: API.DirItem): Promise<API.MessageResponse> {
    return request.post('/dictionaries/dir', data);
}

export async function updateDirDict(oldProduct: string, data: API.DirItem): Promise<API.MessageResponse> {
    return request.put(`/dictionaries/dir/${encodeURIComponent(oldProduct)}`, data);
}

export async function deleteDirDict(product: string): Promise<API.MessageResponse> {
    return request.delete(`/dictionaries/dir/${encodeURIComponent(product)}`);
}

// ===========================
// API Keys 集中配置
// ===========================

export async function getApiKeysConfig(): Promise<API.ApiKeyEntry[]> {
    return request.get('/config/api-keys');
}

export async function saveApiKeysConfig(data: API.ApiKeyEntry[]): Promise<API.MessageResponse> {
    return request.put('/config/api-keys', data);
}

// ===========================
// WebSocket（自动重连）
// ===========================

export function connectWebSocket(
    onMessage: (data: unknown) => void,
    onStatusChange?: (connected: boolean) => void,
): WebSocket {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = localStorage.getItem('token');
    const url = `${protocol}//${window.location.host}/api/v1/ws?token=${token}`;

    let reconnectDelay = 2000;
    const maxDelay = 30000;
    let destroyed = false;

    function connect(): WebSocket {
        const ws = new WebSocket(url);

        ws.onopen = () => {
            reconnectDelay = 2000; // 连接成功后重置退避
            onStatusChange?.(true);
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                onMessage(data);
            } catch {
                // ignore malformed messages
            }
        };

        ws.onerror = () => {
            // 静默处理，onclose 会触发重连
        };

        ws.onclose = () => {
            onStatusChange?.(false);
            if (destroyed) return;
            // 指数退避重连
            setTimeout(() => {
                if (!destroyed) {
                    connect();
                }
            }, reconnectDelay);
            reconnectDelay = Math.min(reconnectDelay * 1.5, maxDelay);
        };

        // 扩展 close 方法以支持外部销毁
        const originalClose = ws.close.bind(ws);
        ws.close = (code?: number, reason?: string) => {
            destroyed = true;
            originalClose(code, reason);
        };

        return ws;
    }

    return connect();
}

// ===========================
// User Management API
// ===========================

export async function listUsers(): Promise<API.User[]> {
    return request.get('/users');
}

export async function createUserApi(data: API.CreateUserRequest): Promise<{ status: string; id: number }> {
    return request.post('/users', data);
}

export async function updateUserApi(id: number, data: API.UpdateUserRequest): Promise<API.MessageResponse> {
    return request.put(`/users/${id}`, data);
}

export async function deleteUserApi(id: number): Promise<API.MessageResponse> {
    return request.delete(`/users/${id}`);
}

// ===========================
// Cloud Resource API
// ===========================

// Accounts
export async function listCloudAccounts(): Promise<API.CloudAccount[]> {
    return request.get('/cloud/accounts');
}

export async function createCloudAccount(data: API.CreateCloudAccountRequest): Promise<API.MessageResponse> {
    return request.post('/cloud/accounts', data);
}

export async function updateCloudAccount(id: string, data: Partial<API.CreateCloudAccountRequest>): Promise<API.MessageResponse> {
    return request.put(`/cloud/accounts/${id}`, data);
}

export async function getCloudAccountBindings(id: string): Promise<API.CloudAccountBindingsResponse> {
    return request.get(`/cloud/accounts/${id}/bindings`);
}

export async function updateCloudAccountBindings(id: string, userIds: string[]): Promise<API.MessageResponse> {
    return request.put(`/cloud/accounts/${id}/bindings`, { user_ids: userIds });
}

export async function deleteCloudAccount(id: string): Promise<API.MessageResponse> {
    return request.delete(`/cloud/accounts/${id}`);
}

export async function testCloudAccount(id: string): Promise<API.MessageResponse> {
    return request.post(`/cloud/accounts/${id}/test`);
}

export async function uploadAgentToOSS(id: string): Promise<any> {
    return request.post(`/cloud/accounts/${id}/oss/upload`);
}

export async function testOSSConnection(id: string): Promise<API.MessageResponse> {
    return request.post(`/cloud/accounts/${id}/oss/test`);
}

// Policies
export async function listCloudPolicies(): Promise<API.CloudScalingPolicy[]> {
    return request.get('/cloud/policies');
}

export async function createCloudPolicy(data: Partial<API.CloudScalingPolicy>): Promise<API.MessageResponse> {
    return request.post('/cloud/policies', data);
}

export async function updateCloudPolicy(id: string, data: Partial<API.CloudScalingPolicy>): Promise<API.MessageResponse> {
    return request.put(`/cloud/policies/${id}`, data);
}

export async function deleteCloudPolicy(id: string): Promise<API.MessageResponse> {
    return request.delete(`/cloud/policies/${id}`);
}

export async function toggleCloudPolicy(id: string): Promise<API.MessageResponse> {
    return request.post(`/cloud/policies/${id}/toggle`);
}

// Instances
export async function listCloudInstances(): Promise<API.CloudInstance[]> {
    return request.get('/cloud/instances');
}

export async function createCloudInstance(data: API.CreateCloudInstanceRequest): Promise<API.MessageResponse> {
    return request.post('/cloud/instances', data);
}

export async function deleteCloudInstance(id: string): Promise<API.MessageResponse> {
    return request.delete(`/cloud/instances/${id}`);
}

export async function rebootCloudInstance(id: string): Promise<API.MessageResponse> {
    return request.post(`/cloud/instances/${id}/reboot`);
}

// Region Discovery
export async function listCloudRegions(accountId: string): Promise<{ regions: API.RegionInfo[] }> {
    return request.get(`/cloud/accounts/${accountId}/regions`);
}

export async function updateCloudAccountRegion(accountId: string, region: string): Promise<API.MessageResponse> {
    return request.put(`/cloud/accounts/${accountId}`, { region });
}

// Agent 分发
export async function listReleaseFiles(accountId: string): Promise<{ files: API.ReleaseFileInfo[]; release_dir: string }> {
    return request.get(`/cloud/accounts/${accountId}/release-files`);
}

export async function uploadServerAgent(accountId: string, files?: string[]): Promise<any> {
    return request.post(`/cloud/accounts/${accountId}/oss/upload`, files ? { files } : undefined);
}

export async function uploadLocalAgent(
    accountId: string,
    files: File[],
    onProgress?: (percent: number) => void,
): Promise<any> {
    const formData = new FormData();
    files.forEach(f => formData.append('files', f));

    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', `/api/v1/cloud/accounts/${accountId}/oss/upload-local`);

        const token = localStorage.getItem('token');
        if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);

        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable && onProgress) {
                onProgress(Math.round((e.loaded / e.total) * 100));
            }
        };

        xhr.onload = () => {
            try {
                const data = JSON.parse(xhr.responseText);
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(data);
                } else {
                    reject(data?.error || data?.message || `上传失败 (${xhr.status})`);
                }
            } catch {
                reject(`上传失败: ${xhr.statusText}`);
            }
        };

        xhr.onerror = () => reject('网络错误');
        xhr.send(formData);
    });
}

export async function listOSSFiles(accountId: string, prefix?: string): Promise<{ files: API.OSSFileInfo[]; bucket: string; prefix: string }> {
    return request.get(`/cloud/accounts/${accountId}/oss/files`, { params: prefix ? { prefix } : undefined });
}

export async function deleteOSSFile(accountId: string, objectKey: string): Promise<API.MessageResponse> {
    return request.post(`/cloud/accounts/${accountId}/oss/delete`, { object_key: objectKey });
}

// Resource Discovery
export async function discoverCloudResources(accountId: string): Promise<any> {
    return request.get(`/cloud/accounts/${accountId}/discover`);
}

export async function autoConfigureCloudAccount(accountId: string, data: {
    default_instance_type?: string;
    default_image_id?: string;
    default_security_group?: string;
    default_v_switch?: string;
}): Promise<API.MessageResponse> {
    return request.post(`/cloud/accounts/${accountId}/auto-configure`, data);
}

export async function oneClickSetup(accountId: string): Promise<any> {
    return request.post(`/cloud/accounts/${accountId}/one-click-setup`);
}

// Permission Check
export async function checkCloudPermissions(accountId: string): Promise<any> {
    return request.get(`/cloud/accounts/${accountId}/permissions`, { timeout: 60000 });
}

// Price Query
export async function queryCloudPrice(accountId: string, params?: { instance_type?: string; spot_strategy?: string; region?: string }): Promise<{
    instance_type: string;
    region: string;
    spot_strategy: string;
    instance_price: number;
    spot_price: number;
    spot_discount: number;
    total_hourly: number;
    currency: string;
    price_unit: string;
    status?: string;
    message?: string;
}> {
    return request.get(`/cloud/accounts/${accountId}/price`, { params });
}

// Available Instance Types
export async function listAvailableInstanceTypes(accountId: string, params?: { spot_strategy?: string; region?: string }): Promise<{
    instance_types: { id: string; cpu: number; memory_gb: number; family: string; status: string }[];
    region: string;
    default_type: string;
}> {
    return request.get(`/cloud/accounts/${accountId}/instance-types`, { params, timeout: 30000 });
}

// Dashboard
export async function getCloudDashboard(): Promise<API.CloudDashboard> {
    return request.get('/cloud/dashboard');
}

// ===========================
// Build API
// ===========================

export async function listBuildArtifacts(): Promise<API.BuildArtifact[]> {
    return request.get('/build/artifacts');
}

export async function triggerBuild(data: API.BuildRequest): Promise<API.MessageResponse> {
    return request.post('/build/client', data);
}

// ===========================
// MCP Key API
// ===========================

export async function listMcpKeys(): Promise<API.McpKey[]> {
    return request.get('/mcp/keys');
}

export async function saveMcpKey(provider: string, key: string): Promise<API.MessageResponse> {
    return request.post('/mcp/keys', { provider, key });
}

export async function deleteMcpKey(id: string): Promise<API.MessageResponse> {
    return request.delete(`/mcp/keys/${id}`);
}

// ===========================
// Data Enhancement API
// ===========================

export async function getVulnTrends(days: number = 30): Promise<API.TrendPoint[]> {
    return request.get('/stats/trends', { params: { days } });
}

export async function getSeverityDistribution(): Promise<API.SeverityCount[]> {
    return request.get('/stats/severity');
}

export async function getTaskResultStats(limit: number = 20): Promise<API.TaskStats[]> {
    return request.get('/stats/task-results', { params: { limit } });
}

export async function getRecentHighVulns(limit: number = 10): Promise<API.Vulnerability[]> {
    return request.get('/stats/recent-high-vulns', { params: { limit } });
}

// ===========================
// Agent Log API
// ===========================

export async function getAgentLogs(agentId: string, limit: number = 100, level?: string): Promise<API.AgentLog[]> {
    const params: Record<string, string | number> = { limit };
    if (level) params.level = level;
    return request.get(`/agents/${agentId}/logs`, { params });
}

// ===========================
// Arsenal Rollback API
// ===========================

export async function rollbackArsenal(type: string, filename: string): Promise<API.MessageResponse> {
    return request.post(`/arsenals/${type}/${filename}/rollback`);
}

export default request;
