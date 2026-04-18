import axios from 'axios';
import type { AxiosInstance, AxiosResponse } from 'axios';

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
            if (!window.location.pathname.includes('/login')) {
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
// Task API
// ===========================

export async function listTasks(): Promise<API.RootTask[]> {
    return request.get('/tasks');
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

export async function getProfiles(): Promise<API.Profile[]> {
    return request.get('/profiles');
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

export async function aiAnalyzeArsenal(content: string): Promise<{ suggestion: string; reason: string; confidence: number }> {
    return request.post('/arsenals/ai/analyze', { content });
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

// ===========================
// WebSocket
// ===========================

export function connectWebSocket(onMessage: (data: unknown) => void): WebSocket {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = localStorage.getItem('token');
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws?token=${token}`);
    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            onMessage(data);
        } catch {
            // ignore
        }
    };
    return ws;
}

export default request;
