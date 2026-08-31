import request from './request';

export interface McpAdminStatus {
    enabled: boolean;
    mcp_url: string;
    public_url: string;
    transport: string;
    session_count: number;
}

export interface McpAdminClient {
    client_id: string;
    redirect_uris: string[];
    builtin: boolean;
    blocked: boolean;
    session_count: number;
    last_used_at?: string;
    created_at?: string;
}

export interface McpAdminSession {
    session_id: string;
    user_id: string;
    client_id: string;
    created_at: string;
    expires_at: string;
}

export interface McpAdminInvocation {
    id: string;
    user_id: string;
    role: string;
    client_id: string;
    tool_name: string;
    action?: string;
    args: Record<string, unknown>;
    agent_id?: string;
    target?: string;
    duration_ms: number;
    status: string;
    error_summary?: string;
    created_at: string;
}

export interface McpAdminInvocationList {
    total: number;
    items: McpAdminInvocation[];
}

export interface McpAdminEvent {
    id: string;
    actor_id: string;
    action: string;
    client_id?: string;
    details: Record<string, unknown>;
    created_at: string;
}

export interface McpAdminEventList {
    total: number;
    items: McpAdminEvent[];
}

export interface McpAdminTool {
    name: string;
    title?: string;
    description: string;
    category: string;
    auditable: boolean;
    audit_when?: string;
    input_schema?: Record<string, unknown>;
    example_call?: {
        jsonrpc: string;
        id: number;
        method: string;
        params: { name: string; arguments: Record<string, unknown> };
    };
}

export async function getMcpAdminStatus(): Promise<McpAdminStatus> {
    return request.get('/mcp/admin/status');
}

export async function updateMcpAdminStatus(enabled: boolean, confirm = false): Promise<{ status: string; enabled: boolean; revoked_sessions?: number }> {
    return request.put('/mcp/admin/status', { enabled, confirm });
}

export async function listMcpAdminClients(): Promise<McpAdminClient[]> {
    return request.get('/mcp/admin/clients');
}

export async function revokeMcpAdminClient(clientId: string): Promise<{ status: string; revoked_sessions: number }> {
    return request.post(`/mcp/admin/clients/${encodeURIComponent(clientId)}/revoke`, { confirm: true });
}

export async function disableMcpAdminClient(clientId: string): Promise<{ status: string; revoked_sessions: number }> {
    return request.post(`/mcp/admin/clients/${encodeURIComponent(clientId)}/disable`, { confirm: true });
}

export async function enableMcpAdminClient(clientId: string): Promise<API.MessageResponse> {
    return request.post(`/mcp/admin/clients/${encodeURIComponent(clientId)}/enable`);
}

export async function deleteMcpAdminClient(clientId: string): Promise<{ status: string; revoked_sessions: number; row_deleted: boolean }> {
    return request.delete(`/mcp/admin/clients/${encodeURIComponent(clientId)}`, { data: { confirm: true } });
}

export async function listMcpAdminSessions(): Promise<McpAdminSession[]> {
    return request.get('/mcp/admin/sessions');
}

export async function revokeMcpAdminSession(sessionId: string): Promise<{ status: string; revoked_sessions: number }> {
    return request.post('/mcp/admin/sessions/revoke', { confirm: true, session_id: sessionId });
}

export async function revokeMcpAdminUserSessions(userId: string): Promise<{ status: string; revoked_sessions: number }> {
    return request.post('/mcp/admin/sessions/revoke', { confirm: true, user_id: userId });
}

export async function listMcpAdminInvocations(params?: {
    limit?: number;
    offset?: number;
    tool_name?: string;
    user_id?: string;
    client_id?: string;
    status?: string;
    since?: string;
    until?: string;
}): Promise<McpAdminInvocationList> {
    return request.get('/mcp/admin/invocations', { params });
}

export async function listMcpAdminEvents(params?: {
    limit?: number;
    offset?: number;
    action?: string;
    actor_id?: string;
    client_id?: string;
}): Promise<McpAdminEventList> {
    return request.get('/mcp/admin/events', { params });
}

export async function listMcpAdminTools(): Promise<McpAdminTool[]> {
    return request.get('/mcp/admin/tools');
}
