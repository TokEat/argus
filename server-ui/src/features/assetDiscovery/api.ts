import request from '../../services/api';

export async function queryProjectAssetDiscovery(
    projectId: string,
    provider: API.AssetDiscoveryProvider,
    expression: string,
    params: { page?: number; limit?: number; snapshotId?: number } = {},
): Promise<API.AssetDiscoveryQueryPreview> {
    return request.post(
        `/projects/${encodeURIComponent(projectId)}/asset-discovery/${provider}/query`,
        {
            expression,
            limit: params.limit,
            page: params.page,
            snapshot_id: params.snapshotId,
        },
    );
}

export async function listProjectAssetDiscoveryQueries(
    projectId: string,
    params: { page?: number; pageSize?: number; provider?: API.AssetDiscoveryProvider } = {},
): Promise<API.AssetDiscoveryQueryHistory> {
    return request.get(`/projects/${encodeURIComponent(projectId)}/asset-discovery/queries`, {
        params: {
            page: params.page,
            page_size: params.pageSize,
            provider: params.provider,
        },
    });
}

export async function getProjectAssetDiscoveryQuery(
    projectId: string,
    snapshotId: number,
    params: { page?: number; pageSize?: number } = {},
): Promise<API.AssetDiscoveryQueryDetail> {
    return request.get(`/projects/${encodeURIComponent(projectId)}/asset-discovery/queries/${encodeURIComponent(String(snapshotId))}`, {
        params: { page: params.page, page_size: params.pageSize },
    });
}

export async function exportProjectAssetDiscoveryQuery(
    projectId: string,
    snapshotId: number,
): Promise<Blob> {
    return request.get<Blob, Blob>(
        `/projects/${encodeURIComponent(projectId)}/asset-discovery/queries/${encodeURIComponent(String(snapshotId))}/export`,
        { responseType: 'blob' },
    );
}

export async function listProjectAssetDiscoveryNotebookItems(
    projectId: string,
    params: { page?: number; pageSize?: number; q?: string; tag?: string; state?: 'active' | 'removed' | 'all' } = {},
): Promise<API.AssetDiscoveryNotebookList> {
    return request.get(`/projects/${encodeURIComponent(projectId)}/asset-discovery/notebook-items`, {
        params: { page: params.page, page_size: params.pageSize, q: params.q, tag: params.tag, state: params.state },
    });
}

export async function listAccessibleAssetDiscoveryNotebookItems(
    params: { page?: number; pageSize?: number; q?: string; tag?: string; state?: 'active' | 'removed' | 'all'; projectId?: string } = {},
): Promise<API.AssetDiscoveryNotebookList> {
    return request.get('/asset-discovery/notebook-items', {
        params: {
            page: params.page,
            page_size: params.pageSize,
            q: params.q,
            tag: params.tag,
            state: params.state,
            project_id: params.projectId,
        },
    });
}

export async function updateProjectAssetDiscoveryNotebookItem(
    projectId: string,
    itemId: number,
    data: API.AssetDiscoveryNotebookUpdateRequest,
): Promise<void> {
    return request.patch(
        `/projects/${encodeURIComponent(projectId)}/asset-discovery/notebook-items/${encodeURIComponent(String(itemId))}`,
        data,
    );
}

export async function setProjectAssetDiscoveryNotebookItemRemoved(
    projectId: string,
    itemId: number,
    removed: boolean,
): Promise<void> {
    return request.post(
        `/projects/${encodeURIComponent(projectId)}/asset-discovery/notebook-items/${encodeURIComponent(String(itemId))}/${removed ? 'remove' : 'restore'}`,
    );
}

export async function archiveProjectAssetDiscoveryNotebookItems(
    projectId: string,
    snapshotId: number,
    itemIds: number[],
): Promise<API.AssetDiscoveryArchiveNotebookItemsResult> {
    return request.post(
        `/projects/${encodeURIComponent(projectId)}/asset-discovery/queries/${encodeURIComponent(String(snapshotId))}/notebook-items`,
        { item_ids: itemIds },
    );
}

export async function previewProjectAssetDiscoveryNotebookDistribution(
    projectId: string,
    taskId: string,
    itemIds: number[],
): Promise<API.AssetDiscoveryNotebookDistributionPreview> {
    return request.post(
        `/projects/${encodeURIComponent(projectId)}/asset-discovery/notebook-distributions/preview`,
        { task_id: taskId, item_ids: itemIds },
    );
}

export async function materializeProjectAssetDiscoveryNotebookDistribution(
    projectId: string,
    data: API.AssetDiscoveryNotebookDistributionMaterializeRequest,
    idempotencyKey: string,
): Promise<API.AssetDiscoveryNotebookDistributionMaterializeResult> {
    return request.post(
        `/projects/${encodeURIComponent(projectId)}/asset-discovery/notebook-distributions`,
        {
            task_id: data.task_id,
            item_ids: data.item_ids,
            plan_hash: data.plan_hash,
        },
        { headers: { 'Idempotency-Key': idempotencyKey } },
    );
}
