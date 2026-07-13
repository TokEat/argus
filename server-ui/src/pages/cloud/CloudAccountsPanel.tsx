import { Alert, Table } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { ReactNode } from 'react';

interface CloudAccountsPanelProps {
    accounts: API.CloudAccount[];
    columns: ColumnsType<API.CloudAccount>;
    renderExpandedRow: (record: API.CloudAccount) => ReactNode;
}

export const CloudAccountsPanel = ({ accounts, columns, renderExpandedRow }: CloudAccountsPanelProps) => (
    <div style={{ padding: '20px 0' }}>
        <Alert
            message="所有 AccessKey 和 Secret 均在入库前通过 AES-256-GCM 算法进行加密存储。点击「自动探测」可通过 AK/SK 自动发现云资源并配置。"
            type="success"
            showIcon
            style={{ marginBottom: 16 }}
        />
        <Table
            columns={columns}
            dataSource={accounts}
            rowKey="id"
            pagination={false}
            size="middle"
            expandable={{ expandedRowRender: renderExpandedRow, rowExpandable: () => true }}
        />
    </div>
);
