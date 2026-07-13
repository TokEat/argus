import { Empty, Spin, Table } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { ReactNode } from 'react';

interface CloudInstancesPanelProps {
    loading: boolean;
    instances: API.CloudInstance[];
    columns: ColumnsType<API.CloudInstance>;
    renderExpandedRow: (record: API.CloudInstance) => ReactNode;
}

export const CloudInstancesPanel = ({ loading, instances, columns, renderExpandedRow }: CloudInstancesPanelProps) => (
    <div style={{ padding: '20px 0' }}>
        {loading && instances.length === 0 ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '60px 0' }}><Spin size="large" /></div>
        ) : instances.length === 0 ? (
            <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有正在运行或被调度的云实例" style={{ padding: '60px 0' }} />
        ) : (
            <Table
                columns={columns}
                dataSource={instances}
                rowKey="id"
                pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 个实例` }}
                size="middle"
                expandable={{ expandedRowRender: renderExpandedRow, rowExpandable: () => true }}
            />
        )}
    </div>
);
