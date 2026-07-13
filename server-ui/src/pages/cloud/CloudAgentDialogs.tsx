import { CloudServerOutlined, CloudUploadOutlined, DeleteOutlined, FileOutlined, InboxOutlined, UploadOutlined } from '@ant-design/icons';
import { Alert, Button, Empty, Modal, Progress, Segmented, Space, Spin, Table, Tag, Typography, Upload } from 'antd';
import type { Dispatch, SetStateAction } from 'react';

const { Text } = Typography;

interface CloudAgentUploadModalProps {
    open: boolean;
    mode: string;
    releaseFiles: API.ReleaseFileInfo[];
    releaseFilesLoading: boolean;
    selectedReleaseFiles: string[];
    serverUploading: boolean;
    localFiles: File[];
    localUploading: boolean;
    localUploadProgress: number;
    onClose: () => void;
    onModeChange: (mode: string) => void;
    onSelectedReleaseFilesChange: (files: string[]) => void;
    onServerUpload: () => void;
    onLocalFilesChange: Dispatch<SetStateAction<File[]>>;
    onLocalUpload: () => void;
    onClearLocalFiles: () => void;
}

export const CloudAgentUploadModal = ({
    open,
    mode,
    releaseFiles,
    releaseFilesLoading,
    selectedReleaseFiles,
    serverUploading,
    localFiles,
    localUploading,
    localUploadProgress,
    onClose,
    onModeChange,
    onSelectedReleaseFilesChange,
    onServerUpload,
    onLocalFilesChange,
    onLocalUpload,
    onClearLocalFiles,
}: CloudAgentUploadModalProps) => (
    <Modal
        title={<><CloudUploadOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />上传 Agent 到 OSS</>}
        open={open}
        onCancel={onClose}
        footer={null}
        width={680}
        destroyOnClose
    >
        <Segmented
            block
            value={mode}
            onChange={(value) => onModeChange(value as string)}
            options={[
                { label: <span><CloudServerOutlined style={{ marginRight: 4 }} />服务器端制品</span>, value: '服务器端制品' },
                { label: <span><UploadOutlined style={{ marginRight: 4 }} />本地上传</span>, value: '本地上传' },
            ]}
            style={{ marginBottom: 20 }}
        />
        {mode === '服务器端制品' ? (
            <div>
                <Alert message="选择服务器 ./release 目录下的 Agent 二进制文件上传到 OSS" type="info" showIcon style={{ marginBottom: 16 }} />
                {releaseFilesLoading ? (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}><Spin /></div>
                ) : releaseFiles.length === 0 ? (
                    <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description={<span>服务器 <Text code>./release</Text> 目录为空或不存在<br /><Text type="secondary" style={{ fontSize: 12 }}>请先构建 Agent 二进制或切换到「本地上传」</Text></span>}
                        style={{ padding: '40px 0' }}
                    />
                ) : (
                    <>
                        <Table
                            dataSource={releaseFiles}
                            rowKey="name"
                            pagination={false}
                            size="small"
                            rowSelection={{
                                selectedRowKeys: selectedReleaseFiles,
                                onChange: (keys) => onSelectedReleaseFilesChange(keys as string[]),
                            }}
                            columns={[
                                { title: '文件名', dataIndex: 'name', key: 'name', render: (name: string) => <Space><FileOutlined style={{ color: '#64748b' }} /><Text style={{ fontFamily: 'monospace', fontSize: 13 }}>{name}</Text></Space> },
                                { title: '大小', dataIndex: 'size', key: 'size', width: 120, render: (size: number) => <Text type="secondary">{(size / 1024 / 1024).toFixed(1)} MB</Text> },
                                { title: '修改时间', dataIndex: 'modified', key: 'modified', width: 180, render: (value: string) => <Text style={{ fontSize: 12, color: '#64748b' }}>{value ? new Date(value).toLocaleString('zh-CN') : '-'}</Text> },
                            ]}
                        />
                        <div style={{ marginTop: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Text type="secondary" style={{ fontSize: 12 }}>已选 {selectedReleaseFiles.length}/{releaseFiles.length} 个文件</Text>
                            <Space>
                                <Button onClick={() => onSelectedReleaseFilesChange(releaseFiles.map(file => file.name))}>全选</Button>
                                <Button type="primary" icon={<CloudUploadOutlined />} disabled={selectedReleaseFiles.length === 0} loading={serverUploading} onClick={onServerUpload}>
                                    上传选中文件到 OSS
                                </Button>
                            </Space>
                        </div>
                    </>
                )}
            </div>
        ) : (
            <div>
                <Alert message="从本地选择 Agent 二进制文件，上传到服务器并自动推送到 OSS" type="info" showIcon style={{ marginBottom: 16 }} />
                <Upload.Dragger
                    multiple
                    beforeUpload={(file, fileList) => {
                        if (file === fileList[0]) {
                            onLocalFilesChange(previous => {
                                const existingNames = new Set(previous.map(item => item.name));
                                return [...previous, ...fileList.filter(item => !existingNames.has(item.name))];
                            });
                        }
                        return false;
                    }}
                    showUploadList={false}
                    accept="*"
                    disabled={localUploading}
                >
                    <p className="ant-upload-drag-icon"><InboxOutlined style={{ color: '#0ea5e9', fontSize: 48 }} /></p>
                    <p className="ant-upload-text">点击或拖拽文件到此区域</p>
                    <p className="ant-upload-hint">支持多文件选择，支持 Linux/ARM 等多架构 Agent 二进制</p>
                </Upload.Dragger>
                {localFiles.length > 0 && (
                    <div style={{ marginTop: 16 }}>
                        <div style={{ marginBottom: 8, fontWeight: 500 }}>待上传文件 ({localFiles.length})</div>
                        {localFiles.map((file, index) => (
                            <div key={file.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', background: index % 2 === 0 ? '#f8fafc' : '#fff', borderRadius: 4, marginBottom: 2 }}>
                                <Space><FileOutlined style={{ color: '#64748b' }} /><Text style={{ fontFamily: 'monospace', fontSize: 13 }}>{file.name}</Text><Text type="secondary" style={{ fontSize: 12 }}>({(file.size / 1024 / 1024).toFixed(1)} MB)</Text></Space>
                                <Button type="text" size="small" danger icon={<DeleteOutlined />} onClick={() => onLocalFilesChange(previous => previous.filter((_, itemIndex) => itemIndex !== index))} disabled={localUploading} />
                            </div>
                        ))}
                        {localUploading && <Progress percent={localUploadProgress} status="active" strokeColor={{ '0%': '#0ea5e9', '100%': '#10b981' }} style={{ marginTop: 12 }} />}
                        <div style={{ marginTop: 16, display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                            <Button onClick={onClearLocalFiles} disabled={localUploading}>清空</Button>
                            <Button type="primary" icon={<CloudUploadOutlined />} loading={localUploading} onClick={onLocalUpload}>上传到服务器 & OSS</Button>
                        </div>
                    </div>
                )}
            </div>
        )}
    </Modal>
);

interface CloudRegionSelectModalProps {
    open: boolean;
    loading: boolean;
    regions: API.RegionInfo[];
    onSelect: (regionId: string) => void;
    onClose: () => void;
}

export const CloudRegionSelectModal = ({ open, loading, regions, onSelect, onClose }: CloudRegionSelectModalProps) => (
    <Modal title="选择云资源地域" open={open} onCancel={onClose} footer={null} width={600}>
        <Alert message="该凭证尚未指定地域，请选择一个地域以继续操作。地域决定了弹性扩缩时 ECS 实例的创建位置。" type="info" showIcon style={{ marginBottom: 16 }} />
        {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}><Spin size="large" /></div>
        ) : (
            <div style={{ maxHeight: 400, overflow: 'auto' }}>
                {regions.map(region => (
                    <div
                        key={region.region_id}
                        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', borderBottom: '1px solid #f0f0f0', cursor: 'pointer', borderRadius: 6, transition: 'background 0.2s' }}
                        onMouseEnter={(event) => { event.currentTarget.style.background = '#f0f9ff'; }}
                        onMouseLeave={(event) => { event.currentTarget.style.background = 'transparent'; }}
                        onClick={() => onSelect(region.region_id)}
                    >
                        <div>
                            <Text strong style={{ fontSize: 14 }}>{region.local_name}</Text>
                            <Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>{region.region_id}</Text>
                            {region.region_id.startsWith('cn-') && <Tag color="blue" style={{ marginLeft: 8, fontSize: 10 }}>推荐</Tag>}
                        </div>
                        <Button type="link" size="small">选择</Button>
                    </div>
                ))}
                {regions.length === 0 && <Empty description="未获取到可用地域" style={{ padding: '40px 0' }} />}
            </div>
        )}
    </Modal>
);
