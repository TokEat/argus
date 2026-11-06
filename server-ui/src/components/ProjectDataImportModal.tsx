import { useState } from 'react';
import { Alert, Modal, Progress, Radio, Upload, message } from 'antd';
import { InboxOutlined } from '@ant-design/icons';
import { importProjectData } from '../services/api';
import type { ProjectDataImportResult } from '../services/api';

interface ProjectDataImportModalProps {
    open: boolean;
    onClose: () => void;
    /** 提供时允许「合并到当前项目」；为 undefined（如项目列表页顶部导入）时只允许新建项目。 */
    mergeProjectId?: string;
    onImported?: (result: ProjectDataImportResult) => void;
}

export default function ProjectDataImportModal({ open, onClose, mergeProjectId, onImported }: ProjectDataImportModalProps) {
    const [file, setFile] = useState<File | null>(null);
    const [mode, setMode] = useState<'new' | 'merge'>(mergeProjectId ? 'merge' : 'new');
    const [uploading, setUploading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState('');

    const reset = () => {
        setFile(null);
        setMode(mergeProjectId ? 'merge' : 'new');
        setUploading(false);
        setProgress(0);
        setError('');
    };

    const describe = (r: ProjectDataImportResult['counts'][keyof ProjectDataImportResult['counts']]) =>
        `新增 ${r.inserted} / 更新 ${r.updated}`;

    const handleOk = async () => {
        if (!file) {
            setError('请选择要导入的项目数据包');
            return;
        }
        if (mode === 'merge' && !mergeProjectId) {
            setError('缺少目标项目');
            return;
        }
        setUploading(true);
        setError('');
        setProgress(0);
        try {
            const result = await importProjectData(
                file,
                mode,
                mode === 'merge' ? mergeProjectId : undefined,
                setProgress,
            );
            message.success(
                `导入完成：资产（${describe(result.counts.assets)}）、漏洞（${describe(result.counts.vulnerabilities)}）、` +
                `指纹（${describe(result.counts.fingerprint_hits)}）、域名（${describe(result.counts.domains)}）`,
                5,
            );
            onImported?.(result);
            reset();
            onClose();
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        } finally {
            setUploading(false);
        }
    };

    return (
        <Modal
            title="导入项目数据"
            open={open}
            onOk={handleOk}
            onCancel={() => {
                if (uploading) return;
                reset();
                onClose();
            }}
            confirmLoading={uploading}
            okText="导入"
            cancelText="取消"
            okButtonProps={{ disabled: !file }}
        >
            <Radio.Group
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                style={{ marginBottom: 16 }}
                disabled={uploading}
                options={[
                    { value: 'new', label: '新建项目' },
                    { value: 'merge', label: '合并到当前项目', disabled: !mergeProjectId },
                ]}
                optionType="button"
                buttonStyle="solid"
            />
            <Upload.Dragger
                beforeUpload={(f) => {
                    setFile(f);
                    setError('');
                    return false;
                }}
                showUploadList={false}
                disabled={uploading}
                accept=".gz"
                maxCount={1}
            >
                <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                <p className="ant-upload-text">{file ? file.name : '点击或拖拽上传 .argus.json.gz 文件'}</p>
                <p className="ant-upload-hint">仅支持本平台导出的项目数据包，单个文件最大 512MB</p>
            </Upload.Dragger>
            {uploading && <Progress percent={progress} style={{ marginTop: 12 }} />}
            {error && <Alert type="error" message={error} style={{ marginTop: 12 }} showIcon />}
        </Modal>
    );
}
