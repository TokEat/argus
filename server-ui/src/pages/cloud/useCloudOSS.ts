import { message } from 'antd';
import { useCallback, useState } from 'react';
import {
    listReleaseFiles,
    testOSSConnection,
    uploadLocalAgent,
    uploadServerAgent,
} from '../../services/api';
import { extractErrorMsg } from './utils';

export const useCloudOSS = () => {
    const [uploadOpen, setUploadOpen] = useState(false);
    const [accountId, setAccountId] = useState('');
    const [mode, setMode] = useState('服务器端制品');
    const [releaseFiles, setReleaseFiles] = useState<API.ReleaseFileInfo[]>([]);
    const [releaseFilesLoading, setReleaseFilesLoading] = useState(false);
    const [selectedReleaseFiles, setSelectedReleaseFiles] = useState<string[]>([]);
    const [serverUploading, setServerUploading] = useState(false);
    const [localFiles, setLocalFiles] = useState<File[]>([]);
    const [localUploading, setLocalUploading] = useState(false);
    const [localUploadProgress, setLocalUploadProgress] = useState(0);
    const [testResult, setTestResult] = useState<any>(null);
    const [testModalOpen, setTestModalOpen] = useState(false);
    const [testLoading, setTestLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const loadReleaseFiles = useCallback(async (targetAccountId: string) => {
        setReleaseFilesLoading(true);
        setError(null);
        try {
            const result = await listReleaseFiles(targetAccountId);
            setReleaseFiles(result.files || []);
        } catch (err) {
            setReleaseFiles([]);
            setError(extractErrorMsg(err) || 'Failed to load release files');
        } finally {
            setReleaseFilesLoading(false);
        }
    }, []);

    const openUpload = useCallback((account: API.CloudAccount) => {
        setAccountId(account.id);
        setMode('服务器端制品');
        setSelectedReleaseFiles([]);
        setLocalFiles([]);
        setLocalUploadProgress(0);
        setUploadOpen(true);
        loadReleaseFiles(account.id);
    }, [loadReleaseFiles]);

    const closeUpload = useCallback(() => {
        setUploadOpen(false);
        setLocalFiles([]);
        setLocalUploadProgress(0);
    }, []);

    const changeMode = useCallback((nextMode: string) => {
        setMode(nextMode);
        if (nextMode === '服务器端制品' && releaseFiles.length === 0 && !releaseFilesLoading) {
            loadReleaseFiles(accountId);
        }
    }, [accountId, loadReleaseFiles, releaseFiles.length, releaseFilesLoading]);

    const uploadServer = useCallback(async () => {
        setServerUploading(true);
        try {
            const result = await uploadServerAgent(accountId, selectedReleaseFiles);
            if (result?.status === 'ok') {
                message.success(result.message || '上传成功');
                setUploadOpen(false);
            } else {
                message.error(result?.message || '上传失败');
            }
        } catch (err) {
            message.error(`上传失败: ${extractErrorMsg(err) || String(err) || '未知错误'}`);
        } finally {
            setServerUploading(false);
        }
    }, [accountId, selectedReleaseFiles]);

    const uploadLocal = useCallback(async () => {
        setLocalUploading(true);
        setLocalUploadProgress(0);
        try {
            const result = await uploadLocalAgent(accountId, localFiles, setLocalUploadProgress);
            if (result?.status === 'ok') {
                message.success(result.message || '上传成功');
                setUploadOpen(false);
                setLocalFiles([]);
                setLocalUploadProgress(0);
            } else {
                message.error(result?.message || '上传失败');
            }
        } catch (err) {
            message.error(`上传失败: ${extractErrorMsg(err) || String(err) || '未知错误'}`);
        } finally {
            setLocalUploading(false);
        }
    }, [accountId, localFiles]);

    const test = useCallback(async (account: API.CloudAccount) => {
        setTestLoading(true);
        setTestResult(null);
        setTestModalOpen(true);
        try {
            setTestResult(await testOSSConnection(account.id));
        } catch (err) {
            setTestResult({
                status: 'error',
                connection: false,
                connection_err: extractErrorMsg(err) || String(err),
                bucket: account.oss_bucket,
                endpoint: account.oss_endpoint,
            });
        } finally {
            setTestLoading(false);
        }
    }, []);

    return {
        uploadOpen,
        mode,
        releaseFiles,
        releaseFilesLoading,
        selectedReleaseFiles,
        setSelectedReleaseFiles,
        serverUploading,
        localFiles,
        setLocalFiles,
        localUploading,
        localUploadProgress,
        setLocalUploadProgress,
        testResult,
        testModalOpen,
        setTestModalOpen,
        testLoading,
        error,
        openUpload,
        closeUpload,
        changeMode,
        uploadServer,
        uploadLocal,
        test,
    };
};
