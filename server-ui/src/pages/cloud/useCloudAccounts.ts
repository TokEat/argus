import { Form, message } from 'antd';
import { useCallback, useState } from 'react';
import {
    createCloudAccount,
    deleteCloudAccount,
    getCloudAccountBindings,
    listCloudAccounts,
    listUsers,
    testCloudAccount,
    updateCloudAccountBindings,
} from '../../services/api';
import { extractErrorMsg } from './utils';

interface UseCloudAccountsOptions {
    isAdmin: boolean;
    onDashboardRefresh: () => void;
}

export const useCloudAccounts = ({ isAdmin, onDashboardRefresh }: UseCloudAccountsOptions) => {
    const [accounts, setAccounts] = useState<API.CloudAccount[]>([]);
    const [users, setUsers] = useState<API.User[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [addModalOpen, setAddModalOpen] = useState(false);
    const [bindingModalOpen, setBindingModalOpen] = useState(false);
    const [bindingAccount, setBindingAccount] = useState<API.CloudAccount | null>(null);
    const [bindingUserIds, setBindingUserIds] = useState<string[]>([]);
    const [bindingSaving, setBindingSaving] = useState(false);
    const [form] = Form.useForm();

    const canManage = useCallback((account?: API.CloudAccount | null) => {
        if (!account) return false;
        return account.access_level === 'admin' || account.access_level === 'owner';
    }, []);

    const fetchAccounts = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const result = await listCloudAccounts();
            setAccounts(result || []);
            return result || [];
        } catch (err) {
            const messageText = extractErrorMsg(err) || 'Failed to fetch accounts';
            setError(messageText);
            console.error('Failed to fetch accounts:', err);
            return [];
        } finally {
            setLoading(false);
        }
    }, []);

    const fetchUsers = useCallback(async () => {
        if (!isAdmin) return [];
        try {
            const result = await listUsers();
            const usable = (result || []).filter(user => user.status === 'active' && ['admin', 'operator'].includes(user.role));
            setUsers(usable);
            return usable;
        } catch (err) {
            console.error('Failed to fetch tenant users:', err);
            return [];
        }
    }, [isAdmin]);

    const openAddModal = useCallback(() => {
        form.resetFields();
        if (isAdmin && users.length === 0) fetchUsers();
        setAddModalOpen(true);
    }, [fetchUsers, form, isAdmin, users.length]);

    const addAccount = useCallback(async () => {
        try {
            const values = await form.validateFields();
            if (!isAdmin) delete values.bound_user_ids;
            await createCloudAccount(values);
            message.success('凭证已加密保存');
            setAddModalOpen(false);
            fetchAccounts();
            onDashboardRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        }
    }, [fetchAccounts, form, isAdmin, onDashboardRefresh]);

    const openBindings = useCallback(async (account: API.CloudAccount) => {
        setBindingAccount(account);
        setBindingUserIds(account.bound_user_ids || []);
        setBindingModalOpen(true);
        const availableUsers = users.length > 0 ? users : await fetchUsers();
        try {
            const bindings = await getCloudAccountBindings(account.id);
            setBindingUserIds((bindings.user_ids || []).filter(id => availableUsers.some(user => String(user.id) === String(id))));
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        }
    }, [fetchUsers, users]);

    const saveBindings = useCallback(async () => {
        if (!bindingAccount) return;
        setBindingSaving(true);
        try {
            await updateCloudAccountBindings(bindingAccount.id, bindingUserIds);
            message.success('凭证绑定已更新');
            setBindingModalOpen(false);
            await fetchAccounts();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        } finally {
            setBindingSaving(false);
        }
    }, [bindingAccount, bindingUserIds, fetchAccounts]);

    const deleteAccount = useCallback(async (id: string) => {
        try {
            await deleteCloudAccount(id);
            message.success('凭证已删除');
            fetchAccounts();
            onDashboardRefresh();
        } catch (err) {
            const messageText = extractErrorMsg(err);
            if (messageText) message.error(messageText);
        }
    }, [fetchAccounts, onDashboardRefresh]);

    const testAccount = useCallback(async (id: string) => {
        try {
            message.loading({ content: '正在连接云厂商测试凭证...', key: 'testAK', duration: 0 });
            const result = await testCloudAccount(id);
            message.destroy('testAK');
            if (result && (result as any).status === 'error') {
                message.error(`连通性测试失败: ${(result as any).message || '未知错误'}`);
            } else {
                message.success('凭证连通性测试通过');
            }
        } catch (err) {
            message.destroy('testAK');
            setTimeout(() => message.error(`连通性测试失败: ${extractErrorMsg(err)}`), 50);
        }
    }, []);

    return {
        accounts,
        users,
        loading,
        error,
        addModalOpen,
        setAddModalOpen,
        bindingModalOpen,
        setBindingModalOpen,
        bindingAccount,
        bindingUserIds,
        setBindingUserIds,
        bindingSaving,
        form,
        canManage,
        fetchAccounts,
        fetchUsers,
        openAddModal,
        addAccount,
        openBindings,
        saveBindings,
        deleteAccount,
        testAccount,
    };
};
