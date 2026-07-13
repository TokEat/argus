import { AppstoreOutlined, CloudOutlined, CloudUploadOutlined, DeleteOutlined, KeyOutlined, PlusOutlined, ReloadOutlined, SettingOutlined, WifiOutlined } from '@ant-design/icons';
import { ProCard } from '@ant-design/pro-components';
import { Button, Popconfirm, Space, Tabs, Tag, Typography } from 'antd';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import NetworkCanvas from '../components/NetworkCanvas';
import { useAutoContext } from '../contexts/GlobalAIContext';
import { getCloudDashboard } from '../services/api';
import { canAccessRole, getCurrentUserRole } from '../utils/auth';
import { AddCloudAccountModal, CloudAccountBindingModal, CloudDiscoveryModal } from './cloud/CloudAccountDialogs';
import { CloudOSSTestModal, CloudPermissionDrawer, CloudSetupResultModal } from './cloud/CloudAccountResultDialogs';
import { CloudAccountsPanel } from './cloud/CloudAccountsPanel';
import { CloudAgentUploadModal, CloudRegionSelectModal } from './cloud/CloudAgentDialogs';
import { CloudAgentDistributionPanel } from './cloud/CloudAgentDistributionPanel';
import { CloudInstanceCreateModal } from './cloud/CloudInstanceCreateModal';
import { CloudInstancesPanel } from './cloud/CloudInstancesPanel';
import { CloudPolicyPanel } from './cloud/CloudPolicyPanel';
import { useCloudAccounts } from './cloud/useCloudAccounts';
import { useCloudDiscovery } from './cloud/useCloudDiscovery';
import { useCloudInstances } from './cloud/useCloudInstances';
import { useCloudOSS } from './cloud/useCloudOSS';
import { useCloudPolicies } from './cloud/useCloudPolicies';
import gsap from 'gsap';

const { Title } = Typography;

const CloudManagement = () => {
    const [activeTab, setActiveTab] = useState('instances');
    const [dashboard, setDashboard] = useState<API.CloudDashboard | null>(null);
    const pageRef = useRef<HTMLDivElement>(null);
    const isAdmin = useMemo(() => canAccessRole('admin', getCurrentUserRole()), []);

    const fetchDashboard = useCallback(async () => {
        try {
            setDashboard(await getCloudDashboard());
        } catch (error) {
            console.error('Failed to fetch dashboard:', error);
        }
    }, []);

    const accountState = useCloudAccounts({ isAdmin, onDashboardRefresh: fetchDashboard });
    const policyState = useCloudPolicies({
        active: activeTab === 'policy',
        accounts: accountState.accounts,
        onDashboardRefresh: fetchDashboard,
    });
    const instanceState = useCloudInstances({
        accounts: accountState.accounts,
        policies: policyState.policies,
        onAccountsRefresh: accountState.fetchAccounts,
        onDashboardRefresh: fetchDashboard,
    });
    const discoveryState = useCloudDiscovery({
        accounts: accountState.accounts,
        canManageAccount: accountState.canManage,
        onAccountsRefresh: accountState.fetchAccounts,
        onPoliciesRefresh: policyState.fetchPolicies,
        onDashboardRefresh: fetchDashboard,
    });
    const ossState = useCloudOSS();
    const tabLifecycleRef = useRef({
        fetchDashboard,
        fetchInstances: instanceState.fetchInstances,
        setInstancesLoading: instanceState.setLoading,
        fetchAccounts: accountState.fetchAccounts,
        accountCount: accountState.accounts.length,
        fetchUsers: accountState.fetchUsers,
        userCount: accountState.users.length,
        fetchPolicies: policyState.fetchPolicies,
        isAdmin,
    });
    useEffect(() => {
        tabLifecycleRef.current = {
            fetchDashboard,
            fetchInstances: instanceState.fetchInstances,
            setInstancesLoading: instanceState.setLoading,
            fetchAccounts: accountState.fetchAccounts,
            accountCount: accountState.accounts.length,
            fetchUsers: accountState.fetchUsers,
            userCount: accountState.users.length,
            fetchPolicies: policyState.fetchPolicies,
            isAdmin,
        };
    }, [
        accountState.accounts.length,
        accountState.fetchAccounts,
        accountState.fetchUsers,
        accountState.users.length,
        fetchDashboard,
        instanceState.fetchInstances,
        instanceState.setLoading,
        isAdmin,
        policyState.fetchPolicies,
    ]);

    useEffect(() => {
        if (!pageRef.current) return;
        const elements = pageRef.current.querySelectorAll('.cloud-animate-in');
        if (elements.length === 0) return;
        const context = gsap.context(() => {
            gsap.from(elements, { y: 24, opacity: 0, duration: 0.45, stagger: 0.08, ease: 'power2.out', clearProps: 'transform,opacity' });
        }, pageRef);
        return () => context.revert();
    }, []);

    useEffect(() => {
        const actions = tabLifecycleRef.current;
        actions.fetchDashboard();
        if (activeTab === 'instances') {
            actions.setInstancesLoading(true);
            actions.fetchInstances().finally(() => actions.setInstancesLoading(false));
            if (actions.accountCount === 0) actions.fetchAccounts();
            const timer = window.setInterval(() => {
                actions.fetchInstances();
                actions.fetchDashboard();
            }, 15000);
            return () => window.clearInterval(timer);
        }
        if (activeTab === 'credentials' || activeTab === 'agent-dist') {
            actions.fetchAccounts();
            if (actions.isAdmin && actions.userCount === 0) actions.fetchUsers();
        } else if (activeTab === 'policy') {
            actions.fetchPolicies();
            if (actions.accountCount === 0) actions.fetchAccounts();
        }
    }, [activeTab]);

    useAutoContext({ cloud_dashboard: dashboard, cloud_active_tab: activeTab });

    const policyTabContent = useMemo(() => (
        <CloudPolicyPanel
            policies={policyState.policies}
            accounts={accountState.accounts}
            currentPolicyId={policyState.currentPolicyId}
            form={policyState.form}
            initialValues={policyState.defaultFormValues}
            userDataScript={policyState.userDataScript}
            onPolicyChange={policyState.selectPolicy}
            onUserDataScriptChange={policyState.setUserDataScript}
            onToggle={policyState.toggle}
            onSubmit={policyState.submit}
            onDelete={policyState.remove}
        />
    ), [
        accountState.accounts,
        policyState.currentPolicyId,
        policyState.defaultFormValues,
        policyState.form,
        policyState.policies,
        policyState.remove,
        policyState.selectPolicy,
        policyState.setUserDataScript,
        policyState.submit,
        policyState.toggle,
        policyState.userDataScript,
    ]);

    return (
        <div ref={pageRef} style={{ position: 'relative', overflow: 'hidden' }}>
            <NetworkCanvas color="#0ea5e9" count={30} speed={0.15} linkDist={100} />
            <div className="cloud-animate-in" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, position: 'relative', zIndex: 1 }}>
                <Title level={4} style={{ margin: 0, color: '#1e293b', fontWeight: 600 }}>
                    <CloudOutlined style={{ marginRight: 8, color: '#0ea5e9' }} />云资源动态调度
                </Title>
                <Space>
                    <Tag color="#10b981" style={{ borderRadius: 20 }}><WifiOutlined /> 运行中云实例 {dashboard?.running_instances || 0}</Tag>
                    {activeTab === 'instances' && (
                        <>
                            <Button type="primary" icon={<PlusOutlined />} onClick={instanceState.openModal}>手动弹容</Button>
                            <Popconfirm
                                title="确认清理所有已终止/错误的实例记录？"
                                description="只会软删除当前可访问云账号下的终止或错误记录，不会销毁运行中的云实例。"
                                onConfirm={instanceState.cleanup}
                                okText="确认清理"
                                cancelText="取消"
                            >
                                <Button danger icon={<DeleteOutlined />} disabled={instanceState.cleanupCandidateCount === 0}>一键清理 ({instanceState.cleanupCandidateCount})</Button>
                            </Popconfirm>
                            <Button icon={<ReloadOutlined />} onClick={instanceState.fetchInstances} loading={instanceState.loading}>刷新</Button>
                        </>
                    )}
                    {activeTab === 'credentials' && <Button type="primary" icon={<PlusOutlined />} onClick={accountState.openAddModal}>添加凭证</Button>}
                </Space>
            </div>

            <ProCard className="glass-card cloud-animate-in" style={{ background: 'transparent', border: 'none', position: 'relative', zIndex: 1 }} bodyStyle={{ padding: 0 }}>
                <Tabs
                    activeKey={activeTab}
                    onChange={setActiveTab}
                    style={{ padding: '0 20px' }}
                    items={[
                        {
                            key: 'instances',
                            label: <span><AppstoreOutlined /> 实例状态追踪</span>,
                            children: <CloudInstancesPanel loading={instanceState.loading} instances={instanceState.instances} onReboot={instanceState.reboot} onDelete={instanceState.remove} />,
                        },
                        { key: 'policy', label: <span><SettingOutlined /> AutoScaler 策略</span>, forceRender: true, children: policyTabContent },
                        {
                            key: 'credentials',
                            label: <span><KeyOutlined /> API 凭证管理</span>,
                            children: (
                                <CloudAccountsPanel
                                    accounts={accountState.accounts}
                                    isAdmin={isAdmin}
                                    canManage={accountState.canManage}
                                    onOneClick={accountId => discoveryState.ensureRegionThen(accountId, 'oneclick')}
                                    onPermissions={discoveryState.checkPermissions}
                                    onDiscover={accountId => discoveryState.ensureRegionThen(accountId, 'discover')}
                                    onTest={accountState.testAccount}
                                    onBindings={accountState.openBindings}
                                    onDelete={accountState.deleteAccount}
                                />
                            ),
                        },
                        { key: 'agent-dist', label: <span><CloudUploadOutlined /> Agent 分发</span>, children: <CloudAgentDistributionPanel accounts={accountState.accounts} onUpload={ossState.openUpload} onTest={ossState.test} /> },
                    ]}
                />
            </ProCard>

            <CloudInstanceCreateModal
                open={instanceState.modalOpen}
                form={instanceState.form}
                accounts={accountState.accounts}
                policies={policyState.policies}
                region={instanceState.region}
                regions={instanceState.regions}
                regionsLoading={instanceState.regionsLoading}
                availableTypes={instanceState.availableTypes}
                typesLoading={instanceState.typesLoading}
                selectedInstanceType={instanceState.selectedInstanceType}
                priceData={instanceState.priceData}
                priceLoading={instanceState.priceLoading}
                onSubmit={instanceState.create}
                onCancel={() => instanceState.setModalOpen(false)}
                onAccountChange={instanceState.changeAccount}
                onRegionChange={instanceState.changeRegion}
                onInstanceTypeChange={instanceState.changeInstanceType}
            />
            <AddCloudAccountModal open={accountState.addModalOpen} form={accountState.form} isAdmin={isAdmin} users={accountState.users} onSubmit={accountState.addAccount} onCancel={() => accountState.setAddModalOpen(false)} onLoadUsers={accountState.fetchUsers} />
            <CloudAccountBindingModal open={accountState.bindingModalOpen} account={accountState.bindingAccount} userIds={accountState.bindingUserIds} users={accountState.users} saving={accountState.bindingSaving} onChange={accountState.setBindingUserIds} onSubmit={accountState.saveBindings} onCancel={() => accountState.setBindingModalOpen(false)} />
            <CloudDiscoveryModal open={discoveryState.modalOpen} loading={discoveryState.loading} saving={discoveryState.saving} data={discoveryState.data} form={discoveryState.form} onSubmit={discoveryState.save} onCancel={() => discoveryState.setModalOpen(false)} />
            <CloudSetupResultModal open={discoveryState.setupResultOpen} result={discoveryState.setupResult} onClose={() => discoveryState.setSetupResultOpen(false)} />
            <CloudPermissionDrawer open={discoveryState.permissionOpen} loading={discoveryState.permissionLoading} error={discoveryState.permissionError} data={discoveryState.permissionData} onClose={() => discoveryState.setPermissionOpen(false)} />
            <CloudOSSTestModal open={ossState.testModalOpen} loading={ossState.testLoading} result={ossState.testResult} onClose={() => ossState.setTestModalOpen(false)} />
            <CloudAgentUploadModal
                open={ossState.uploadOpen}
                mode={ossState.mode}
                releaseFiles={ossState.releaseFiles}
                releaseFilesLoading={ossState.releaseFilesLoading}
                selectedReleaseFiles={ossState.selectedReleaseFiles}
                serverUploading={ossState.serverUploading}
                localFiles={ossState.localFiles}
                localUploading={ossState.localUploading}
                localUploadProgress={ossState.localUploadProgress}
                onClose={ossState.closeUpload}
                onModeChange={ossState.changeMode}
                onSelectedReleaseFilesChange={ossState.setSelectedReleaseFiles}
                onServerUpload={ossState.uploadServer}
                onLocalFilesChange={ossState.setLocalFiles}
                onLocalUpload={ossState.uploadLocal}
                onClearLocalFiles={() => { ossState.setLocalFiles([]); ossState.setLocalUploadProgress(0); }}
            />
            <CloudRegionSelectModal open={discoveryState.regionOpen} loading={discoveryState.regionLoading} regions={discoveryState.regions} onSelect={discoveryState.selectRegion} onClose={() => discoveryState.setRegionOpen(false)} />
        </div>
    );
};

export default CloudManagement;
