import { Form, Modal } from 'antd';
import type { FormInstance } from 'antd';
import ScanPolicyComposer, { scanPolicyInitialValues, type ScanPolicyFormValues } from './ScanPolicyComposer';

interface Props {
    open: boolean; creating: boolean; form: FormInstance<ScanPolicyFormValues>; projects: API.Project[];
    activeProjectId: string; plan: API.ScanPlanPreview | null;
    onPlanChange: (plan: API.ScanPlanPreview | null) => void; onCancel: () => void;
    onCreate: () => void; onDraftChange: () => void;
}

export default function ScanTaskCreateModal(props: Props) {
    return <Modal title="创建扫描任务" open={props.open} onCancel={props.onCancel} onOk={props.onCreate}
        okText="按此计划创建" confirmLoading={props.creating} okButtonProps={{ disabled: !props.plan }}
        width={1320} destroyOnHidden>
        <Form form={props.form} layout="vertical"
            initialValues={{ ...scanPolicyInitialValues, project_id: props.activeProjectId || undefined }}
            onValuesChange={() => { if (!props.creating) props.onDraftChange(); }}>
            <ScanPolicyComposer form={props.form} projects={props.projects} onPlanChange={props.onPlanChange} />
        </Form>
    </Modal>;
}
