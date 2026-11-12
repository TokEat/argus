import { Tabs } from 'antd';
import { useLocation, useNavigate } from 'react-router-dom';
import DirConfig from './DirConfig';
import BehaviorProbeConfig from './BehaviorProbeConfig';
import DirProbeConfig from './DirProbeConfig';
import WorkflowConfig from './WorkflowConfig';

const sections = [
    { key: '/config/active-finger', label: '被动规则' },
    { key: '/config/behavior-probe', label: '行为探针' },
    { key: '/config/dir', label: '路径探针' },
    { key: '/config/workflow', label: 'Workflow / POC 关联' },
];

export default function ProductRulesConfig() {
    const location = useLocation();
    const navigate = useNavigate();
    const current = sections.some((item) => item.key === location.pathname) ? location.pathname : sections[0].key;
    const content = current === '/config/behavior-probe' ? <BehaviorProbeConfig />
        : current === '/config/dir' ? <DirProbeConfig />
            : current === '/config/workflow' ? <WorkflowConfig /> : <DirConfig />;
    return <><Tabs activeKey={current} items={sections} onChange={navigate} />{content}</>;
}
