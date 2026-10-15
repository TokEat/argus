import { unstableSetRender } from 'antd';
import * as React from 'react';
import { createRoot } from 'react-dom/client';

// React 19 移除了 ReactDOM.render/createRoot 主入口导出，antd v5 静态方法
// （message/notification/Modal.confirm）的默认渲染链路会静默失效，
// 按 antd 官方 React 19 兼容方案改挂 createRoot 渲染器。
type AntdReactRender = NonNullable<Parameters<typeof unstableSetRender>[0]>;
type PatchedContainer = Parameters<AntdReactRender>[1] & {
    __reactRoot?: ReturnType<typeof createRoot>;
};

const majorVersion = Number.parseInt(React.version.split('.')[0], 10);
if (majorVersion >= 19) {
    unstableSetRender((node, container: PatchedContainer) => {
        container.__reactRoot ||= createRoot(container);
        const root = container.__reactRoot;
        root.render(node);
        return () =>
            new Promise<void>((resolve) => {
                setTimeout(() => {
                    root.unmount();
                    resolve();
                }, 0);
            });
    });
}
