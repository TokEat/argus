import { cleanup, screen } from '@testing-library/react';
import { message } from 'antd';
import { afterEach, describe, expect, it } from 'vitest';
import './react19AntdPatch';

// React 19 下 antd v5 静态方法默认渲染链路会静默失效（toast 不渲染、
// 请求无反馈），此处保证补丁挂载后静态 message 真实可见。
describe('react19AntdPatch', () => {
    afterEach(cleanup);

    it('static message renders a visible toast', async () => {
        message.info('连通性测试通过');
        expect(await screen.findByText('连通性测试通过', {}, { timeout: 3000 })).toBeInTheDocument();
        message.destroy();
    });
});
