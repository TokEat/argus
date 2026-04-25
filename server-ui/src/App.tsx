import React from 'react';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import { ConfigProvider, App as AntApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import routes from './routes';

const router = createBrowserRouter(routes);

import { GlobalAIProvider } from './contexts/GlobalAIContext';

const App: React.FC = () => {
  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#0ea5e9',
          borderRadius: 8,
          fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
        },
      }}
    >
      <GlobalAIProvider>
        <AntApp>
          <RouterProvider router={router} />
        </AntApp>
      </GlobalAIProvider>
    </ConfigProvider>
  );
};

export default App;
