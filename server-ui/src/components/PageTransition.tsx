import React from 'react';
import { useLocation } from 'react-router-dom';

const PageTransition: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();

  return <div key={location.pathname} className="page-container">{children}</div>;
};

export default PageTransition;
