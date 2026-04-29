import React, { useRef, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import gsap from 'gsap';

const PageTransition: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const ref = useRef<HTMLDivElement>(null);
  const location = useLocation();

  useEffect(() => {
    if (!ref.current) return;

    const tween = gsap.from(ref.current, {
      opacity: 0,
      y: 14,
      duration: 0.32,
      ease: 'power2.out',
      clearProps: 'all',
    });

    return () => { tween.kill(); };
  }, [location.pathname]);

  return <div ref={ref}>{children}</div>;
};

export default PageTransition;
