import React, { useRef, useEffect, useCallback } from 'react';

interface Props {
  /** 粒子数量 (默认 60) */
  count?: number;
  /** 连线最大距离 (默认 150) */
  linkDist?: number;
  /** 主色调 (默认 '#0ea5e9') */
  color?: string;
  /** 粒子速度 (默认 0.3) */
  speed?: number;
  /** 是否显示中心辐射光环 */
  showRadial?: boolean;
  /** 容器样式 */
  style?: React.CSSProperties;
}

interface Dot {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  pulse: number;
}

const NetworkCanvas: React.FC<Props> = ({
  count = 60,
  linkDist = 150,
  color = '#0ea5e9',
  speed = 0.3,
  showRadial = false,
  style,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const dots = useRef<Dot[]>([]);
  const dpr = useRef(1);
  const time = useRef(0);

  /* Parse hex color to rgb */
  const hexToRgb = (hex: string) => {
    const m = hex.replace('#', '');
    return {
      r: parseInt(m.substring(0, 2), 16),
      g: parseInt(m.substring(2, 4), 16),
      b: parseInt(m.substring(4, 6), 16),
    };
  };

  const rgb = hexToRgb(color);

  /* Init dots */
  const initDots = (w: number, h: number) => {
    dots.current = Array.from({ length: count }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * speed,
      vy: (Math.random() - 0.5) * speed,
      r: 1.2 + Math.random() * 1.8,
      pulse: Math.random() * Math.PI * 2,
    }));
  };

  /* Resize */
  const resize = useCallback(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;
    const rect = container.getBoundingClientRect();
    dpr.current = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr.current;
    canvas.height = rect.height * dpr.current;
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;
    if (dots.current.length === 0) initDots(rect.width, rect.height);
  }, []);

  useEffect(() => {
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, [resize]);

  /* Render loop */
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const draw = () => {
      const w = canvas.width / dpr.current;
      const h = canvas.height / dpr.current;

      ctx.save();
      ctx.scale(dpr.current, dpr.current);
      ctx.clearRect(0, 0, w, h);

      time.current += 0.016;
      const t = time.current;

      /* Update & draw dots */
      dots.current.forEach((d) => {
        d.x += d.vx;
        d.y += d.vy;
        if (d.x < 0 || d.x > w) d.vx *= -1;
        if (d.y < 0 || d.y > h) d.vy *= -1;
        d.pulse += 0.02;

        const alpha = 0.3 + Math.sin(d.pulse) * 0.2;
        ctx.fillStyle = `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${alpha})`;
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.fill();
      });

      /* Draw links */
      for (let i = 0; i < dots.current.length; i++) {
        for (let j = i + 1; j < dots.current.length; j++) {
          const a = dots.current[i];
          const b = dots.current[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist > linkDist) continue;
          const alpha = (1 - dist / linkDist) * 0.15;
          ctx.strokeStyle = `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${alpha})`;
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      /* Center radial glow */
      if (showRadial) {
        const cx = w / 2;
        const cy = h / 2;
        const pulseR = 120 + Math.sin(t * 0.8) * 30;
        const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, pulseR);
        grad.addColorStop(0, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.08)`);
        grad.addColorStop(1, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0)`);
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(cx, cy, pulseR, 0, Math.PI * 2);
        ctx.fill();
      }

      ctx.restore();
    };

    let animationFrame = 0;
    const ticker = () => {
      draw();
      animationFrame = window.requestAnimationFrame(ticker);
    };
    animationFrame = window.requestAnimationFrame(ticker);
    return () => window.cancelAnimationFrame(animationFrame);
  }, [count, linkDist, speed, showRadial, rgb.r, rgb.g, rgb.b]);

  return (
    <div
      ref={containerRef}
      style={{
        position: 'absolute',
        inset: 0,
        overflow: 'hidden',
        pointerEvents: 'none',
        ...style,
      }}
    >
      <canvas
        ref={canvasRef}
        style={{ display: 'block', width: '100%', height: '100%' }}
      />
    </div>
  );
};

export default NetworkCanvas;
