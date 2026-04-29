import React, { useRef, useEffect, useCallback } from 'react';
import gsap from 'gsap';

/* ── Types ── */
interface AgentNode {
  AgentID: string;
  Status: string;
  RunningTasks: number;
  Capacity: number;
  RunningTaskIDs?: string;
  RunningTaskIds?: string;
  IP?: string;
}

interface QueueDepthInfo {
  depth: Record<string, number>;
  pending: Record<string, number>;
  mode: string;
  ready_batches?: number;
  pending_batches?: number;
}

interface Particle {
  id: string;
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
  progress: number;
  speed: number;
  label: string;
  color: string;
}

interface NodeState {
  x: number;
  y: number;
  radius: number;
  pulsePhase: number;
  glowIntensity: number;
  agent: AgentNode;
  taskCount: number;
  active: boolean;
}

interface Props {
  nodes: AgentNode[];
  wsMessages: { time: string; type: string; data: string }[];
  queueDepth: QueueDepthInfo | null;
}

const sumValues = (obj?: Record<string, number>) =>
  Object.values(obj || {}).reduce((a, b) => a + b, 0);

const DispatchCanvas: React.FC<Props> = ({ nodes, wsMessages, queueDepth }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const nodeStates = useRef<NodeState[]>([]);
  const particles = useRef<Particle[]>([]);
  const hubPulse = useRef(0);
  const time = useRef(0);
  const dpr = useRef(1);
  const prevMsgLen = useRef(0);
  const lastAnimId = useRef(0);

  const activeNodes = nodes.filter(n => n.Status === 'Alive');

  const totalQueued = sumValues(queueDepth?.depth);
  const totalPending = sumValues(queueDepth?.pending);

  /* ── Layout nodes in a semicircle on the right side ── */
  const layoutNodes = useCallback((w: number, h: number) => {
    const cx = w * 0.32;
    const cy = h * 0.5;
    const count = activeNodes.length;
    if (count === 0) return;

    const arcRadius = Math.min(w * 0.28, h * 0.38);
    const nodeRadius = Math.min(22, arcRadius * 0.15);

    const startAngle = -Math.PI * 0.45;
    const endAngle = Math.PI * 0.45;

    nodeStates.current = activeNodes.map((node, i) => {
      const angle = count === 1
        ? 0
        : startAngle + (endAngle - startAngle) * (i / (count - 1));
      let taskIds: string[] = [];
      try {
        const raw = node.RunningTaskIDs || node.RunningTaskIds || '[]';
        taskIds = JSON.parse(raw);
      } catch {}
      return {
        x: cx + arcRadius * Math.cos(angle),
        y: cy + arcRadius * Math.sin(angle),
        radius: nodeRadius,
        pulsePhase: Math.random() * Math.PI * 2,
        glowIntensity: taskIds.length > 0 ? 0.8 : 0.2,
        agent: node,
        taskCount: taskIds.length,
        active: taskIds.length > 0,
      };
    });
  }, [activeNodes]);

  /* ── Spawn particles on WS task_claimed ── */
  useEffect(() => {
    if (wsMessages.length === 0 || wsMessages.length === prevMsgLen.current) return;
    prevMsgLen.current = wsMessages.length;

    const latest = wsMessages[0];
    if (latest.type !== 'task_claimed') return;

    try {
      const data = JSON.parse(latest.data);
      if (!data.agent_id) return;
      const target = nodeStates.current.find(n => n.agent.AgentID === data.agent_id);
      if (!target) return;

      const canvas = canvasRef.current;
      if (!canvas) return;
      const w = canvas.width / dpr.current;
      const h = canvas.height / dpr.current;
      const cx = w * 0.32;
      const cy = h * 0.5;

      const colors = ['#10b981', '#0ea5e9', '#8b5cf6', '#f59e0b', '#ef4444'];
      const color = colors[Math.floor(Math.random() * colors.length)];

      particles.current.push({
        id: String(lastAnimId.current++),
        fromX: cx,
        fromY: cy,
        toX: target.x,
        toY: target.y,
        progress: 0,
        speed: 0.015 + Math.random() * 0.01,
        label: (data.task_id || '').slice(0, 6),
        color,
      });
    } catch {}
  }, [wsMessages]);

  /* ── Also spawn ambient particles for idle agents periodically ── */
  useEffect(() => {
    const interval = setInterval(() => {
      if (nodeStates.current.length === 0) return;
      const canvas = canvasRef.current;
      if (!canvas) return;
      const w = canvas.width / dpr.current;
      const h = canvas.height / dpr.current;
      const cx = w * 0.32;
      const cy = h * 0.5;

      // Pick a random active node for an ambient pulse
      const active = nodeStates.current.filter(n => n.active);
      if (active.length === 0) return;
      const target = active[Math.floor(Math.random() * active.length)];

      particles.current.push({
        id: String(lastAnimId.current++),
        fromX: cx,
        fromY: cy,
        toX: target.x,
        toY: target.y,
        progress: 0,
        speed: 0.008 + Math.random() * 0.006,
        label: '',
        color: 'rgba(14, 165, 233, 0.5)',
      });
    }, 2200);
    return () => clearInterval(interval);
  }, []);

  /* ── Canvas resize ── */
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

    layoutNodes(rect.width, rect.height);
  }, [layoutNodes]);

  useEffect(() => {
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, [resize]);

  useEffect(() => {
    resize();
  }, [activeNodes.length, resize]);

  /* ── GSAP ticker: main render loop ── */
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const draw = () => {
      const w = canvas.width / dpr.current;
      const h = canvas.height / dpr.current;
      const cx = w * 0.32;
      const cy = h * 0.5;

      ctx.save();
      ctx.scale(dpr.current, dpr.current);
      ctx.clearRect(0, 0, w, h);

      time.current += 0.016;
      const t = time.current;

      /* ── Background grid ── */
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.06)';
      ctx.lineWidth = 0.5;
      const gridSize = 32;
      for (let x = 0; x < w; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let y = 0; y < h; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }

      /* ── Connection lines (dashed, animated) ── */
      nodeStates.current.forEach((node, i) => {
        const angle = Math.atan2(node.y - cy, node.x - cx);
        const hubEdgeX = cx + 38 * Math.cos(angle);
        const hubEdgeY = cy + 38 * Math.sin(angle);
        const nodeEdgeX = node.x - node.radius * Math.cos(angle);
        const nodeEdgeY = node.y - node.radius * Math.sin(angle);

        // Animated dash offset
        const dashOffset = -t * 40 + i * 20;

        ctx.save();
        ctx.setLineDash([4, 6]);
        ctx.lineDashOffset = dashOffset;
        ctx.strokeStyle = node.active
          ? 'rgba(14, 165, 233, 0.35)'
          : 'rgba(148, 163, 184, 0.15)';
        ctx.lineWidth = node.active ? 1.5 : 1;
        ctx.beginPath();
        ctx.moveTo(hubEdgeX, hubEdgeY);

        // Bezier curve for nicer path
        const cpx = (hubEdgeX + nodeEdgeX) / 2 + (cy - hubEdgeY) * 0.15;
        const cpy = (hubEdgeY + nodeEdgeY) / 2 + (nodeEdgeX - hubEdgeX) * 0.15;
        ctx.quadraticCurveTo(cpx, cpy, nodeEdgeX, nodeEdgeY);
        ctx.stroke();
        ctx.restore();
      });

      /* ── Hub (queue center) ── */
      hubPulse.current += 0.03;
      const hubGlow = 0.3 + Math.sin(hubPulse.current) * 0.15;

      // Outer ring glow
      const hubGrad = ctx.createRadialGradient(cx, cy, 28, cx, cy, 60);
      hubGrad.addColorStop(0, `rgba(139, 92, 246, ${hubGlow * 0.4})`);
      hubGrad.addColorStop(1, 'rgba(139, 92, 246, 0)');
      ctx.fillStyle = hubGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, 60, 0, Math.PI * 2);
      ctx.fill();

      // Rotating ring
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(t * 0.5);
      ctx.strokeStyle = `rgba(139, 92, 246, ${hubGlow})`;
      ctx.lineWidth = 1.5;
      ctx.setLineDash([8, 12]);
      ctx.lineDashOffset = -t * 30;
      ctx.beginPath();
      ctx.arc(0, 0, 42, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      // Hub body
      const hubBodyGrad = ctx.createRadialGradient(cx - 6, cy - 6, 4, cx, cy, 36);
      hubBodyGrad.addColorStop(0, '#a78bfa');
      hubBodyGrad.addColorStop(1, '#7c3aed');
      ctx.fillStyle = hubBodyGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, 36, 0, Math.PI * 2);
      ctx.fill();

      // Hub inner highlight
      ctx.fillStyle = 'rgba(255, 255, 255, 0.12)';
      ctx.beginPath();
      ctx.arc(cx - 8, cy - 8, 16, 0, Math.PI * 2);
      ctx.fill();

      // Hub text
      ctx.fillStyle = '#fff';
      ctx.font = 'bold 11px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('QUEUE', cx, cy - 6);
      ctx.font = 'bold 13px Inter, sans-serif';
      ctx.fillText(String(totalQueued), cx, cy + 10);

      /* ── Agent Nodes ── */
      nodeStates.current.forEach((node) => {
        const { x, y, radius, active: isActive } = node;
        node.pulsePhase += 0.02;

        // Pulse ring for active nodes
        if (isActive) {
          const pulseScale = 1 + Math.sin(node.pulsePhase) * 0.15;
          const pulseAlpha = 0.3 - Math.sin(node.pulsePhase) * 0.15;
          const pulseGrad = ctx.createRadialGradient(x, y, radius, x, y, radius * pulseScale * 1.8);
          pulseGrad.addColorStop(0, `rgba(16, 185, 129, ${pulseAlpha})`);
          pulseGrad.addColorStop(1, 'rgba(16, 185, 129, 0)');
          ctx.fillStyle = pulseGrad;
          ctx.beginPath();
          ctx.arc(x, y, radius * pulseScale * 1.8, 0, Math.PI * 2);
          ctx.fill();
        }

        // Outer glow
        const outerGlow = ctx.createRadialGradient(x, y, radius * 0.8, x, y, radius * 1.6);
        outerGlow.addColorStop(0, isActive ? 'rgba(14, 165, 233, 0.15)' : 'rgba(148, 163, 184, 0.08)');
        outerGlow.addColorStop(1, 'rgba(0, 0, 0, 0)');
        ctx.fillStyle = outerGlow;
        ctx.beginPath();
        ctx.arc(x, y, radius * 1.6, 0, Math.PI * 2);
        ctx.fill();

        // Node body
        const nodeGrad = ctx.createRadialGradient(x - 3, y - 3, 2, x, y, radius);
        if (isActive) {
          nodeGrad.addColorStop(0, '#38bdf8');
          nodeGrad.addColorStop(1, '#0284c7');
        } else {
          nodeGrad.addColorStop(0, '#cbd5e1');
          nodeGrad.addColorStop(1, '#94a3b8');
        }
        ctx.fillStyle = nodeGrad;
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fill();

        // Node border ring
        ctx.strokeStyle = isActive ? 'rgba(14, 165, 233, 0.5)' : 'rgba(148, 163, 184, 0.3)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(x, y, radius + 2, 0, Math.PI * 2);
        ctx.stroke();

        // Inner highlight
        ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
        ctx.beginPath();
        ctx.arc(x - 4, y - 4, radius * 0.4, 0, Math.PI * 2);
        ctx.fill();

        // Agent label
        ctx.fillStyle = '#fff';
        ctx.font = `bold ${Math.max(9, radius * 0.5)}px Inter, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const shortId = node.agent.AgentID.length > 8
          ? node.agent.AgentID.slice(0, 8)
          : node.agent.AgentID;
        ctx.fillText(shortId, x, y - 2);

        // Task count badge
        if (node.taskCount > 0) {
          ctx.fillStyle = '#10b981';
          ctx.beginPath();
          ctx.arc(x + radius * 0.7, y - radius * 0.7, 7, 0, Math.PI * 2);
          ctx.fill();
          ctx.fillStyle = '#fff';
          ctx.font = 'bold 8px Inter, sans-serif';
          ctx.fillText(String(node.taskCount), x + radius * 0.7, y - radius * 0.7 + 0.5);
        }

        // Label below node
        ctx.fillStyle = isActive ? '#0ea5e9' : '#94a3b8';
        ctx.font = '10px Inter, sans-serif';
        ctx.textAlign = 'center';
        const label = node.agent.AgentID.length > 14
          ? node.agent.AgentID.slice(0, 14) + '…'
          : node.agent.AgentID;
        ctx.fillText(label, x, y + radius + 14);

        // Capacity bar
        const barW = radius * 2;
        const barH = 3;
        const barX = x - barW / 2;
        const barY = y + radius + 20;
        const ratio = node.agent.Capacity > 0
          ? node.agent.RunningTasks / node.agent.Capacity
          : 0;
        ctx.fillStyle = 'rgba(148, 163, 184, 0.15)';
        ctx.fillRect(barX, barY, barW, barH);
        ctx.fillStyle = isActive ? '#0ea5e9' : '#cbd5e1';
        ctx.fillRect(barX, barY, barW * Math.min(ratio, 1), barH);
      });

      /* ── Particles ── */
      particles.current = particles.current.filter(p => {
        p.progress += p.speed;
        if (p.progress >= 1) return false;

        // Quadratic bezier position
        const midX = (p.fromX + p.toX) / 2;
        const midY = (p.fromY + p.toY) / 2;
        const cpX = midX + (p.fromY - p.toY) * 0.15;
        const cpY = midY + (p.toX - p.fromX) * 0.15;

        const u = 1 - p.progress;
        const px = u * u * p.fromX + 2 * u * p.progress * cpX + p.progress * p.progress * p.toX;
        const py = u * u * p.fromY + 2 * u * p.progress * cpY + p.progress * p.progress * p.toY;

        // Particle trail
        const trailLen = 5;
        for (let j = 0; j < trailLen; j++) {
          const tp = Math.max(0, p.progress - j * 0.03);
          const tu = 1 - tp;
          const tx = tu * tu * p.fromX + 2 * tu * tp * cpX + tp * tp * p.toX;
          const ty = tu * tu * p.fromY + 2 * tu * tp * cpY + tp * tp * p.toY;
          const alpha = (1 - j / trailLen) * (1 - p.progress * 0.5);

          ctx.fillStyle = p.color.startsWith('rgba')
            ? p.color.replace(/[\d.]+\)$/, `${alpha * 0.6})`)
            : p.color;
          ctx.globalAlpha = alpha * 0.6;
          ctx.beginPath();
          ctx.arc(tx, ty, 2.5 - j * 0.3, 0, Math.PI * 2);
          ctx.fill();
        }

        // Main particle
        ctx.globalAlpha = 1 - p.progress * 0.3;
        const particleGrad = ctx.createRadialGradient(px, py, 0, px, py, 5);
        particleGrad.addColorStop(0, '#fff');
        particleGrad.addColorStop(0.5, p.color);
        particleGrad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = particleGrad;
        ctx.beginPath();
        ctx.arc(px, py, 5, 0, Math.PI * 2);
        ctx.fill();

        // Particle label
        if (p.label) {
          ctx.globalAlpha = 1 - p.progress;
          ctx.fillStyle = '#fff';
          ctx.font = 'bold 8px Inter, monospace';
          ctx.textAlign = 'center';
          ctx.fillText(p.label, px, py - 10);
        }

        ctx.globalAlpha = 1;
        return true;
      });

      /* ── Floating scan lines ── */
      const scanY = (t * 30) % h;
      ctx.strokeStyle = 'rgba(14, 165, 233, 0.04)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, scanY);
      ctx.lineTo(w, scanY);
      ctx.stroke();

      ctx.restore();
    };

    const ticker = () => {
      draw();
    };

    gsap.ticker.add(ticker);
    return () => {
      gsap.ticker.remove(ticker);
    };
  }, [totalQueued, activeNodes]);

  return (
    <div
      ref={containerRef}
      style={{
        width: '100%',
        height: '100%',
        position: 'relative',
        borderRadius: 8,
        overflow: 'hidden',
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)',
      }}
    >
      <canvas
        ref={canvasRef}
        style={{
          display: 'block',
          width: '100%',
          height: '100%',
        }}
      />
      {/* Queue stats overlay (bottom-left) */}
      <div style={{
        position: 'absolute',
        bottom: 12,
        left: 12,
        display: 'flex',
        gap: 8,
        pointerEvents: 'none',
      }}>
        <div style={{
          padding: '4px 10px',
          borderRadius: 6,
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          color: '#f87171',
          fontSize: 11,
          fontWeight: 600,
          fontFamily: "'JetBrains Mono', monospace",
        }}>
          QUEUED {totalQueued}
        </div>
        <div style={{
          padding: '4px 10px',
          borderRadius: 6,
          background: 'rgba(14, 165, 233, 0.15)',
          border: '1px solid rgba(14, 165, 233, 0.25)',
          color: '#38bdf8',
          fontSize: 11,
          fontWeight: 600,
          fontFamily: "'JetBrains Mono', monospace",
        }}>
          RUNNING {totalPending}
        </div>
      </div>
      {/* Node count overlay (bottom-right) */}
      <div style={{
        position: 'absolute',
        bottom: 12,
        right: 12,
        padding: '4px 10px',
        borderRadius: 6,
        background: 'rgba(139, 92, 246, 0.15)',
        border: '1px solid rgba(139, 92, 246, 0.25)',
        color: '#a78bfa',
        fontSize: 11,
        fontWeight: 600,
        fontFamily: "'JetBrains Mono', monospace",
        pointerEvents: 'none',
      }}>
        AGENTS {activeNodes.length}
      </div>
    </div>
  );
};

export default DispatchCanvas;
