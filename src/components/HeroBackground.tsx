import React, { useEffect, useRef } from 'react';

export const HeroBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener('resize', handleResize);

    // Nodes for cyber neural grid
    const nodeCount = Math.floor((width * height) / 35000);
    const nodes: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      pulse: number;
    }> = [];

    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 1.5 + 1,
        pulse: Math.random() * Math.PI
      });
    }

    let radarAngle = 0;

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // Faint radial background gradient
      const bgGrad = ctx.createRadialGradient(
        width * 0.5,
        height * 0.15,
        20,
        width * 0.5,
        height * 0.5,
        width * 0.8
      );
      bgGrad.addColorStop(0, 'rgba(34, 211, 238, 0.04)');
      bgGrad.addColorStop(0.5, 'rgba(139, 92, 246, 0.02)');
      bgGrad.addColorStop(1, 'rgba(10, 14, 23, 0)');
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, width, height);

      // Radar beam sweep in upper center
      radarAngle += 0.007;
      const radarCenterX = width * 0.5;
      const radarCenterY = 120;
      const radarRadius = Math.min(width * 0.4, 380);

      // Sweep arc
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(radarCenterX, radarCenterY);
      ctx.arc(radarCenterX, radarCenterY, radarRadius, radarAngle, radarAngle + 0.35);
      ctx.closePath();
      const sweepGrad = ctx.createRadialGradient(
        radarCenterX,
        radarCenterY,
        0,
        radarCenterX,
        radarCenterY,
        radarRadius
      );
      sweepGrad.addColorStop(0, 'rgba(34, 211, 238, 0.07)');
      sweepGrad.addColorStop(1, 'rgba(34, 211, 238, 0.0)');
      ctx.fillStyle = sweepGrad;
      ctx.fill();

      // Faint concentric range rings
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.03)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(radarCenterX, radarCenterY, radarRadius * 0.33, 0, Math.PI * 2);
      ctx.arc(radarCenterX, radarCenterY, radarRadius * 0.66, 0, Math.PI * 2);
      ctx.arc(radarCenterX, radarCenterY, radarRadius, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      // Update & draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;
        n.pulse += 0.02;

        if (n.x < 0) n.x = width;
        if (n.x > width) n.x = 0;
        if (n.y < 0) n.y = height;
        if (n.y > height) n.y = 0;

        // Draw connections
        for (let j = i + 1; j < nodes.length; j++) {
          const n2 = nodes[j];
          const dx = n.x - n2.x;
          const dy = n.y - n2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 110) {
            const alpha = (1 - dist / 110) * 0.08;
            ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
            ctx.lineWidth = 0.7;
            ctx.beginPath();
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.stroke();
          }
        }

        // Draw node
        const currentAlpha = 0.15 + Math.sin(n.pulse) * 0.1;
        ctx.fillStyle = `rgba(34, 211, 238, ${currentAlpha})`;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0 opacity-80"
      aria-hidden="true"
    />
  );
};
