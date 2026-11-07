import React, { useRef, useState } from 'react';

interface SpotlightCardProps {
  children: React.ReactNode;
  className?: string;
  spotlightColor?: string;
  onClick?: () => void;
}

/**
 * Translucent Glassmorphic Spotlight Card
 * Refracts the ReactBits MicroSlats WebGL background with a cursor-reactive specular sheen.
 */
export const SpotlightCard: React.FC<SpotlightCardProps> = ({
  children,
  className = '',
  spotlightColor = 'rgba(56, 189, 248, 0.12)',
  onClick,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [opacity, setOpacity] = useState(0);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setPosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  return (
    <div
      ref={containerRef}
      onClick={onClick}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setOpacity(1)}
      onMouseLeave={() => setOpacity(0)}
      className={`glass-panel relative overflow-hidden rounded-xl transition-all duration-150 ${
        onClick
          ? 'cursor-pointer hover:border-white/[0.22] hover:bg-[#101A30]/65'
          : ''
      } ${className}`}
    >
      <div
        className="pointer-events-none absolute -inset-px transition-opacity duration-200"
        style={{
          opacity,
          background: `radial-gradient(460px circle at ${position.x}px ${position.y}px, ${spotlightColor}, transparent 65%)`,
        }}
      />
      <div className="relative z-10">{children}</div>
    </div>
  );
};

interface DecryptedHeadingProps {
  text: string;
  className?: string;
}

export const BlurRevealHeading: React.FC<DecryptedHeadingProps> = ({
  text,
  className = '',
}) => {
  return (
    <h1
      className={`font-display tracking-tight text-white drop-shadow-[0_2px_12px_rgba(0,0,0,0.5)] transition-all duration-200 ${className}`}
    >
      {text}
    </h1>
  );
};
