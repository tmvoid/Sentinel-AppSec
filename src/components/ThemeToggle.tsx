import React from 'react';
import { Moon, Sun } from 'lucide-react';

export type ThemeMode = 'dark' | 'bright';

interface ThemeToggleProps {
  theme: ThemeMode;
  onChange: (next: ThemeMode) => void;
}

/**
 * Premium Precision-Machined Dark / Bright Polarity Switch
 * Features an animated specular thumb, rotational Sun/Moon micro-choreography,
 * and glassmorphic housing that adapts to Obsidian (Dark) and Alabaster (Bright) modes.
 */
export const ThemeToggle: React.FC<ThemeToggleProps> = ({
  theme,
  onChange,
}) => {
  const isBright = theme === 'bright';

  return (
    <div
      role="group"
      aria-label="Interface color theme switcher"
      className={`relative inline-flex h-8 items-center rounded-full p-0.5 transition-all duration-300 select-none shrink-0 ${
        isBright
          ? 'bg-slate-200/85 border border-slate-900/12 shadow-[inset_0_1px_2px_rgba(15,23,42,0.08),0_1px_2px_rgba(255,255,255,0.9)]'
          : 'bg-[#050913]/90 border border-white/[0.14] shadow-[inset_0_1px_3px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.08)]'
      } backdrop-blur-xl`}
    >
      {/* Animated Sliding Specular Thumb */}
      <span
        aria-hidden="true"
        className={`pointer-events-none absolute top-0.5 bottom-0.5 w-[calc(50%-2px)] rounded-full transition-all duration-300 ease-[cubic-bezier(0.22,1,0.36,1)] ${
          isBright
            ? 'translate-x-full bg-gradient-to-b from-white to-slate-50 shadow-[0_2px_8px_rgba(15,23,42,0.14),inset_0_1px_0_#FFFFFF] border border-slate-900/8'
            : 'translate-x-0 bg-gradient-to-b from-[#0E2242] to-[#08152C] shadow-[0_2px_10px_rgba(0,120,212,0.45),inset_0_1px_0_rgba(125,211,252,0.35)] border border-[#38BDF8]/35'
        }`}
      />

      {/* Dark (Obsidian) Segment */}
      <button
        type="button"
        onClick={() => onChange('dark')}
        aria-pressed={!isBright}
        title="Switch to Obsidian Dark Mode"
        className={`relative z-10 flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-mono font-semibold tracking-tight transition-colors duration-200 whitespace-nowrap ${
          !isBright
            ? 'text-white'
            : 'text-slate-600 hover:text-slate-900'
        }`}
      >
        <Moon
          className={`h-3 w-3 transition-transform duration-300 ${
            !isBright
              ? 'text-[#38BDF8] rotate-0 scale-100'
              : 'text-slate-500 -rotate-12 scale-90'
          }`}
        />
        <span>Dark</span>
      </button>

      {/* Bright (Alabaster) Segment */}
      <button
        type="button"
        onClick={() => onChange('bright')}
        aria-pressed={isBright}
        title="Switch to Alabaster Bright Mode"
        className={`relative z-10 flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-mono font-semibold tracking-tight transition-colors duration-200 whitespace-nowrap ${
          isBright
            ? 'text-slate-900'
            : 'text-[#94A3B8] hover:text-white'
        }`}
      >
        <Sun
          className={`h-3 w-3 transition-transform duration-300 ${
            isBright
              ? 'text-[#0078D4] rotate-0 scale-100'
              : 'text-[#94A3B8] rotate-45 scale-90'
          }`}
        />
        <span>Bright</span>
      </button>
    </div>
  );
};
