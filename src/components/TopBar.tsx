import { SCENARIO_CATEGORIES } from '../data/scenarios';
import { ScenarioCategory } from '../types/simulator';

interface TopBarProps {
  activeCategory: ScenarioCategory;
  onSelectCategory: (category: ScenarioCategory) => void;
  onResetLab: () => void;
}

export function TopBar({ activeCategory, onSelectCategory, onResetLab }: TopBarProps) {
  return (
    <header className="h-14 shrink-0 border-b border-[#243247] bg-[#0F172A] px-6 flex items-center justify-between gap-8">
      {/* Zone 1: Single-element display wordmark */}
      <a
        href="#workspace"
        onClick={(e) => {
          e.preventDefault();
          onSelectCategory('mitm');
        }}
        className="font-display text-lg font-bold tracking-tight text-slate-50 whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 rounded-sm"
      >
        WireBreach Lab
      </a>

      {/* Zone 2: 3 concise single-line attack category navigation links */}
      <nav aria-label="Attack categories" className="hidden md:flex items-center gap-8">
        {SCENARIO_CATEGORIES.map((cat) => {
          const isActive = cat.id === activeCategory;
          return (
            <button
              key={cat.id}
              type="button"
              onClick={() => onSelectCategory(cat.id)}
              className={`relative py-4 text-sm font-medium transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
                isActive ? 'text-sky-300' : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              {cat.label}
              {isActive && (
                <span className="absolute inset-x-0 bottom-0 h-0.5 bg-sky-400" aria-hidden="true" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Zone 3: 1 primary action */}
      <div className="flex items-center shrink-0">
        <button
          type="button"
          onClick={onResetLab}
          className="px-4 py-2 text-xs font-semibold text-slate-100 bg-[#1B263B] hover:bg-[#243247] border border-[#334663] rounded-md transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          Reset Lab
        </button>
      </div>
    </header>
  );
}
