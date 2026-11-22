import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Gauge,
  ShieldCheck,
} from 'lucide-react';
import { AttackMetricsState } from '../types/simulator';

interface AttackMetricsWidgetProps {
  metrics: AttackMetricsState;
  isPaused: boolean;
  attackActive: boolean;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
}

export function AttackMetricsWidget({
  metrics,
  isPaused,
  attackActive,
  isExpanded: controlledExpanded,
  onToggleExpand,
}: AttackMetricsWidgetProps) {
  const [internalExpanded, setInternalExpanded] = useState(true);
  const isExpanded = controlledExpanded ?? internalExpanded;
  const handleToggle = onToggleExpand ?? (() => setInternalExpanded((prev) => !prev));

  const history = metrics.history;
  const maxPpsInWindow = Math.max(
    6,
    ...history.map((h) => h.pps),
    metrics.pps
  );
  const maxEventsInWindow = Math.max(
    2,
    ...history.map((h) => Math.max(h.exploitsDelta, h.blockedDelta))
  );

  const svgWidth = 320;
  const svgHeight = 56;
  const padY = 4;
  const plotHeight = svgHeight - padY * 2;
  const stepX = history.length > 1 ? svgWidth / (history.length - 1) : svgWidth;

  const ppsPoints = history.map((sample, idx) => {
    const x = idx * stepX;
    const y = padY + plotHeight - (sample.pps / maxPpsInWindow) * plotHeight;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const bwPoints = history.map((sample, idx) => {
    const x = idx * stepX;
    const y = padY + plotHeight - (sample.bandwidthPct / 100) * plotHeight;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const ppsLinePath = ppsPoints.length > 0 ? `M ${ppsPoints.join(' L ')}` : '';
  const ppsAreaPath =
    ppsPoints.length > 1
      ? `${ppsLinePath} L ${svgWidth},${svgHeight} L 0,${svgHeight} Z`
      : '';
  const bwLinePath = bwPoints.length > 0 ? `M ${bwPoints.join(' L ')}` : '';

  const latestSample = history[history.length - 1];
  const latestExploitRate = latestSample?.exploitsDelta ?? 0;

  const bandwidthState =
    metrics.bandwidthPct >= 75
      ? { label: 'Saturated', textClass: 'text-red-400', barClass: 'bg-red-500' }
      : metrics.bandwidthPct >= 35
      ? { label: 'Elevated', textClass: 'text-amber-300', barClass: 'bg-amber-400' }
      : { label: 'Nominal', textClass: 'text-sky-300', barClass: 'bg-sky-400' };

  const exploitState =
    metrics.successfulExploits > 0
      ? {
          label: latestExploitRate > 0 ? 'Breach Active' : 'Compromised',
          textClass: 'text-red-400',
        }
      : { label: '0 Landed', textClass: 'text-slate-400' };

  const defenseTotal = metrics.blockedPackets + metrics.successfulExploits;
  const defenseState =
    metrics.blockedPackets > 0 && metrics.mitigationRatePct >= 70
      ? { label: 'Protected', textClass: 'text-emerald-400' }
      : metrics.blockedPackets > 0
      ? { label: 'Partial', textClass: 'text-amber-300' }
      : defenseTotal > 0
      ? { label: 'Unprotected', textClass: 'text-red-400' }
      : { label: 'Standby', textClass: 'text-slate-400' };

  return (
    <section
      aria-label="Real-time attack telemetry"
      className="border-b border-[#243247] bg-[#0D1526] shrink-0"
    >
      {/* Collapsible Header Strip */}
      <button
        type="button"
        onClick={handleToggle}
        aria-expanded={isExpanded}
        className="w-full px-4 py-2 bg-[#131C2E] hover:bg-[#172238] border-b border-[#243247]/70 flex items-center justify-between gap-3 text-left transition-colors cursor-pointer"
      >
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-100 whitespace-nowrap shrink-0">
          {isExpanded ? (
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
          )}
          Attack Telemetry
        </span>

        <span className="font-mono text-[11px] text-slate-400 tabular-nums truncate">
          <span className="text-sky-300">{metrics.pps} PPS</span>
          <span className="mx-1.5 text-slate-600">·</span>
          <span className={bandwidthState.textClass}>{metrics.bandwidthPct}% BW</span>
          <span className="mx-1.5 text-slate-600">·</span>
          <span className={metrics.successfulExploits > 0 ? 'text-red-400' : 'text-slate-300'}>
            {metrics.successfulExploits} Exploits
          </span>
          <span className="mx-1.5 text-slate-600">·</span>
          <span className={metrics.blockedPackets > 0 ? 'text-emerald-400' : 'text-slate-400'}>
            {metrics.mitigationRatePct}% Mitigated
          </span>
        </span>
      </button>

      {/* Expanded Dashboard Body */}
      {isExpanded && (
        <div className="px-3.5 py-2.5 space-y-2.5">
          {/* 2x2 KPI Counters */}
          <div className="grid grid-cols-2 gap-2">
            {/* 1. Packets Per Second */}
            <div className="px-2.5 py-2 rounded-md bg-[#111A2E] border border-[#223048]">
              <div className="flex items-center justify-between gap-1 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1 whitespace-nowrap">
                  <Activity className="w-3 h-3 text-sky-400" />
                  Packets / Sec
                </span>
                <span className={`font-mono text-[10px] ${isPaused ? 'text-amber-300' : attackActive ? 'text-sky-300' : 'text-slate-400'}`}>
                  {isPaused ? 'Paused' : attackActive ? 'Burst' : 'Live'}
                </span>
              </div>
              <div className="mt-1 flex items-baseline justify-between gap-2">
                <span className="font-mono text-sm font-semibold text-sky-300 tabular-nums">
                  {metrics.pps} <span className="text-[11px] font-normal text-slate-400">PPS</span>
                </span>
                <span className="font-mono text-[10px] text-slate-400 tabular-nums">
                  Peak {metrics.peakPps} · {metrics.totalPackets}
                </span>
              </div>
            </div>

            {/* 2. Bandwidth Utilization */}
            <div className="px-2.5 py-2 rounded-md bg-[#111A2E] border border-[#223048]">
              <div className="flex items-center justify-between gap-1 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1 whitespace-nowrap">
                  <Gauge className="w-3 h-3 text-amber-300" />
                  Bandwidth Use
                </span>
                <span className={`font-mono text-[10px] ${bandwidthState.textClass}`}>
                  {bandwidthState.label}
                </span>
              </div>
              <div className="mt-1 flex items-baseline justify-between gap-2">
                <span className={`font-mono text-sm font-semibold tabular-nums ${bandwidthState.textClass}`}>
                  {metrics.bandwidthPct}%
                </span>
                <span className="font-mono text-[10px] text-slate-400 tabular-nums">
                  {metrics.kbps} Kbps
                </span>
              </div>
              <div className="mt-1.5 h-1 w-full bg-[#1B263B] rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${bandwidthState.barClass}`}
                  style={{ width: `${metrics.bandwidthPct}%` }}
                />
              </div>
            </div>

            {/* 3. Successful Exploits */}
            <div className="px-2.5 py-2 rounded-md bg-[#111A2E] border border-[#223048]">
              <div className="flex items-center justify-between gap-1 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1 whitespace-nowrap">
                  <AlertTriangle className="w-3 h-3 text-red-400" />
                  Exploits Landed
                </span>
                <span className={`font-mono text-[10px] ${exploitState.textClass}`}>
                  {exploitState.label}
                </span>
              </div>
              <div className="mt-1 flex items-baseline justify-between gap-2">
                <span
                  className={`font-mono text-sm font-semibold tabular-nums ${
                    metrics.successfulExploits > 0 ? 'text-red-400' : 'text-slate-200'
                  }`}
                >
                  {metrics.successfulExploits}
                </span>
                <span className="font-mono text-[10px] text-slate-400 tabular-nums">
                  {latestExploitRate > 0 ? `+${latestExploitRate}/s now` : 'Target hits'}
                </span>
              </div>
            </div>

            {/* 4. Blocked Packets & Defense Mitigation Rate */}
            <div className="px-2.5 py-2 rounded-md bg-[#111A2E] border border-[#223048]">
              <div className="flex items-center justify-between gap-1 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1 whitespace-nowrap">
                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                  Blocked & Rate
                </span>
                <span className={`font-mono text-[10px] ${defenseState.textClass}`}>
                  {defenseState.label}
                </span>
              </div>
              <div className="mt-1 flex items-baseline justify-between gap-2">
                <span className="font-mono text-sm font-semibold text-emerald-300 tabular-nums">
                  {metrics.blockedPackets}
                </span>
                <span className="font-mono text-[10px] text-slate-300 tabular-nums">
                  {metrics.mitigationRatePct}% mitigated
                </span>
              </div>
            </div>
          </div>

          {/* 24-Sample Rolling Sparkline Chart */}
          <div className="px-2.5 py-2 rounded-md bg-[#090F1D] border border-[#1E2B40]">
            <div className="flex items-center justify-between gap-2 mb-1.5 text-[10px] font-mono">
              <span className="text-slate-400">24s Throughput & Exploit Trend</span>
              <span className="flex items-center gap-2.5 text-slate-400 whitespace-nowrap">
                <span className="text-sky-300">PPS</span>
                <span className="text-amber-300">BW%</span>
                <span className="text-red-400">Exploit</span>
                <span className="text-emerald-400">Blocked</span>
              </span>
            </div>

            <svg
              viewBox={`0 0 ${svgWidth} ${svgHeight}`}
              preserveAspectRatio="none"
              className="w-full h-14 block overflow-visible"
              role="img"
              aria-label={`Live 24-second sparkline: ${metrics.pps} PPS, ${metrics.bandwidthPct}% bandwidth, ${metrics.successfulExploits} exploits, ${metrics.blockedPackets} blocked`}
            >
              <defs>
                <linearGradient id="ppsAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.28" />
                  <stop offset="100%" stopColor="#38BDF8" stopOpacity="0.02" />
                </linearGradient>
              </defs>

              {/* Subtle Reference Gridlines */}
              {[0.25, 0.5, 0.75].map((ratio) => {
                const y = padY + plotHeight * ratio;
                return (
                  <line
                    key={ratio}
                    x1={0}
                    y1={y}
                    x2={svgWidth}
                    y2={y}
                    stroke="#1E2B40"
                    strokeWidth="0.75"
                    strokeDasharray="2 3"
                  />
                );
              })}

              {/* Exploit & Blocked per-second impulse ticks along baseline */}
              {history.map((sample, idx) => {
                const x = idx * stepX;
                const exploitH =
                  sample.exploitsDelta > 0
                    ? Math.max(4, (sample.exploitsDelta / maxEventsInWindow) * 18)
                    : 0;
                const blockedH =
                  sample.blockedDelta > 0
                    ? Math.max(4, (sample.blockedDelta / maxEventsInWindow) * 18)
                    : 0;
                return (
                  <g key={idx}>
                    {exploitH > 0 && (
                      <rect
                        x={Math.max(0, x - 2)}
                        y={svgHeight - exploitH}
                        width={3.5}
                        height={exploitH}
                        fill="#EF4444"
                        fillOpacity="0.85"
                        rx={1}
                      />
                    )}
                    {blockedH > 0 && (
                      <rect
                        x={Math.min(svgWidth - 3.5, x + 2)}
                        y={svgHeight - blockedH}
                        width={3.5}
                        height={blockedH}
                        fill="#10B981"
                        fillOpacity="0.85"
                        rx={1}
                      />
                    )}
                  </g>
                );
              })}

              {/* Bandwidth % Dashed Overlay Line */}
              {bwLinePath && (
                <path
                  d={bwLinePath}
                  fill="none"
                  stroke="#F59E0B"
                  strokeWidth="1.25"
                  strokeDasharray="3 2"
                  strokeOpacity="0.85"
                />
              )}

              {/* PPS Area + Primary Line */}
              {ppsAreaPath && <path d={ppsAreaPath} fill="url(#ppsAreaGrad)" />}
              {ppsLinePath && (
                <path
                  d={ppsLinePath}
                  fill="none"
                  stroke="#38BDF8"
                  strokeWidth="1.75"
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              )}
            </svg>
          </div>
        </div>
      )}
    </section>
  );
}
