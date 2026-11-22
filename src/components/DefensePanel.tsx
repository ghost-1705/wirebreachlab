import { useState } from 'react';
import { AlertTriangle, Flame, ShieldAlert, ShieldCheck } from 'lucide-react';
import { DEFENSE_DEFINITIONS, SCENARIOS } from '../data/scenarios';
import {
  ArpEntry,
  DefenseKey,
  DefenseState,
  DnsCacheEntry,
  FirewallEvent,
  ScenarioId,
  TopologyId,
} from '../types/simulator';

interface DefensePanelProps {
  activeScenario: ScenarioId;
  topologyId: TopologyId;
  defenses: DefenseState;
  onToggleDefense: (key: DefenseKey) => void;
  firewallPlaced: boolean;
  onToggleFirewallPlaced: () => void;
  onApplyAllDefenses: (enabled: boolean) => void;
  arpTable: ArpEntry[];
  dnsCache: DnsCacheEntry[];
  portScanResults: { port: number; service: string; state: 'open' | 'closed' | 'filtered' }[];
  firewallEvents: FirewallEvent[];
}

export function DefensePanel({
  activeScenario,
  topologyId,
  defenses,
  onToggleDefense,
  firewallPlaced,
  onToggleFirewallPlaced,
  onApplyAllDefenses,
  arpTable,
  dnsCache,
  portScanResults,
  firewallEvents,
}: DefensePanelProps) {
  const [showAllDefenses, setShowAllDefenses] = useState(false);
  const primaryKey = SCENARIOS[activeScenario].primaryDefense;
  const isFirewallSession = activeScenario === 'all-out-defense' || topologyId === 'firewall-sandbox';
  const activeRuleCount = Object.values(defenses).filter(Boolean).length;
  const allRulesActive = activeRuleCount === DEFENSE_DEFINITIONS.length;

  const orderedDefenses = [...DEFENSE_DEFINITIONS].sort((a, b) => {
    if (a.key === primaryKey) return -1;
    if (b.key === primaryKey) return 1;
    return 0;
  });

  const showExpandedList = showAllDefenses || activeScenario === 'all-out-defense';
  const visibleDefenses = showExpandedList
    ? orderedDefenses
    : orderedDefenses.filter((d) => d.key === primaryKey || defenses[d.key]);

  return (
    <div className="h-full overflow-y-auto p-4 space-y-5 bg-[#0F172A]">
      {isFirewallSession && (
        <div
          className={`p-3.5 rounded-md border space-y-3 ${
            firewallPlaced
              ? allRulesActive
                ? 'bg-emerald-950/20 border-emerald-500/40'
                : 'bg-[#131C2E] border-sky-500/40'
              : 'bg-amber-950/20 border-amber-500/40'
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                {firewallPlaced ? (
                  <Flame className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                )}
                <h3 className="text-xs font-semibold text-slate-100">
                  Perimeter Firewall Placement &amp; Policy
                </h3>
              </div>
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                {firewallPlaced
                  ? 'Firewall is inline between the Edge Router and Core L2 Switch. Apply rules below to filter active vectors.'
                  : 'Firewall is currently bypassed. Traffic flows directly from Edge Router to Core L2 Switch unfiltered.'}
              </p>
            </div>
            <span
              className={`font-mono text-[11px] font-semibold tabular-nums whitespace-nowrap shrink-0 ${
                firewallPlaced ? 'text-emerald-400' : 'text-amber-300'
              }`}
            >
              {firewallPlaced ? 'INLINE' : 'BYPASSED'}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={onToggleFirewallPlaced}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                firewallPlaced
                  ? 'bg-[#1B263B] text-slate-200 border border-[#334663] hover:bg-[#243247]'
                  : 'bg-amber-600 text-white hover:bg-amber-500'
              }`}
            >
              {firewallPlaced ? 'Bypass Firewall' : 'Place Firewall Inline'}
            </button>

            <button
              type="button"
              onClick={() => onApplyAllDefenses(!allRulesActive)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                allRulesActive
                  ? 'bg-[#1B263B] text-slate-200 border border-[#334663] hover:bg-[#243247]'
                  : 'bg-emerald-600 text-white hover:bg-emerald-500'
              }`}
            >
              {allRulesActive ? 'Clear All Rules' : `Apply All ${DEFENSE_DEFINITIONS.length} Rules`}
            </button>

            <span className="ml-auto font-mono text-[11px] text-slate-400 tabular-nums">
              {activeRuleCount}/{DEFENSE_DEFINITIONS.length} active
            </span>
          </div>

          {!firewallPlaced && activeRuleCount > 0 && (
            <p className="text-[11px] text-amber-300 bg-amber-950/40 border border-amber-500/30 rounded px-2.5 py-1.5">
              {activeRuleCount} rule{activeRuleCount === 1 ? ' is' : 's are'} staged, but traffic still bypasses the firewall until you place it inline.
            </p>
          )}
        </div>
      )}

      {/* Blue-Team Mitigation Switches */}
      <div className="space-y-2.5">
        <div className="flex items-start justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Blue-Team Defense Controls</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Toggle mitigations mid-attack to watch real-time interception.
            </p>
          </div>
          {activeScenario !== 'all-out-defense' && (
            <div className="flex items-center p-0.5 bg-[#0B1120] border border-[#243247] rounded-md shrink-0">
              <button
                type="button"
                onClick={() => setShowAllDefenses(false)}
                className={`px-2 py-1 text-[11px] font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                  !showAllDefenses ? 'bg-[#1E2B42] text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Active Lab
              </button>
              <button
                type="button"
                onClick={() => setShowAllDefenses(true)}
                className={`px-2 py-1 text-[11px] font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                  showAllDefenses ? 'bg-[#1E2B42] text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                All {DEFENSE_DEFINITIONS.length}
              </button>
            </div>
          )}
        </div>

        <div className="space-y-2">
          {visibleDefenses.map((def) => {
            const enabled = defenses[def.key];
            const isPrimary = def.key === primaryKey;
            return (
              <div
                key={def.key}
                className={`p-3 rounded-md border transition-colors ${
                  enabled
                    ? 'bg-emerald-950/25 border-emerald-500/40'
                    : isPrimary
                    ? 'bg-[#162238] border-sky-500/40'
                    : 'bg-[#131C2E] border-[#243247]'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      {enabled ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-slate-400 shrink-0" />
                      )}
                      <span className="text-xs font-semibold text-slate-100">{def.name}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      {def.enforcedBy}
                      {isPrimary ? ' · Recommended for current scenario' : ''}
                    </p>
                    <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">{def.description}</p>
                  </div>

                  <button
                    type="button"
                    role="switch"
                    aria-checked={enabled}
                    onClick={() => onToggleDefense(def.key)}
                    className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
                      enabled
                        ? 'bg-emerald-600 text-white hover:bg-emerald-500'
                        : 'bg-[#1B263B] text-slate-200 border border-[#334663] hover:bg-[#243247]'
                    }`}
                  >
                    {enabled ? 'Enabled' : 'Enable'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live ARP Cache Table */}
      <div className="space-y-2 pt-3 border-t border-[#243247]">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold text-slate-200">Host ARP Cache Table</h4>
          <span className="text-[11px] font-mono text-slate-500">Layer 2 Bindings</span>
        </div>
        <div className="border border-[#243247] rounded-md overflow-hidden bg-[#0B1120]">
          <table className="w-full text-left border-collapse font-mono text-[11px]">
            <thead className="bg-[#131C2E] border-b border-[#243247] text-slate-400">
              <tr>
                <th className="py-1.5 px-2.5 font-medium">IP Address</th>
                <th className="py-1.5 px-2.5 font-medium">MAC Address</th>
                <th className="py-1.5 px-2.5 font-medium text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#182235]">
              {arpTable.map((row) => (
                <tr key={row.ip} className={row.status === 'poisoned' ? 'bg-amber-950/30' : undefined}>
                  <td className="py-1.5 px-2.5 text-slate-200 tabular-nums">{row.ip}</td>
                  <td className="py-1.5 px-2.5 text-slate-300 tabular-nums">{row.mac}</td>
                  <td
                    className={`py-1.5 px-2.5 text-right font-semibold ${
                      row.status === 'poisoned' ? 'text-amber-300' : 'text-emerald-400'
                    }`}
                  >
                    {row.status === 'poisoned' ? 'POISONED' : 'VALID'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Live DNS Resolver Cache */}
      <div className="space-y-2 pt-3 border-t border-[#243247]">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold text-slate-200">DNS Resolver Cache</h4>
          <span className="text-[11px] font-mono text-slate-500">A-Records</span>
        </div>
        <div className="border border-[#243247] rounded-md overflow-hidden bg-[#0B1120]">
          <table className="w-full text-left border-collapse font-mono text-[11px]">
            <thead className="bg-[#131C2E] border-b border-[#243247] text-slate-400">
              <tr>
                <th className="py-1.5 px-2.5 font-medium">Domain</th>
                <th className="py-1.5 px-2.5 font-medium">Resolved IP</th>
                <th className="py-1.5 px-2.5 font-medium text-right">Trust</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#182235]">
              {dnsCache.map((row) => (
                <tr key={row.domain} className={row.status === 'spoofed' ? 'bg-amber-950/30' : undefined}>
                  <td className="py-1.5 px-2.5 text-slate-200">{row.domain}</td>
                  <td className="py-1.5 px-2.5 text-slate-300 tabular-nums">{row.ip}</td>
                  <td
                    className={`py-1.5 px-2.5 text-right font-semibold ${
                      row.status === 'spoofed' ? 'text-amber-300' : 'text-emerald-400'
                    }`}
                  >
                    {row.status === 'spoofed' ? 'SPOOFED' : 'VERIFIED'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Nmap Port Recon Table (shown once scanned) */}
      {portScanResults.length > 0 && (
        <div className="space-y-2 pt-3 border-t border-[#243247]">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-slate-200">Discovered Port Map</h4>
            <span className="text-[11px] font-mono text-slate-500">Nmap Recon</span>
          </div>
          <div className="border border-[#243247] rounded-md overflow-hidden bg-[#0B1120]">
            <table className="w-full text-left border-collapse font-mono text-[11px]">
              <thead className="bg-[#131C2E] border-b border-[#243247] text-slate-400">
                <tr>
                  <th className="py-1.5 px-2.5 font-medium">Port</th>
                  <th className="py-1.5 px-2.5 font-medium">Service</th>
                  <th className="py-1.5 px-2.5 font-medium text-right">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182235]">
                {portScanResults.map((row) => (
                  <tr key={row.port}>
                    <td className="py-1.5 px-2.5 text-slate-200 tabular-nums">{row.port}/tcp</td>
                    <td className="py-1.5 px-2.5 text-slate-300">{row.service}</td>
                    <td
                      className={`py-1.5 px-2.5 text-right font-semibold ${
                        row.state === 'open'
                          ? 'text-amber-300'
                          : row.state === 'filtered'
                          ? 'text-emerald-400'
                          : 'text-slate-400'
                      }`}
                    >
                      {row.state.toUpperCase()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Firewall / IDS Drop Log */}
      <div className="space-y-2 pt-3 border-t border-[#243247]">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold text-slate-200">Security Policy & Drop Log</h4>
          <span className="text-[11px] font-mono text-slate-500 tabular-nums">
            {firewallEvents.length} events
          </span>
        </div>
        {firewallEvents.length === 0 ? (
          <p className="text-xs text-slate-500 py-3">
            No blocked events yet. Enable a defense control while an attack is running to log real-time interceptions.
          </p>
        ) : (
          <div className="space-y-1.5">
            {firewallEvents.slice(0, 12).map((ev) => (
              <div
                key={ev.id}
                className="p-2 rounded bg-[#0B1120] border border-[#1E2B40] font-mono text-[11px] space-y-0.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-emerald-400 font-semibold">
                    {ev.action} · {ev.rule}
                  </span>
                  <span className="text-slate-500 tabular-nums">{ev.timestamp}</span>
                </div>
                <div className="text-slate-300 break-all">{ev.detail}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
