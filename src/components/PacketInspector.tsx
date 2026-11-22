import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Search, Trash2 } from 'lucide-react';
import { AttackMetricsState, PacketCategory, ProtocolType, SimulatedPacket } from '../types/simulator';
import { AttackMetricsWidget } from './AttackMetricsWidget';

interface PacketInspectorProps {
  packets: SimulatedPacket[];
  selectedPacket: SimulatedPacket | null;
  onSelectPacket: (id: string) => void;
  onClearCapture: () => void;
  attackMetrics: AttackMetricsState;
  isPaused: boolean;
  attackActive: boolean;
}

const PROTOCOL_FILTERS: ('ALL' | ProtocolType)[] = [
  'ALL',
  'TCP',
  'UDP',
  'HTTP',
  'HTTPS',
  'ARP',
  'DNS',
  'ICMP',
  'SMTP',
  'NTP',
  'WIFI',
  'SQL',
];

function categoryMeta(category: PacketCategory): { label: string; textClass: string } {
  switch (category) {
    case 'attack':
      return { label: 'ATTACK', textClass: 'text-red-400' };
    case 'spoof':
      return { label: 'SPOOF', textClass: 'text-amber-300' };
    case 'blocked':
      return { label: 'BLOCKED', textClass: 'text-emerald-400' };
    case 'response':
      return { label: 'REPLY', textClass: 'text-indigo-300' };
    default:
      return { label: 'NORMAL', textClass: 'text-sky-300' };
  }
}

export function PacketInspector({
  packets,
  selectedPacket,
  onSelectPacket,
  onClearCapture,
  attackMetrics,
  isPaused,
  attackActive,
}: PacketInspectorProps) {
  const [protoFilter, setProtoFilter] = useState<'ALL' | ProtocolType>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [metricsExpanded, setMetricsExpanded] = useState(true);
  const [openLayers, setOpenLayers] = useState<Record<string, boolean>>({
    l2: true,
    l3: true,
    l4: true,
    l7: true,
    hex: true,
  });

  const filteredPackets = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return packets.filter((pkt) => {
      if (protoFilter !== 'ALL' && pkt.protocol !== protoFilter) return false;
      if (!q) return true;
      return (
        pkt.srcIp.toLowerCase().includes(q) ||
        pkt.dstIp.toLowerCase().includes(q) ||
        pkt.summary.toLowerCase().includes(q) ||
        pkt.protocol.toLowerCase().includes(q) ||
        pkt.rawPayload.toLowerCase().includes(q) ||
        pkt.shortTag.toLowerCase().includes(q)
      );
    });
  }, [packets, protoFilter, searchQuery]);

  const toggleLayer = (key: string) => {
    setOpenLayers((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Real-Time Attack Telemetry Widget (Collapsible Strip) */}
      <AttackMetricsWidget
        metrics={attackMetrics}
        isPaused={isPaused}
        attackActive={attackActive}
        isExpanded={metricsExpanded}
        onToggleExpand={() => setMetricsExpanded((prev) => !prev)}
      />

      {/* Filter Toolbar */}
      <div className="px-4 py-2.5 border-b border-[#243247] bg-[#131C2E] space-y-2 shrink-0">
        <div className="flex items-center gap-2">
          <div className="relative flex-1 min-w-0">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by IP, port, flag, or payload..."
              aria-label="Filter captured packets"
              className="w-full pl-8 pr-3 py-1.5 bg-[#0B1120] border border-[#243247] rounded-md text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>
          <button
            type="button"
            onClick={onClearCapture}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-300 bg-[#1B263B] hover:bg-[#243247] border border-[#2D3E58] rounded-md transition-colors cursor-pointer shrink-0 whitespace-nowrap"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear
          </button>
        </div>

        {/* Protocol segmented filter */}
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1 overflow-x-auto">
            {PROTOCOL_FILTERS.map((proto) => {
              const active = protoFilter === proto;
              return (
                <button
                  key={proto}
                  type="button"
                  onClick={() => setProtoFilter(proto)}
                  className={`px-2 py-0.5 text-[11px] font-mono rounded transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                    active
                      ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                      : 'text-slate-400 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  {proto}
                </button>
              );
            })}
          </div>
          <span className="text-[11px] font-mono text-slate-500 tabular-nums shrink-0">
            {filteredPackets.length} frames
          </span>
        </div>
      </div>

      {/* Live Packet Capture Table */}
      <div
        className={`${
          metricsExpanded ? 'h-[28%] min-h-[120px]' : 'h-[42%] min-h-[175px]'
        } overflow-y-auto border-b border-[#243247] bg-[#0B1120] shrink-0 transition-[height] duration-150`}
      >
        {filteredPackets.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center p-6 text-center">
            <p className="text-sm font-medium text-slate-300">No packets matching filter</p>
            <p className="text-xs text-slate-500 mt-1 max-w-xs">
              Start an attack or run a terminal command like ping, dig, or nmap to capture live frames.
            </p>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 z-10 bg-[#131C2E] border-b border-[#243247] text-[11px] font-mono text-slate-400">
              <tr>
                <th className="py-1.5 pl-3 pr-2 font-medium w-10">#</th>
                <th className="py-1.5 px-2 font-medium w-14">Proto</th>
                <th className="py-1.5 px-2 font-medium">Source → Dest</th>
                <th className="py-1.5 pl-2 pr-3 font-medium text-right w-20">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#182235] font-mono text-[11px]">
              {filteredPackets.map((pkt) => {
                const isSelected = selectedPacket?.id === pkt.id;
                const meta = categoryMeta(pkt.category);
                return (
                  <tr
                    key={pkt.id}
                    onClick={() => onSelectPacket(pkt.id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-sky-500/15 text-slate-50'
                        : 'hover:bg-[#131C2E] text-slate-300'
                    }`}
                  >
                    <td className="py-1.5 pl-3 pr-2 text-slate-500 tabular-nums">{pkt.seqNo}</td>
                    <td className="py-1.5 px-2 font-semibold text-slate-200">{pkt.protocol}</td>
                    <td className="py-1.5 px-2 max-w-[200px] truncate">
                      <span className="tabular-nums">{pkt.srcIp}</span>
                      <span className="text-slate-500 mx-1">→</span>
                      <span className="tabular-nums">{pkt.dstIp}</span>
                      <div className="text-[10px] text-slate-400 truncate font-sans">{pkt.summary}</div>
                    </td>
                    <td className={`py-1.5 pl-2 pr-3 text-right font-semibold ${meta.textClass}`}>
                      {meta.label}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Layered OSI Payload Dissector */}
      <div className="flex-1 overflow-y-auto bg-[#0F172A] p-4 space-y-3 min-h-0">
        {!selectedPacket ? (
          <div className="h-full flex flex-col items-center justify-center text-center py-8">
            <p className="text-sm font-medium text-slate-300">Select a packet to inspect its payload</p>
            <p className="text-xs text-slate-500 mt-1 max-w-xs">
              Click any animated packet moving along the network cables or select any row in the capture table above.
            </p>
          </div>
        ) : (
          <>
            {/* Selected Packet Header Summary (Zero-pill clean text) */}
            <div className="pb-2.5 border-b border-[#243247] space-y-1">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-semibold text-slate-100">
                  Frame #{selectedPacket.seqNo} · {selectedPacket.protocol}
                </h3>
                <span className={`font-mono text-xs font-semibold ${categoryMeta(selectedPacket.category).textClass}`}>
                  {categoryMeta(selectedPacket.category).label}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono tabular-nums">
                {selectedPacket.timestamp} · {selectedPacket.lengthBytes} bytes · {selectedPacket.status.toUpperCase()}
              </p>
            </div>

            {/* Security Context Educational Note (clean hairline container, no border-l-4) */}
            <div
              className={`p-3 rounded-md border text-xs leading-relaxed ${
                selectedPacket.category === 'blocked'
                  ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-100'
                  : selectedPacket.category === 'attack'
                  ? 'bg-red-950/30 border-red-500/30 text-red-100'
                  : selectedPacket.category === 'spoof'
                  ? 'bg-amber-950/30 border-amber-500/30 text-amber-100'
                  : 'bg-[#131C2E] border-[#243247] text-slate-300'
              }`}
            >
              <div className="font-semibold mb-1 text-[11px] text-slate-200">
                Security Analysis
              </div>
              <p>{selectedPacket.educationalNote}</p>
              {selectedPacket.dropReason && (
                <p className="mt-1.5 font-mono text-[11px] text-emerald-300">
                  Policy Action: {selectedPacket.dropReason}
                </p>
              )}
            </div>

            {/* OSI Layers Accordion */}
            <div className="space-y-1.5">
              {(['l2', 'l3', 'l4', 'l7'] as const).map((layerKey) => {
                const layer = selectedPacket.layers[layerKey];
                if (!layer) return null;
                const isOpen = openLayers[layerKey];
                return (
                  <div key={layerKey} className="border border-[#243247] rounded-md bg-[#131C2E] overflow-hidden">
                    <button
                      type="button"
                      onClick={() => toggleLayer(layerKey)}
                      className="w-full flex items-center justify-between px-3 py-2 text-left text-xs font-medium text-slate-200 hover:bg-[#1A253B] transition-colors cursor-pointer"
                    >
                      <span className="flex items-center gap-1.5">
                        {isOpen ? (
                          <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                        )}
                        {layer.title}
                      </span>
                      <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                        {layer.fields.length} fields
                      </span>
                    </button>
                    {isOpen && (
                      <div className="px-3 pb-2.5 pt-1 border-t border-[#1E2B40] space-y-1 bg-[#0D1526]">
                        {layer.fields.map((field) => (
                          <div
                            key={field.label}
                            className="flex items-baseline justify-between gap-3 text-[11px] font-mono"
                          >
                            <span className="text-slate-400 shrink-0">{field.label}:</span>
                            <span
                              className={`text-right break-all tabular-nums ${
                                field.highlight === 'attack'
                                  ? 'text-red-300 font-semibold'
                                  : field.highlight === 'spoof'
                                  ? 'text-amber-300 font-semibold'
                                  : field.highlight === 'blocked'
                                  ? 'text-emerald-300 font-semibold'
                                  : 'text-slate-200'
                              }`}
                            >
                              {field.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Hex + ASCII Byte Dump */}
              <div className="border border-[#243247] rounded-md bg-[#131C2E] overflow-hidden">
                <button
                  type="button"
                  onClick={() => toggleLayer('hex')}
                  className="w-full flex items-center justify-between px-3 py-2 text-left text-xs font-medium text-slate-200 hover:bg-[#1A253B] transition-colors cursor-pointer"
                >
                  <span className="flex items-center gap-1.5">
                    {openLayers.hex ? (
                      <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                    )}
                    Raw Payload Hex & ASCII Dump
                  </span>
                  <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                    {selectedPacket.lengthBytes} B
                  </span>
                </button>
                {openLayers.hex && (
                  <div className="px-3 py-2.5 border-t border-[#1E2B40] bg-[#090F1D] overflow-x-auto">
                    <pre className="font-mono text-[10.5px] leading-relaxed text-slate-300 tabular-nums">
                      {selectedPacket.hexLines.map((row) => (
                        <div key={row.offset} className="flex gap-3">
                          <span className="text-slate-500 select-none">{row.offset}</span>
                          <span className="text-sky-300/90">{row.hex}</span>
                          <span className="text-slate-400">{row.ascii}</span>
                        </div>
                      ))}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
