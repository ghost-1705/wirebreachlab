import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Flame,
  Pause,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  SkipForward,
  Square,
  Zap,
} from 'lucide-react';
import { DEFENSE_DEFINITIONS, SCENARIO_LIST, SCENARIOS } from '../data/scenarios';
import { TOPOLOGY_LIST } from '../data/topologies';
import {
  DefenseState,
  DeviceRole,
  DropEffect,
  NetworkLink,
  NetworkNode,
  PacketCategory,
  PlaybackSpeed,
  ScenarioId,
  SimulatedPacket,
  TopologyId,
} from '../types/simulator';
import { Device3DGraphic } from './Device3DGraphic';

interface TopologyCanvasProps {
  activeScenario: ScenarioId;
  onSelectScenario: (id: ScenarioId) => void;
  topologyId: TopologyId;
  nodes: NetworkNode[];
  links: NetworkLink[];
  selectedNodeId: string;
  onSelectNode: (id: string) => void;
  onMoveNode: (id: string, x: number, y: number) => void;
  onResetLayout: () => void;
  onSelectTopology: (id: TopologyId) => void;
  inFlightPackets: SimulatedPacket[];
  selectedPacketId: string | null;
  onSelectPacket: (id: string) => void;
  dropEffects: DropEffect[];
  defenses: DefenseState;
  firewallPlaced: boolean;
  onToggleFirewallPlaced: () => void;
  onApplyAllDefenses: (enabled: boolean) => void;
  arpPoisoned: boolean;
  dnsPoisoned: boolean;
  wifiEvilTwinActive: boolean;
  isPaused: boolean;
  onTogglePause: () => void;
  speed: PlaybackSpeed;
  onChangeSpeed: (s: PlaybackSpeed) => void;
  attackActive: boolean;
  onToggleAttack: () => void;
  onStepForward: () => void;
}

const VIEWBOX_W = 900;
const VIEWBOX_H = 430;

function getPacketStyle(category: PacketCategory): {
  fill: string;
  stroke: string;
  text: string;
} {
  switch (category) {
    case 'attack':
      return { fill: '#450A0A', stroke: '#F87171', text: '#FECACA' };
    case 'spoof':
      return { fill: '#451A03', stroke: '#FBBF24', text: '#FDE68A' };
    case 'blocked':
      return { fill: '#052E16', stroke: '#34D399', text: '#A7F3D0' };
    case 'response':
      return { fill: '#1E1B4B', stroke: '#A5B4FC', text: '#E0E7FF' };
    default:
      return { fill: '#0C2D48', stroke: '#38BDF8', text: '#BAE6FD' };
  }
}

function isNodeDefended(role: DeviceRole, defenses: DefenseState, firewallPlaced: boolean): boolean {
  if (
    role === 'firewall' &&
    firewallPlaced &&
    (defenses.synCookies ||
      defenses.wafParameterizedSql ||
      defenses.firewallPortFilter ||
      defenses.l7HttpRateLimit ||
      defenses.udpRateLimit ||
      defenses.icmpRateLimit ||
      defenses.urpfIpFiltering ||
      defenses.ntpMonlistDisable ||
      defenses.dynamicArpInspection ||
      defenses.dnssecValidation ||
      defenses.vpnWpa3Encryption ||
      defenses.hstsCertPinning ||
      defenses.spfDkimDmarc)
  ) {
    return true;
  }
  if (role === 'router' && defenses.urpfIpFiltering) return true;
  if (role === 'switch' && defenses.dynamicArpInspection) return true;
  if (role === 'webserver' && (defenses.synCookies || defenses.wafParameterizedSql || defenses.l7HttpRateLimit)) return true;
  if (role === 'dns' && defenses.dnssecValidation) return true;
  if (role === 'wifi_ap' && defenses.vpnWpa3Encryption) return true;
  if (role === 'client' && (defenses.vpnWpa3Encryption || defenses.hstsCertPinning)) return true;
  if (role === 'mail' && defenses.spfDkimDmarc) return true;
  if (role === 'ntp' && defenses.ntpMonlistDisable) return true;
  return false;
}

export function TopologyCanvas({
  activeScenario,
  onSelectScenario,
  topologyId,
  nodes,
  links,
  selectedNodeId,
  onSelectNode,
  onMoveNode,
  onResetLayout,
  onSelectTopology,
  inFlightPackets,
  selectedPacketId,
  onSelectPacket,
  dropEffects,
  defenses,
  firewallPlaced,
  onToggleFirewallPlaced,
  onApplyAllDefenses,
  arpPoisoned,
  dnsPoisoned,
  wifiEvilTwinActive,
  isPaused,
  onTogglePause,
  speed,
  onChangeSpeed,
  attackActive,
  onToggleAttack,
  onStepForward,
}: TopologyCanvasProps) {
  const stageOuterRef = useRef<HTMLDivElement | null>(null);
  const stageInnerRef = useRef<HTMLDivElement | null>(null);
  const [stageScale, setStageScale] = useState(1);
  const [draggingId, setDraggingId] = useState<string | null>(null);
  const dragOffsetRef = useRef<{ dx: number; dy: number; moved: boolean }>({ dx: 0, dy: 0, moved: false });

  useEffect(() => {
    const el = stageOuterRef.current;
    if (!el) return;
    const updateScale = () => {
      const { width, height } = el.getBoundingClientRect();
      if (width > 0 && height > 0) {
        setStageScale(Math.max(0.35, Math.min(width / VIEWBOX_W, height / VIEWBOX_H)));
      }
    };
    updateScale();
    const ro = new ResizeObserver(updateScale);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const toStageCoords = useCallback((clientX: number, clientY: number) => {
    const inner = stageInnerRef.current;
    if (!inner) return { x: 0, y: 0 };
    const rect = inner.getBoundingClientRect();
    const x = ((clientX - rect.left) / rect.width) * VIEWBOX_W;
    const y = ((clientY - rect.top) / rect.height) * VIEWBOX_H;
    return { x, y };
  }, []);

  const handleNodePointerDown = (e: React.PointerEvent, node: NetworkNode) => {
    e.stopPropagation();
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
    const pt = toStageCoords(e.clientX, e.clientY);
    dragOffsetRef.current = { dx: pt.x - node.x, dy: pt.y - node.y, moved: false };
    setDraggingId(node.id);
    onSelectNode(node.id);
  };

  const handleStagePointerMove = (e: React.PointerEvent) => {
    if (!draggingId) return;
    const pt = toStageCoords(e.clientX, e.clientY);
    dragOffsetRef.current.moved = true;
    onMoveNode(draggingId, pt.x - dragOffsetRef.current.dx, pt.y - dragOffsetRef.current.dy);
  };

  const handleStagePointerUp = () => {
    if (draggingId) {
      setDraggingId(null);
    }
  };

  const depthSortedNodes = useMemo(
    () => [...nodes].sort((a, b) => a.y - b.y),
    [nodes]
  );

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const scenario = SCENARIOS[activeScenario];
  const categoryScenarios = SCENARIO_LIST.filter((s) => s.category === scenario.category);
  const loadLabel = scenario.loadMeterLabel ?? 'SYN Queue';
  const activeDefenseCount = Object.values(defenses).filter(Boolean).length;
  const allDefensesApplied = activeDefenseCount === DEFENSE_DEFINITIONS.length;
  const isFirewallSession = activeScenario === 'all-out-defense' || topologyId === 'firewall-sandbox';
  const routerNode = nodeMap.get('router');
  const switchNode = nodeMap.get('switch');
  const hasFirewallNode = nodeMap.has('firewall');

  return (
    <section
      aria-label="Interactive network topology"
      className="flex-1 min-h-0 flex flex-col bg-[#0F172A] border border-[#243247] rounded-lg overflow-hidden"
    >
      {/* Row 1: Attack Scenario Selector Strip for the Active Category */}
      <div className="flex items-center justify-between gap-3 px-4 py-2 border-b border-[#1E2B40] bg-[#10182B] overflow-x-auto">
        <div className="flex items-center gap-1.5">
          {categoryScenarios.map((sc) => {
            const active = sc.id === activeScenario;
            return (
              <button
                key={sc.id}
                type="button"
                onClick={() => onSelectScenario(sc.id)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? 'bg-sky-500/20 text-sky-200 border border-sky-500/40'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-[#19243A] border border-transparent'
                }`}
              >
                {sc.shortLabel}
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {isFirewallSession && hasFirewallNode && (
            <>
              <button
                type="button"
                onClick={onToggleFirewallPlaced}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer ${
                  firewallPlaced
                    ? 'bg-emerald-500/15 text-emerald-200 border border-emerald-500/40 hover:bg-emerald-500/25'
                    : 'bg-amber-500/20 text-amber-200 border border-amber-500/45 hover:bg-amber-500/30'
                }`}
              >
                {firewallPlaced ? <Flame className="w-3.5 h-3.5 text-emerald-400" /> : <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />}
                {firewallPlaced ? 'Firewall Inline' : 'Place Firewall'}
              </button>

              <button
                type="button"
                onClick={() => onApplyAllDefenses(!allDefensesApplied)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer ${
                  allDefensesApplied
                    ? 'bg-emerald-600 text-white hover:bg-emerald-500'
                    : 'bg-[#1B263B] text-slate-200 border border-[#2D3E58] hover:bg-[#243247]'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                {allDefensesApplied ? `All ${DEFENSE_DEFINITIONS.length} Rules Active` : 'Apply All Rules'}
              </button>
            </>
          )}

          <span className="hidden xl:inline text-[11px] font-mono text-slate-400 whitespace-nowrap shrink-0">
            {scenario.layerBadge}
          </span>
        </div>
      </div>

      {/* Row 2: Topology Switcher & Playback Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 border-b border-[#243247] bg-[#131C2E]">
        {/* Left: Switchable Preset Topologies */}
        <div className="flex items-center gap-1 p-0.5 bg-[#0B1120] border border-[#243247] rounded-md overflow-x-auto">
          {TOPOLOGY_LIST.map((topo) => {
            const active = topo.id === topologyId;
            return (
              <button
                key={topo.id}
                type="button"
                onClick={() => onSelectTopology(topo.id)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer ${
                  active ? 'bg-[#1E2B42] text-slate-50' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {topo.shortName}
              </button>
            );
          })}
        </div>

        {/* Right: Playback & Attack Controls */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onToggleAttack}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              attackActive
                ? 'bg-red-500/20 text-red-200 border border-red-500/50 hover:bg-red-500/30'
                : 'bg-red-600 text-white hover:bg-red-500'
            }`}
          >
            {attackActive ? <Square className="w-3.5 h-3.5 fill-current" /> : <Zap className="w-3.5 h-3.5" />}
            {attackActive ? 'Stop Attack' : 'Start Attack'}
          </button>

          <div className="h-4 w-px bg-[#243247]" aria-hidden="true" />

          <button
            type="button"
            onClick={onTogglePause}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-200 bg-[#1B263B] hover:bg-[#243247] border border-[#2D3E58] rounded-md transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer"
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {isPaused ? 'Resume' : 'Pause'}
          </button>

          <button
            type="button"
            onClick={onStepForward}
            title="Step packets forward one increment"
            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-200 bg-[#1B263B] hover:bg-[#243247] border border-[#2D3E58] rounded-md transition-colors duration-150 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <SkipForward className="w-3.5 h-3.5" />
            Step
          </button>

          <div className="flex items-center p-0.5 bg-[#0B1120] border border-[#243247] rounded-md">
            {([0.5, 1, 2] as PlaybackSpeed[]).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => onChangeSpeed(s)}
                className={`px-2 py-1 text-[11px] font-mono tabular-nums rounded transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                  speed === s ? 'bg-sky-500/20 text-sky-300' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {s}x
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={onResetLayout}
            title="Reset dragged node positions"
            className="p-1.5 text-slate-400 hover:text-slate-100 bg-[#1B263B] hover:bg-[#243247] border border-[#2D3E58] rounded-md transition-colors cursor-pointer"
            aria-label="Reset Layout"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Interactive 3D Isometric Topology Stage */}
      <div
        ref={stageOuterRef}
        onPointerMove={handleStagePointerMove}
        onPointerUp={handleStagePointerUp}
        onPointerLeave={handleStagePointerUp}
        className="relative flex-1 min-h-[320px] lg:min-h-[350px] bg-[#0B1120] select-none overflow-hidden flex items-center justify-center"
      >
        {/* CSS 3D Tilted Floor Perspective Grid + Depth Vignette */}
        <div
          aria-hidden="true"
          className="iso-floor-plane absolute inset-0 pointer-events-none opacity-85"
        />
        <div
          aria-hidden="true"
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(ellipse at 50% 48%, transparent 38%, rgba(7, 11, 21, 0.88) 100%)',
          }}
        />

        <div className="absolute top-3 left-4 z-30 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-400 pointer-events-none">
          <span>Drag 3D devices to reposition · Click device for terminal · Click packet to inspect</span>
        </div>

        {(arpPoisoned || dnsPoisoned || (wifiEvilTwinActive && !defenses.vpnWpa3Encryption) || (isFirewallSession && hasFirewallNode && !firewallPlaced)) && (
          <div className="absolute top-3 right-4 z-30 flex items-center gap-1.5 px-2.5 py-1 bg-amber-950/90 border border-amber-500/40 rounded text-[11px] font-medium text-amber-200">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <span>
              {isFirewallSession && hasFirewallNode && !firewallPlaced
                ? 'Perimeter Firewall Bypassed · Click Place Firewall to intercept attacks'
                : arpPoisoned
                ? 'ARP Cache Poisoned · Traffic rerouting through Attacker'
                : dnsPoisoned
                ? 'DNS Cache Spoofed · Portal redirecting to Rogue Site'
                : 'Evil Twin Wi-Fi Active · Client connected to Rogue AP'}
            </span>
          </div>
        )}

        {/* Coordinate-Locked 900x430 Isometric Stage */}
        <div
          ref={stageInnerRef}
          style={{
            width: VIEWBOX_W,
            height: VIEWBOX_H,
            transform: `scale(${stageScale})`,
            transformOrigin: 'center center',
          }}
          className="relative shrink-0"
        >
          {/* Layer 1: Wire & Bypass Cable SVG */}
          <svg
            viewBox={`0 0 ${VIEWBOX_W} ${VIEWBOX_H}`}
            width={VIEWBOX_W}
            height={VIEWBOX_H}
            className="absolute inset-0 z-0 pointer-events-none block"
          >
            {links.map((link) => {
              const src = nodeMap.get(link.sourceId);
              const dst = nodeMap.get(link.targetId);
              if (!src || !dst) return null;

              const isBypassedFirewallEdge =
                !firewallPlaced && hasFirewallNode && (src.role === 'firewall' || dst.role === 'firewall');

              const isMitmLink =
                arpPoisoned &&
                !defenses.dynamicArpInspection &&
                (src.role === 'attacker' || dst.role === 'attacker' || src.role === 'client' || dst.role === 'client');
              const isRogueLink =
                dnsPoisoned && !defenses.dnssecValidation && (src.role === 'rogue' || dst.role === 'rogue');
              const isEvilWifiLink =
                wifiEvilTwinActive &&
                !defenses.vpnWpa3Encryption &&
                ((src.role === 'client' && dst.role === 'attacker') ||
                  (src.role === 'attacker' && dst.role === 'client') ||
                  (src.role === 'attacker' && dst.role === 'router'));
              const isNtpAmpLink =
                attackActive &&
                activeScenario === 'ntp-amplification' &&
                !defenses.ntpMonlistDisable &&
                (src.role === 'ntp' || dst.role === 'ntp');

              const isRedirected = !isBypassedFirewallEdge && (isMitmLink || isRogueLink || isEvilWifiLink || isNtpAmpLink);
              const midX = (src.x + dst.x) / 2;
              const midY = (src.y + dst.y) / 2;

              return (
                <g key={link.id} opacity={isBypassedFirewallEdge ? 0.25 : 1}>
                  {/* Subtle wire depth shadow on floor plane */}
                  <line
                    x1={src.x}
                    y1={src.y + 4}
                    x2={dst.x}
                    y2={dst.y + 4}
                    stroke="#020617"
                    strokeOpacity={0.55}
                    strokeWidth={3.5}
                  />
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={dst.x}
                    y2={dst.y}
                    stroke={isNtpAmpLink ? '#EF4444' : isRedirected ? '#D97706' : '#2E4362'}
                    strokeWidth={isRedirected ? 2.5 : 2}
                    strokeDasharray={
                      isBypassedFirewallEdge
                        ? '3 5'
                        : isRedirected
                        ? '6 6'
                        : link.bandwidth.includes('Wi-Fi')
                        ? '3 4'
                        : undefined
                    }
                    className={isRedirected ? 'animate-dash-flow' : undefined}
                  />
                  <text
                    x={midX}
                    y={midY - 7}
                    textAnchor="middle"
                    style={{ paintOrder: 'stroke', stroke: '#0B1120', strokeWidth: 3, strokeLinejoin: 'round' }}
                    className="fill-slate-500 font-mono text-[9px] select-none"
                  >
                    {link.sourceInterface} · {link.bandwidth}
                  </text>
                </g>
              );
            })}

            {/* Direct Router-to-Switch Bypass Path when Perimeter Firewall is not placed */}
            {!firewallPlaced && hasFirewallNode && routerNode && switchNode && (
              <g className="pointer-events-none">
                <line
                  x1={routerNode.x}
                  y1={routerNode.y}
                  x2={switchNode.x}
                  y2={switchNode.y}
                  stroke={attackActive ? '#EF4444' : '#D97706'}
                  strokeWidth={2.25}
                  strokeDasharray="6 6"
                  className="animate-dash-flow"
                />
                <text
                  x={(routerNode.x + switchNode.x) / 2}
                  y={(routerNode.y + switchNode.y) / 2 - 44}
                  textAnchor="middle"
                  style={{ paintOrder: 'stroke', stroke: '#0B1120', strokeWidth: 3.5, strokeLinejoin: 'round' }}
                  className={`font-mono text-[9px] font-semibold select-none ${
                    attackActive ? 'fill-red-400' : 'fill-amber-300'
                  }`}
                >
                  BYPASS · DIRECT UNFILTERED LINK
                </text>
              </g>
            )}
          </svg>

          {/* Layer 2: CSS 3D Isometric Hardware Nodes (Depth-Sorted by Y) */}
          <div className="absolute inset-0 z-10 pointer-events-none">
            {depthSortedNodes.map((node, depthIdx) => {
              const isSelected = node.id === selectedNodeId;
              const isDragging = draggingId === node.id;
              const isBypassedFirewall = node.role === 'firewall' && !firewallPlaced;
              const defended = isNodeDefended(node.role, defenses, firewallPlaced);
              const isAlert = node.status === 'under_attack' || node.status === 'compromised';
              const isPoisoned = node.status === 'poisoned';
              const isAttacker = node.role === 'attacker' || node.role === 'rogue';
              const isUnconfiguredFirewall =
                node.role === 'firewall' &&
                firewallPlaced &&
                !defended &&
                isFirewallSession;

              const statusText = isBypassedFirewall
                ? 'NOT PLACED (BYPASSED)'
                : isAlert
                ? node.status === 'compromised'
                  ? 'COMPROMISED'
                  : 'UNDER ATTACK'
                : isPoisoned
                ? 'POISONED'
                : isUnconfiguredFirewall
                ? 'INLINE · ALLOW ANY'
                : defended
                ? 'SECURED'
                : null;

              const showLoadMeter = node.role === 'webserver' && node.synBacklog > 15;

              return (
                <div
                  key={node.id}
                  role="button"
                  tabIndex={0}
                  aria-label={`${node.label} (${node.ip})`}
                  onPointerDown={(e) => handleNodePointerDown(e, node)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectNode(node.id);
                    }
                  }}
                  style={{
                    left: node.x,
                    top: node.y,
                    transform: 'translate(-50%, -50%)',
                    zIndex: isDragging ? 40 : isSelected ? 30 : 10 + depthIdx,
                    touchAction: 'none',
                  }}
                  className={`group absolute w-[88px] flex flex-col items-center pointer-events-auto focus-visible:outline-none ${
                    isDragging ? 'cursor-grabbing' : 'cursor-grab'
                  }`}
                >
                  {/* Selection / Bypass Slot Pedestal Highlight */}
                  {(isSelected || isBypassedFirewall) && (
                    <div
                      aria-hidden="true"
                      className={`absolute -top-2 w-[82px] h-[68px] rounded-[10px] pointer-events-none ${
                        isSelected
                          ? 'border border-dashed border-sky-400/75'
                          : 'border border-dashed border-amber-400/80 bg-[#0F172A]/45'
                      }`}
                    />
                  )}

                  {/* Defended Shield Indicator */}
                  {defended && (
                    <div
                      aria-hidden="true"
                      className="absolute -top-1.5 right-1.5 z-20 w-4 h-4 flex items-center justify-center pointer-events-none"
                    >
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 drop-shadow" />
                    </div>
                  )}

                  {/* True CSS 3D Isometric Hardware Assembly */}
                  <div className="-mt-3">
                    <Device3DGraphic
                      role={node.role}
                      isSelected={isSelected}
                      isAlert={isAlert}
                      isPoisoned={isPoisoned}
                      defended={defended}
                      isAttacker={isAttacker}
                      isBypassed={isBypassedFirewall}
                    />
                  </div>

                  {/* Crisp Billboard Labels */}
                  <div className="-mt-1 flex flex-col items-center text-center pointer-events-none">
                    <span
                      style={{ textShadow: '0 1px 3px #0B1120, 0 0 6px #0B1120' }}
                      className="font-display text-[10px] font-semibold text-slate-100 leading-tight whitespace-nowrap"
                    >
                      {node.label}
                    </span>
                    <span
                      style={{ textShadow: '0 1px 3px #0B1120, 0 0 5px #0B1120' }}
                      className="font-mono text-[8.5px] text-slate-400 tabular-nums leading-tight whitespace-nowrap mt-0.5"
                    >
                      {node.ip}
                    </span>

                    {showLoadMeter && (
                      <div className="mt-1 flex flex-col items-center gap-0.5">
                        <div className="w-[72px] h-[5px] rounded-[2px] bg-[#1E293B] overflow-hidden">
                          <div
                            className="h-full transition-[width] duration-200"
                            style={{
                              width: `${Math.min(100, Math.round(node.synBacklog))}%`,
                              backgroundColor: node.synBacklog >= 70 ? '#EF4444' : '#F59E0B',
                            }}
                          />
                        </div>
                        <span
                          style={{ textShadow: '0 1px 3px #0B1120, 0 0 5px #0B1120' }}
                          className="font-mono text-[8.5px] text-red-300 tabular-nums whitespace-nowrap"
                        >
                          {loadLabel} {Math.round(node.synBacklog)}%
                        </span>
                      </div>
                    )}

                    {statusText && !showLoadMeter && (
                      <span
                        style={{ textShadow: '0 1px 3px #0B1120, 0 0 5px #0B1120' }}
                        className={`mt-0.5 font-mono text-[8.5px] font-semibold whitespace-nowrap ${
                          isAlert
                            ? 'text-red-400'
                            : isPoisoned || isBypassedFirewall || isUnconfiguredFirewall
                            ? 'text-amber-300'
                            : 'text-emerald-400'
                        }`}
                      >
                        {statusText}
                      </span>
                    )}

                    {node.role === 'attacker' && node.interceptedCount > 0 && (
                      <span
                        style={{ textShadow: '0 1px 3px #0B1120, 0 0 5px #0B1120' }}
                        className="mt-0.5 font-mono text-[8.5px] font-semibold text-amber-300 tabular-nums whitespace-nowrap"
                      >
                        SNIFFED: {node.interceptedCount}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Layer 3: Foreground Animated Clickable Packets & Blocked Callouts */}
          <svg
            viewBox={`0 0 ${VIEWBOX_W} ${VIEWBOX_H}`}
            width={VIEWBOX_W}
            height={VIEWBOX_H}
            className="absolute inset-0 z-20 pointer-events-none block"
          >
            {dropEffects.map((effect) => {
              const node = nodeMap.get(effect.nodeId);
              if (!node) return null;
              return (
                <g key={effect.id} transform={`translate(${node.x}, ${node.y - 48})`} className="pointer-events-none">
                  <rect
                    x={-40}
                    y={-11}
                    width={80}
                    height={18}
                    rx={4}
                    fill="#052E16"
                    stroke="#34D399"
                    strokeWidth={1}
                  />
                  <text
                    x={0}
                    y={1}
                    textAnchor="middle"
                    className="fill-emerald-200 font-mono text-[8.5px] font-semibold"
                  >
                    {effect.label}
                  </text>
                </g>
              );
            })}

            {inFlightPackets.map((pkt) => {
              const fromId = pkt.path[pkt.currentHopIndex];
              const toId = pkt.path[pkt.currentHopIndex + 1];
              const from = nodeMap.get(fromId);
              const to = nodeMap.get(toId);
              if (!from || !to) return null;

              const px = from.x + (to.x - from.x) * pkt.progress;
              const py = from.y + (to.y - from.y) * pkt.progress;
              const style = getPacketStyle(pkt.category);
              const isSelected = pkt.id === selectedPacketId;
              const isAmp = Boolean(pkt.meta?.isAmplified);

              return (
                <g
                  key={pkt.id}
                  transform={`translate(${px}, ${py})`}
                  style={{ pointerEvents: 'auto' }}
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectPacket(pkt.id);
                  }}
                  className="cursor-pointer"
                >
                  {isSelected && (
                    <rect
                      x={isAmp ? -28 : -24}
                      y={-13}
                      width={isAmp ? 56 : 48}
                      height={26}
                      rx={6}
                      fill="none"
                      stroke="#FFFFFF"
                      strokeWidth={1.5}
                    />
                  )}
                  <rect
                    x={isAmp ? -24 : -20}
                    y={isAmp ? -11 : -10}
                    width={isAmp ? 48 : 40}
                    height={isAmp ? 22 : 20}
                    rx={4}
                    fill={style.fill}
                    stroke={style.stroke}
                    strokeWidth={isAmp ? 2 : 1.5}
                  />
                  <text
                    x={0}
                    y={3.5}
                    textAnchor="middle"
                    fill={style.text}
                    className="font-mono text-[9px] font-semibold select-none"
                  >
                    {pkt.shortTag}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Bottom-left packet legend inside stage */}
        <div className="absolute bottom-2.5 left-4 z-30 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-slate-400 pointer-events-none">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-xs bg-[#0C2D48] border border-sky-400" />
            Normal
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-xs bg-[#450A0A] border border-red-400" />
            Attack / Flood
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-xs bg-[#451A03] border border-amber-400" />
            Spoof / MitM
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-xs bg-[#052E16] border border-emerald-400" />
            Blocked
          </span>
        </div>
      </div>
    </section>
  );
}
