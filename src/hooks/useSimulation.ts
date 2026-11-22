import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { DEFENSE_DEFINITIONS, SCENARIOS } from '../data/scenarios';
import { TOPOLOGIES } from '../data/topologies';
import { interpretCommand } from '../engine/commandInterpreter';
import {
  buildArpSpoofPacket,
  buildDnsQueryPacket,
  buildDnsSpoofReplyPacket,
  buildEmailHijackPacket,
  buildEmailVictimReplyPacket,
  buildHttpFloodPacket,
  buildHttpsSpoofPacket,
  buildIcmpFloodPacket,
  buildIcmpPingPacket,
  buildIcmpUnreachablePacket,
  buildIpSpoofPacket,
  buildNormalHttpPacket,
  buildNtpAmplifiedResponsePacket,
  buildNtpMonlistRequestPacket,
  buildPortScanProbePacket,
  buildPortScanReplyPacket,
  buildSqlExfilPacket,
  buildSqlInjectionHttpPacket,
  buildSqlQueryPacket,
  buildSynFloodPacket,
  buildUdpFloodPacket,
  buildWifiEavesdropPacket,
  formatSimTime,
  resetPacketCounter,
} from '../engine/packetBuilder';
import {
  ArpEntry,
  AttackMetricsState,
  DefenseKey,
  DefenseState,
  DnsCacheEntry,
  DropEffect,
  FirewallEvent,
  LabObjective,
  NetworkLink,
  NetworkNode,
  PlaybackSpeed,
  ScenarioId,
  SimulatedPacket,
  TerminalLine,
  TopologyId,
} from '../types/simulator';

const SPARKLINE_POINTS = 24;

function createInitialAttackMetrics(): AttackMetricsState {
  return {
    pps: 0,
    peakPps: 0,
    kbps: 0,
    bandwidthPct: 0,
    successfulExploits: 0,
    blockedPackets: 0,
    mitigationRatePct: 0,
    totalPackets: 0,
    history: Array.from({ length: SPARKLINE_POINTS }, () => ({
      pps: 0,
      bandwidthPct: 0,
      exploitsDelta: 0,
      blockedDelta: 0,
    })),
  };
}

const INITIAL_DEFENSES: DefenseState = {
  synCookies: false,
  dynamicArpInspection: false,
  wafParameterizedSql: false,
  firewallPortFilter: false,
  dnssecValidation: false,
  vpnWpa3Encryption: false,
  spfDkimDmarc: false,
  urpfIpFiltering: false,
  hstsCertPinning: false,
  l7HttpRateLimit: false,
  udpRateLimit: false,
  icmpRateLimit: false,
  ntpMonlistDisable: false,
};

function findPath(
  links: NetworkLink[],
  startId: string,
  endId: string,
  firewallInline = true
): string[] {
  if (startId === endId) return [startId];
  const adj = new Map<string, string[]>();
  let hasRouter = false;
  let hasSwitch = false;
  for (const link of links) {
    if (link.sourceId === 'router' || link.targetId === 'router') hasRouter = true;
    if (link.sourceId === 'switch' || link.targetId === 'switch') hasSwitch = true;
    if (!firewallInline && (link.sourceId === 'firewall' || link.targetId === 'firewall')) {
      continue;
    }
    if (!adj.has(link.sourceId)) adj.set(link.sourceId, []);
    if (!adj.has(link.targetId)) adj.set(link.targetId, []);
    adj.get(link.sourceId)!.push(link.targetId);
    adj.get(link.targetId)!.push(link.sourceId);
  }

  // When firewall is bypassed/not placed, connect router directly to switch
  if (!firewallInline && hasRouter && hasSwitch) {
    if (!adj.has('router')) adj.set('router', []);
    if (!adj.has('switch')) adj.set('switch', []);
    adj.get('router')!.push('switch');
    adj.get('switch')!.push('router');
  }

  const queue: string[][] = [[startId]];
  const visited = new Set<string>([startId]);

  while (queue.length > 0) {
    const path = queue.shift()!;
    const current = path[path.length - 1];
    const neighbors = adj.get(current) ?? [];
    for (const next of neighbors) {
      if (next === endId) {
        return [...path, next];
      }
      if (!visited.has(next)) {
        visited.add(next);
        queue.push([...path, next]);
      }
    }
  }
  return [startId, endId];
}

function createInitialNodes(topologyId: TopologyId): NetworkNode[] {
  return TOPOLOGIES[topologyId].nodes.map((n) => ({
    ...n,
    status: 'nominal',
    synBacklog: 6,
    interceptedCount: 0,
  }));
}

function createInitialArpTable(nodes: NetworkNode[]): ArpEntry[] {
  return nodes
    .filter((n) => n.role === 'router' || n.role === 'webserver' || n.role === 'dns' || n.role === 'client' || n.role === 'wifi_ap')
    .slice(0, 5)
    .map((n) => ({
      ip: n.ip,
      mac: n.mac,
      interfaceName: n.role === 'wifi_ap' ? 'wlan0' : 'eth0',
      status: 'valid',
      ownerLabel: n.label,
    }));
}

function createInitialDnsCache(nodes: NetworkNode[]): DnsCacheEntry[] {
  const web = nodes.find((n) => n.role === 'webserver');
  const db = nodes.find((n) => n.role === 'database');
  const mail = nodes.find((n) => n.role === 'mail');
  const entries: DnsCacheEntry[] = [
    {
      domain: 'portal.corp.local',
      ip: web?.ip ?? '10.20.0.10',
      ttl: 300,
      status: 'verified',
    },
    {
      domain: 'bank.firstbank.com',
      ip: web?.ip ?? '10.10.20.80',
      ttl: 240,
      status: 'verified',
    },
  ];
  if (db) {
    entries.push({ domain: 'db-prod.corp.local', ip: db.ip, ttl: 600, status: 'verified' });
  }
  if (mail) {
    entries.push({ domain: 'mail.firstbank.com', ip: mail.ip, ttl: 600, status: 'verified' });
  }
  return entries;
}

function createWelcomeTerminals(nodes: NetworkNode[], scenarioId: ScenarioId): Record<string, TerminalLine[]> {
  const scenario = SCENARIOS[scenarioId];
  const primaryDef = DEFENSE_DEFINITIONS.find((d) => d.key === scenario.primaryDefense);
  const map: Record<string, TerminalLine[]> = {};
  for (const n of nodes) {
    const hint =
      n.role === 'attacker' || n.role === 'rogue'
        ? `Try: ${scenario.attackCommandExample}`
        : n.role === 'firewall' || n.role === 'switch' || n.role === 'dns' || n.role === 'mail' || n.role === 'ntp' || n.role === 'router'
        ? `Type "iptables -L" or "defense enable ${primaryDef?.cliFlag ?? 'syn-cookies'}"`
        : `Type "help", "ifconfig", "arp -a", or "netstat -an"`;
    map[n.id] = [
      {
        id: `init-1-${n.id}`,
        type: 'info',
        text: `Connected to ${n.label} (${n.hostname} · ${n.ip}) — ${n.os}`,
      },
      {
        id: `init-2-${n.id}`,
        type: 'output',
        text: hint,
      },
    ];
  }
  return map;
}

export function useSimulation() {
  const [activeScenario, setActiveScenario] = useState<ScenarioId>('syn-flood');
  const [topologyId, setTopologyId] = useState<TopologyId>(SCENARIOS['syn-flood'].defaultTopologyId);
  const [nodes, setNodes] = useState<NetworkNode[]>(() =>
    createInitialNodes(SCENARIOS['syn-flood'].defaultTopologyId)
  );
  const [selectedNodeId, setSelectedNodeId] = useState<string>('attacker');

  const [inFlightPackets, setInFlightPackets] = useState<SimulatedPacket[]>([]);
  const [capturedPackets, setCapturedPackets] = useState<SimulatedPacket[]>([]);
  const [selectedPacketId, setSelectedPacketId] = useState<string | null>(null);
  const [dropEffects, setDropEffects] = useState<DropEffect[]>([]);

  const [defenses, setDefenses] = useState<DefenseState>(INITIAL_DEFENSES);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [speed, setSpeed] = useState<PlaybackSpeed>(1);
  const [attackActive, setAttackActive] = useState<boolean>(false);

  const [arpTable, setArpTable] = useState<ArpEntry[]>(() =>
    createInitialArpTable(createInitialNodes(SCENARIOS['syn-flood'].defaultTopologyId))
  );
  const [dnsCache, setDnsCache] = useState<DnsCacheEntry[]>(() =>
    createInitialDnsCache(createInitialNodes(SCENARIOS['syn-flood'].defaultTopologyId))
  );
  const [firewallEvents, setFirewallEvents] = useState<FirewallEvent[]>([]);
  const [portScanResults, setPortScanResults] = useState<
    { port: number; service: string; state: 'open' | 'closed' | 'filtered' }[]
  >([]);

  const [arpPoisoned, setArpPoisoned] = useState<boolean>(false);
  const [dnsPoisoned, setDnsPoisoned] = useState<boolean>(false);
  const [wifiEvilTwinActive, setWifiEvilTwinActive] = useState<boolean>(false);
  const [firewallPlaced, setFirewallPlaced] = useState<boolean>(true);

  const [terminals, setTerminals] = useState<Record<string, TerminalLine[]>>(() =>
    createWelcomeTerminals(createInitialNodes(SCENARIOS['syn-flood'].defaultTopologyId), 'syn-flood')
  );

  const [completedObjectives, setCompletedObjectives] = useState<Record<string, boolean>>({});
  const [attackMetrics, setAttackMetrics] = useState<AttackMetricsState>(() =>
    createInitialAttackMetrics()
  );

  // Refs for fresh state inside animation & interval loops
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const defensesRef = useRef(defenses);
  defensesRef.current = defenses;
  const firewallPlacedRef = useRef(firewallPlaced);
  firewallPlacedRef.current = firewallPlaced;
  const arpPoisonedRef = useRef(arpPoisoned);
  arpPoisonedRef.current = arpPoisoned;
  const dnsPoisonedRef = useRef(dnsPoisoned);
  dnsPoisonedRef.current = dnsPoisoned;
  const wifiEvilTwinRef = useRef(wifiEvilTwinActive);
  wifiEvilTwinRef.current = wifiEvilTwinActive;
  const topologyIdRef = useRef(topologyId);
  topologyIdRef.current = topologyId;
  const activeScenarioRef = useRef(activeScenario);
  activeScenarioRef.current = activeScenario;
  const attackActiveRef = useRef(attackActive);
  attackActiveRef.current = attackActive;
  const isPausedRef = useRef(isPaused);
  isPausedRef.current = isPaused;
  const speedRef = useRef(speed);
  speedRef.current = speed;
  const portScanCursorRef = useRef(0);
  const allOutCursorRef = useRef(0);

  // Rolling 1-second telemetry accumulator + deduplicated cumulative totals
  const metricsBucketRef = useRef({ packets: 0, bytes: 0, exploits: 0, blocked: 0 });
  const metricsTotalsRef = useRef({ exploits: 0, blocked: 0, totalPackets: 0, peakPps: 0 });
  const countedSpawnIdsRef = useRef(new Set<string>());
  const countedOutcomeIdsRef = useRef(new Set<string>());

  const syncMetricsCounters = useCallback(() => {
    const totals = metricsTotalsRef.current;
    const totalAttempted = totals.exploits + totals.blocked;
    const mitigationRatePct =
      totalAttempted > 0 ? Math.round((totals.blocked / totalAttempted) * 100) : 0;

    setAttackMetrics((prev) => {
      if (
        prev.successfulExploits === totals.exploits &&
        prev.blockedPackets === totals.blocked &&
        prev.totalPackets === totals.totalPackets &&
        prev.mitigationRatePct === mitigationRatePct
      ) {
        return prev;
      }
      return {
        ...prev,
        successfulExploits: totals.exploits,
        blockedPackets: totals.blocked,
        totalPackets: totals.totalPackets,
        mitigationRatePct,
      };
    });
  }, []);

  const recordPacketSpawn = useCallback((pkt: SimulatedPacket) => {
    if (countedSpawnIdsRef.current.has(pkt.id)) return;
    countedSpawnIdsRef.current.add(pkt.id);
    if (countedSpawnIdsRef.current.size > 600) {
      const first = countedSpawnIdsRef.current.values().next().value;
      if (first) countedSpawnIdsRef.current.delete(first);
    }
    metricsBucketRef.current.packets += 1;
    metricsBucketRef.current.bytes += pkt.lengthBytes;
    metricsTotalsRef.current.totalPackets += 1;
  }, []);

  const recordBlockedOutcome = useCallback((pktId: string) => {
    if (countedOutcomeIdsRef.current.has(pktId)) return;
    countedOutcomeIdsRef.current.add(pktId);
    if (countedOutcomeIdsRef.current.size > 600) {
      const first = countedOutcomeIdsRef.current.values().next().value;
      if (first) countedOutcomeIdsRef.current.delete(first);
    }
    metricsBucketRef.current.blocked += 1;
    metricsTotalsRef.current.blocked += 1;
  }, []);

  const recordExploitOutcome = useCallback((pktId: string) => {
    if (countedOutcomeIdsRef.current.has(pktId)) return;
    countedOutcomeIdsRef.current.add(pktId);
    if (countedOutcomeIdsRef.current.size > 600) {
      const first = countedOutcomeIdsRef.current.values().next().value;
      if (first) countedOutcomeIdsRef.current.delete(first);
    }
    metricsBucketRef.current.exploits += 1;
    metricsTotalsRef.current.exploits += 1;
  }, []);

  const links = useMemo(() => TOPOLOGIES[topologyId].links, [topologyId]);

  const appendTerminalLines = useCallback((nodeId: string, newLines: Omit<TerminalLine, 'id'>[]) => {
    if (newLines.length === 0) return;
    setTerminals((prev) => {
      const existing = prev[nodeId] ?? [];
      const stamped = newLines.map((l, idx) => ({
        ...l,
        id: `term-${Date.now()}-${idx}-${Math.random().toString(36).slice(2, 5)}`,
        timestamp: formatSimTime().slice(0, 8),
      }));
      return {
        ...prev,
        [nodeId]: [...existing, ...stamped].slice(-120),
      };
    });
  }, []);

  const pushFirewallEvent = useCallback(
    (nodeLabel: string, action: FirewallEvent['action'], rule: string, detail: string) => {
      setFirewallEvents((prev) => [
        {
          id: `fw-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          timestamp: formatSimTime().slice(0, 8),
          nodeLabel,
          action,
          rule,
          detail,
        },
        ...prev.slice(0, 39),
      ]);
    },
    []
  );

  const addDropEffect = useCallback((nodeId: string, label: string) => {
    const id = `drop-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setDropEffects((prev) => [...prev.slice(-8), { id, nodeId, label, createdAt: Date.now() }]);
    setTimeout(() => {
      setDropEffects((prev) => prev.filter((d) => d.id !== id));
    }, 950);
  }, []);

  const markObjective = useCallback((objectiveId: string) => {
    setCompletedObjectives((prev) => (prev[objectiveId] ? prev : { ...prev, [objectiveId]: true }));
  }, []);

  const enqueuePacket = useCallback(
    (pkt: SimulatedPacket) => {
      recordPacketSpawn(pkt);
      setInFlightPackets((prev) => [...prev.slice(-30), pkt]);
      setCapturedPackets((prev) => [pkt, ...prev.slice(0, 129)]);
    },
    [recordPacketSpawn]
  );

  const spawnBaselinePacket = useCallback(() => {
    const currentNodes = nodesRef.current;
    const currentLinks = TOPOLOGIES[topologyIdRef.current].links;
    const client = currentNodes.find((n) => n.role === 'client');
    const web = currentNodes.find((n) => n.role === 'webserver');
    const attacker = currentNodes.find((n) => n.role === 'attacker');
    const rogue = currentNodes.find((n) => n.role === 'rogue');
    const dns = currentNodes.find((n) => n.role === 'dns');
    const wifiAp = currentNodes.find((n) => n.role === 'wifi_ap');

    if (!client || !web) return;

    // On Wi-Fi topology, route via legitimate Business AP normally (or Evil Twin when eavesdropping active)
    if (wifiAp && attacker) {
      const evilActive = wifiEvilTwinRef.current && !defensesRef.current.vpnWpa3Encryption;
      if (evilActive) {
        const leg1 = findPath(currentLinks, client.id, attacker.id);
        const leg2 = findPath(currentLinks, attacker.id, web.id);
        enqueuePacket(buildWifiEavesdropPacket(client, web, [...leg1, ...leg2.slice(1)], false));
        return;
      }
      const safePath = findPath(currentLinks, client.id, wifiAp.id).concat(
        findPath(currentLinks, wifiAp.id, web.id).slice(1)
      );
      enqueuePacket(
        defensesRef.current.vpnWpa3Encryption
          ? buildWifiEavesdropPacket(client, web, safePath, true)
          : buildNormalHttpPacket(client, web, safePath, false, false)
      );
      return;
    }

    // DNS poisoned redirect
    const fwInline = firewallPlacedRef.current;
    if (dnsPoisonedRef.current && (!defensesRef.current.dnssecValidation || !fwInline)) {
      const hijackTarget = rogue ?? attacker;
      if (hijackTarget) {
        const path = findPath(currentLinks, client.id, hijackTarget.id, fwInline);
        enqueuePacket(buildNormalHttpPacket(client, hijackTarget, path, false, true));
        return;
      }
    }

    // ARP poisoned MITM detour
    if (arpPoisonedRef.current && (!defensesRef.current.dynamicArpInspection || !fwInline) && attacker) {
      const leg1 = findPath(currentLinks, client.id, attacker.id, fwInline);
      const leg2 = findPath(currentLinks, attacker.id, web.id, fwInline);
      const mitmPath = [...leg1, ...leg2.slice(1)];
      enqueuePacket(buildNormalHttpPacket(client, web, mitmPath, true, false));
      return;
    }

    // DNS query baseline on dns-spoof
    if (dns && activeScenarioRef.current === 'dns-spoof' && Math.random() < 0.45) {
      const path = findPath(currentLinks, client.id, dns.id, fwInline);
      enqueuePacket(buildDnsQueryPacket(client, dns, 'portal.corp.local', path));
      return;
    }

    const path = findPath(currentLinks, client.id, web.id, fwInline);
    enqueuePacket(buildNormalHttpPacket(client, web, path, false, false));
  }, [enqueuePacket]);

  const spawnAttackWave = useCallback(
    (scenarioOverride?: ScenarioId, customSqlPayload?: string) => {
      const scenarioId = scenarioOverride ?? activeScenarioRef.current;
      const currentNodes = nodesRef.current;
      const currentLinks = TOPOLOGIES[topologyIdRef.current].links;
      const fwInline = firewallPlacedRef.current;
      const attacker = currentNodes.find((n) => n.role === 'attacker');
      const web = currentNodes.find((n) => n.role === 'webserver') ?? currentNodes.find((n) => n.role === 'router');
      const client = currentNodes.find((n) => n.role === 'client');
      const router = currentNodes.find((n) => n.role === 'router');
      const rogue = currentNodes.find((n) => n.role === 'rogue');
      const wifiAp = currentNodes.find((n) => n.role === 'wifi_ap');
      const mail = currentNodes.find((n) => n.role === 'mail');
      const ntp = currentNodes.find((n) => n.role === 'ntp');
      const dns = currentNodes.find((n) => n.role === 'dns');

      if (!attacker) return;

      const emitVector = (vectorId: ScenarioId) => {
        switch (vectorId) {
          case 'syn-flood': {
            if (!web) return;
            enqueuePacket(buildSynFloodPacket(attacker, web, findPath(currentLinks, attacker.id, web.id, fwInline)));
            break;
          }
          case 'arp-spoof': {
            if (!client || !router) return;
            enqueuePacket(buildArpSpoofPacket(attacker, client, router, findPath(currentLinks, attacker.id, client.id, fwInline)));
            break;
          }
          case 'wifi-eavesdropping': {
            if (!client || !web) return;
            setWifiEvilTwinActive(true);
            if (defensesRef.current.vpnWpa3Encryption && wifiAp) {
              const safePath = findPath(currentLinks, client.id, wifiAp.id, fwInline).concat(
                findPath(currentLinks, wifiAp.id, web.id, fwInline).slice(1)
              );
              const safePkt = buildWifiEavesdropPacket(client, web, safePath, true);
              enqueuePacket(safePkt);
              recordBlockedOutcome(safePkt.id);
              addDropEffect(attacker.id, 'VPN ENCRYPTED');
              pushFirewallEvent(
                wifiAp.label,
                'BLOCKED',
                'WPA3-VPN',
                'Client rejected Evil Twin AP and encrypted payment payload via WPA3 + VPN tunnel.'
              );
              markObjective('verify-blocked');
            } else {
              const leg1 = findPath(currentLinks, client.id, attacker.id, fwInline);
              const leg2 = findPath(currentLinks, attacker.id, web.id, fwInline);
              enqueuePacket(buildWifiEavesdropPacket(client, web, [...leg1, ...leg2.slice(1)], false));
            }
            break;
          }
          case 'email-hijacking': {
            if (!client) return;
            if (mail) {
              const leg1 = findPath(currentLinks, attacker.id, mail.id, fwInline);
              const leg2 = findPath(currentLinks, mail.id, client.id, fwInline);
              enqueuePacket(buildEmailHijackPacket(attacker, client, [...leg1, ...leg2.slice(1)]));
            } else {
              enqueuePacket(buildEmailHijackPacket(attacker, client, findPath(currentLinks, attacker.id, client.id, fwInline)));
            }
            break;
          }
          case 'ip-spoofing': {
            if (!web) return;
            const trustedIp = dns?.ip ?? '10.0.2.53';
            enqueuePacket(buildIpSpoofPacket(attacker, web, trustedIp, findPath(currentLinks, attacker.id, web.id, fwInline)));
            break;
          }
          case 'https-spoofing': {
            if (!client) return;
            const targetRogue = rogue ?? attacker;
            enqueuePacket(buildHttpsSpoofPacket(client, targetRogue, findPath(currentLinks, client.id, targetRogue.id, fwInline)));
            break;
          }
          case 'http-flood': {
            if (!web) return;
            enqueuePacket(buildHttpFloodPacket(attacker, web, findPath(currentLinks, attacker.id, web.id, fwInline)));
            break;
          }
          case 'udp-flood': {
            if (!web) return;
            enqueuePacket(buildUdpFloodPacket(attacker, web, findPath(currentLinks, attacker.id, web.id, fwInline)));
            break;
          }
          case 'icmp-flood': {
            if (!web) return;
            enqueuePacket(buildIcmpFloodPacket(attacker, web, findPath(currentLinks, attacker.id, web.id, fwInline), false));
            break;
          }
          case 'ntp-amplification': {
            if (!web) return;
            const reflector = ntp ?? dns ?? router;
            if (!reflector) return;
            enqueuePacket(
              buildNtpMonlistRequestPacket(attacker, reflector, web, findPath(currentLinks, attacker.id, reflector.id, fwInline))
            );
            break;
          }
          case 'sql-injection': {
            if (!web) return;
            enqueuePacket(
              buildSqlInjectionHttpPacket(
                attacker,
                web,
                findPath(currentLinks, attacker.id, web.id, fwInline),
                customSqlPayload ?? "' OR '1'='1'--"
              )
            );
            break;
          }
          case 'port-scan': {
            if (!web) return;
            const portsToScan =
              web.ports.length > 0
                ? web.ports
                : [
                    { port: 22, service: 'ssh', state: 'open' as const },
                    { port: 80, service: 'http', state: 'open' as const },
                    { port: 443, service: 'https', state: 'open' as const },
                    { port: 3306, service: 'mysql', state: 'closed' as const },
                    { port: 8080, service: 'http-alt', state: 'open' as const },
                  ];
            const portInfo = portsToScan[portScanCursorRef.current % portsToScan.length];
            portScanCursorRef.current += 1;
            enqueuePacket(
              buildPortScanProbePacket(attacker, web, portInfo.port, portInfo.service, findPath(currentLinks, attacker.id, web.id, fwInline))
            );
            break;
          }
          case 'dns-spoof': {
            if (!client) return;
            const rogueIp = rogue?.ip ?? '192.168.10.99';
            enqueuePacket(
              buildDnsSpoofReplyPacket(attacker, client, 'portal.corp.local', rogueIp, findPath(currentLinks, attacker.id, client.id, fwInline))
            );
            break;
          }
        }
      };

      if (scenarioId === 'all-out-defense') {
        const allVectors: ScenarioId[] = [
          'syn-flood',
          'sql-injection',
          'ip-spoofing',
          'http-flood',
          'port-scan',
          'email-hijacking',
          'udp-flood',
          'dns-spoof',
          'ntp-amplification',
          'icmp-flood',
          'arp-spoof',
          'https-spoofing',
        ];
        // Fire 3 distinct simultaneous attack vectors per tick
        for (let i = 0; i < 3; i++) {
          const idx = (allOutCursorRef.current + i) % allVectors.length;
          emitVector(allVectors[idx]);
        }
        allOutCursorRef.current = (allOutCursorRef.current + 3) % allVectors.length;
        return;
      }

      emitVector(scenarioId);
    },
    [addDropEffect, enqueuePacket, markObjective, pushFirewallEvent, recordBlockedOutcome]
  );

  // Evaluate hop arrival, defense drops, and chained responses
  const processPacketStep = useCallback(
    (deltaProgress: number) => {
      const currentNodes = nodesRef.current;
      const currentLinks = TOPOLOGIES[topologyIdRef.current].links;
      const currentDefenses = defensesRef.current;

      const newlySpawned: SimulatedPacket[] = [];
      const updatedCapturedMap = new Map<string, SimulatedPacket>();

      setInFlightPackets((prevPackets) => {
        const remaining: SimulatedPacket[] = [];

        for (const pkt of prevPackets) {
          if (pkt.status !== 'in_flight') continue;

          const nextProgress = pkt.progress + deltaProgress;
          if (nextProgress < 1) {
            remaining.push({ ...pkt, progress: nextProgress });
            continue;
          }

          const arrivedHopIndex = pkt.currentHopIndex + 1;
          const arrivedNodeId = pkt.path[arrivedHopIndex];
          const arrivedNode = currentNodes.find((n) => n.id === arrivedNodeId);
          const isFinalHop = arrivedHopIndex >= pkt.path.length - 1;

          if (!arrivedNode) continue;

          // ==================== DEFENSE INTERCEPTIONS ====================
          const firewallEnforced =
            topologyIdRef.current !== 'firewall-sandbox' || firewallPlacedRef.current;

          // 1. SYN Flood Defense
          if (
            firewallEnforced &&
            pkt.attackType === 'syn-flood' &&
            currentDefenses.synCookies &&
            (arrivedNode.role === 'firewall' || (isFinalHop && arrivedNode.role === 'webserver'))
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'DROP',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'SYN Cookie & Rate-Limit policy dropped spoofed half-open SYN burst.',
              educationalNote:
                'DEFENSE ACTIVE: SYN Cookies & Rate Limiting intercepted this spoofed SYN packet before it could exhaust Web Server backlog memory.',
            });
            addDropEffect(arrivedNode.id, 'SYN DROPPED');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(arrivedNode.label, 'BLOCKED', 'SYN-COOKIES', `Dropped spoofed SYN from ${pkt.srcIp} → :80`);
            if (activeScenarioRef.current === 'syn-flood' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 2. ARP Spoofing Defense (DAI)
          if (
            firewallEnforced &&
            pkt.attackType === 'arp-spoof' &&
            currentDefenses.dynamicArpInspection &&
            (arrivedNode.role === 'switch' || arrivedNode.role === 'router' || arrivedNode.role === 'firewall' || isFinalHop)
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'DAI DROP',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'Dynamic ARP Inspection rejected forged MAC-to-IP binding on untrusted port.',
              educationalNote:
                'DEFENSE ACTIVE: Switch DAI compared the Sender MAC against its DHCP Snooping table and discarded the forged ARP frame.',
            });
            addDropEffect(arrivedNode.id, 'DAI BLOCKED');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'SWITCH-DAI',
              `Rejected forged ARP claiming ${pkt.meta?.spoofTargetIp} is at ${pkt.meta?.spoofMac}`
            );
            if (activeScenarioRef.current === 'arp-spoof' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 3. Email Hijacking Defense (SPF/DKIM/DMARC)
          if (
            firewallEnforced &&
            pkt.attackType === 'email-hijacking' &&
            pkt.meta?.isSpoofedEmail &&
            currentDefenses.spfDkimDmarc &&
            (arrivedNode.role === 'mail' || arrivedNode.role === 'firewall' || isFinalHop)
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: '550 DMARC',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'SMTP Mail Server rejected forged alerts@firstbank.com (SPF FAIL + DMARC p=reject).',
              educationalNote:
                'DEFENSE ACTIVE: SPF/DKIM/DMARC verified that the attacker IP is not authorized to send mail for firstbank.com and dropped the phishing email.',
            });
            addDropEffect(arrivedNode.id, 'DMARC FAIL');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'SMTP-DMARC',
              `550 Rejected spoofed email From:<alerts@firstbank.com> (src ${pkt.srcIp})`
            );
            appendTerminalLines('attacker', [
              { type: 'error', text: '550 5.7.1 DMARC policy reject — SPF & DKIM validation failed' },
            ]);
            if (activeScenarioRef.current === 'email-hijacking' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 4. IP Spoofing Defense (uRPF)
          if (
            firewallEnforced &&
            pkt.attackType === 'ip-spoofing' &&
            currentDefenses.urpfIpFiltering &&
            (arrivedNode.role === 'router' || arrivedNode.role === 'firewall' || isFinalHop)
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'uRPF DROP',
              droppedAtNodeId: arrivedNode.id,
              dropReason: `uRPF dropped external packet claiming internal source IP ${pkt.srcIp} on Gi0/0.`,
              educationalNote:
                'DEFENSE ACTIVE: Unicast Reverse Path Forwarding verified that the forged source subnet does not belong on the external ingress interface and discarded the frame.',
            });
            addDropEffect(arrivedNode.id, 'uRPF DROP');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'uRPF-STRICT',
              `Dropped spoofed source IP ${pkt.srcIp} arriving on external ingress interface`
            );
            if (activeScenarioRef.current === 'ip-spoofing' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 5. HTTPS Spoofing Defense (HSTS & Cert Pinning)
          if (
            firewallEnforced &&
            pkt.attackType === 'https-spoofing' &&
            currentDefenses.hstsCertPinning &&
            (arrivedNode.role === 'router' || arrivedNode.role === 'switch' || arrivedNode.role === 'firewall' || isFinalHop)
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'CERT FAIL',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'Browser HSTS & Certificate Pinning aborted rogue TLS handshake (SHA-256 pin mismatch).',
              educationalNote:
                'DEFENSE ACTIVE: Certificate Pinning detected the untrusted Rogue-SelfSigned-CA certificate on p0rtal-corp.local and terminated the connection before credentials left the client.',
            });
            addDropEffect(arrivedNode.id, 'CERT FAIL');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'HSTS-PINNING',
              'Aborted rogue TLS handshake for lookalike domain https://p0rtal-corp.local'
            );
            if (activeScenarioRef.current === 'https-spoofing' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 6. L7 HTTP Flood Defense
          if (
            firewallEnforced &&
            pkt.attackType === 'http-flood' &&
            currentDefenses.l7HttpRateLimit &&
            (arrivedNode.role === 'firewall' || arrivedNode.role === 'webserver')
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: '429 LIMIT',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'L7 WAF rate limiter returned HTTP 429 Too Many Requests for abusive GET flood.',
              educationalNote:
                'DEFENSE ACTIVE: L7 WAF rate limiting detected abnormal request velocity and dropped excess requests at the edge so App Web Server CPU stays healthy.',
            });
            addDropEffect(arrivedNode.id, 'HTTP 429');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(arrivedNode.label, 'BLOCKED', 'WAF-RATE-429', `Throttled HTTP flood burst from ${pkt.srcIp}`);
            if (activeScenarioRef.current === 'http-flood' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 7. UDP Flood Defense
          if (
            firewallEnforced &&
            pkt.attackType === 'udp-flood' &&
            pkt.protocol === 'UDP' &&
            currentDefenses.udpRateLimit &&
            (arrivedNode.role === 'firewall' || arrivedNode.role === 'router')
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'UDP DROP',
              droppedAtNodeId: arrivedNode.id,
              dropReason: `Firewall dropped random-port UDP flood to port ${pkt.meta?.udpPort ?? 0} and suppressed ICMP replies.`,
              educationalNote:
                'DEFENSE ACTIVE: Perimeter UDP flood filtering discarded the unsolicited high-port datagram before the target server wasted resources sending ICMP Unreachable errors.',
            });
            addDropEffect(arrivedNode.id, 'UDP DROP');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'UDP-RATE-LIMIT',
              `Dropped UDP flood packet to random closed port :${pkt.meta?.udpPort ?? 0}`
            );
            if (activeScenarioRef.current === 'udp-flood' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 8. ICMP Flood Defense
          if (
            firewallEnforced &&
            pkt.attackType === 'icmp-flood' &&
            pkt.shortTag === 'ICMP!' &&
            currentDefenses.icmpRateLimit &&
            (arrivedNode.role === 'firewall' || arrivedNode.role === 'router')
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'ICMP DROP',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'Firewall ICMP Echo policer dropped oversized 1472-byte ping flood frame.',
              educationalNote:
                'DEFENSE ACTIVE: ICMP Echo Rate Limiting discarded the flood request at the edge firewall, protecting both inbound and outbound server bandwidth.',
            });
            addDropEffect(arrivedNode.id, 'ICMP DROP');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'ICMP-POLICER',
              `Dropped 1472B ICMP Echo flood packet from ${pkt.srcIp}`
            );
            if (activeScenarioRef.current === 'icmp-flood' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 9. NTP Amplification Defense
          if (
            firewallEnforced &&
            pkt.attackType === 'ntp-amplification' &&
            currentDefenses.ntpMonlistDisable &&
            (arrivedNode.role === 'ntp' || arrivedNode.role === 'firewall' || arrivedNode.role === 'router')
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'NTP DROP',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'NTP monlist disabled (disable monitor) & BCP38 rejected spoofed reflection query.',
              educationalNote:
                'DEFENSE ACTIVE: Disabling legacy NTP Mode 7 monlist and enforcing BCP38 anti-spoofing completely halts 1:200 reflection amplification.',
            });
            addDropEffect(arrivedNode.id, 'MONLIST OFF');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'NTP-BCP38',
              `Blocked spoofed NTP monlist reflection query (forged victim IP ${pkt.srcIp})`
            );
            if (activeScenarioRef.current === 'ntp-amplification' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 10. SQL Injection Defense (WAF)
          if (
            firewallEnforced &&
            pkt.attackType === 'sql-injection' &&
            pkt.protocol === 'HTTP' &&
            currentDefenses.wafParameterizedSql &&
            (arrivedNode.role === 'firewall' || arrivedNode.role === 'webserver')
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: '403 WAF',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'WAF detected SQL tautology signature (OR 1=1) and returned 403 Forbidden.',
              educationalNote:
                'DEFENSE ACTIVE: WAF signature inspection blocked the SQL injection payload before it reached the SQL Database.',
            });
            addDropEffect(arrivedNode.id, 'WAF 403');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'WAF-SQLI-942100',
              `Blocked SQLi payload "${pkt.meta?.sqlQuery ?? "' OR 1=1--"}" → HTTP 403`
            );
            appendTerminalLines('attacker', [
              { type: 'error', text: `[WAF BLOCKED] HTTP/1.1 403 Forbidden — SQL injection signature rejected` },
            ]);
            if (activeScenarioRef.current === 'sql-injection' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 11. Port Scan Defense
          if (
            firewallEnforced &&
            pkt.attackType === 'port-scan' &&
            pkt.shortTag.startsWith(':') &&
            currentDefenses.firewallPortFilter &&
            arrivedNode.role === 'firewall' &&
            pkt.meta?.scannedPort !== 80 &&
            pkt.meta?.scannedPort !== 443
          ) {
            const port = pkt.meta?.scannedPort ?? 80;
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'FILTERED',
              droppedAtNodeId: arrivedNode.id,
              dropReason: `Firewall stealth-dropped unauthorized scan probe to port ${port}.`,
              educationalNote:
                'DEFENSE ACTIVE: Firewall Port Scan Filtering silently discarded the SYN probe to a non-public port.',
            });
            addDropEffect(arrivedNode.id, `:${port} FILTERED`);
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(arrivedNode.label, 'BLOCKED', 'PORT-SCAN-IDS', `Silently dropped SYN probe to port ${port}`);
            setPortScanResults((prev) => {
              const next = prev.filter((r) => r.port !== port);
              return [
                ...next,
                {
                  port,
                  service: port === 22 ? 'ssh' : port === 3306 ? 'mysql' : 'http-alt',
                  state: 'filtered' as const,
                },
              ].sort((a, b) => a.port - b.port);
            });
            appendTerminalLines('attacker', [
              { type: 'info', text: `${String(port).padEnd(8)} filtered  (no response — firewall dropped probe)` },
            ]);
            if (activeScenarioRef.current === 'port-scan' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // 12. DNS Spoofing Defense (DNSSEC)
          if (
            firewallEnforced &&
            pkt.attackType === 'dns-spoof' &&
            currentDefenses.dnssecValidation &&
            (arrivedNode.role === 'switch' || arrivedNode.role === 'router' || arrivedNode.role === 'firewall' || isFinalHop)
          ) {
            updatedCapturedMap.set(pkt.id, {
              ...pkt,
              currentHopIndex: arrivedHopIndex,
              progress: 1,
              status: 'dropped',
              category: 'blocked',
              shortTag: 'BAD SIG',
              droppedAtNodeId: arrivedNode.id,
              dropReason: 'DNSSEC rejected forged DNS response due to missing/invalid RRSIG signature.',
              educationalNote:
                'DEFENSE ACTIVE: DNSSEC validation verified cryptographic RRSIG records and discarded this unsigned forged A-record.',
            });
            addDropEffect(arrivedNode.id, 'RRSIG FAIL');
            recordBlockedOutcome(pkt.id);
            pushFirewallEvent(
              arrivedNode.label,
              'BLOCKED',
              'DNSSEC-RRSIG',
              `Rejected unsigned DNS A-record claiming ${pkt.meta?.dnsDomain} → ${pkt.meta?.dnsResolvedIp}`
            );
            if (activeScenarioRef.current === 'dns-spoof' || activeScenarioRef.current === 'all-out-defense') {
              markObjective('verify-blocked');
            }
            continue;
          }

          // ==================== MID-HOP MITM / EVIL TWIN SNIFFING ====================
          if ((pkt.meta?.isMitmDetour || pkt.meta?.isWifiSniff) && arrivedNode.role === 'attacker') {
            recordExploitOutcome(pkt.id);
            setNodes((ns) =>
              ns.map((n) =>
                n.id === arrivedNode.id ? { ...n, interceptedCount: n.interceptedCount + 1 } : n
              )
            );
            appendTerminalLines('attacker', [
              {
                type: 'alert',
                text: pkt.meta?.isWifiSniff
                  ? `[EVIL TWIN SNIFFED] Card 4532-8910-4421-7790 CVV 482 | login=alex.chen`
                  : `[MITM CAPTURED] ${pkt.srcIp} → ${pkt.dstIp} | Cookie: session_id=9a81f3c2e04b`,
              },
            ]);
          }

          if (!isFinalHop) {
            remaining.push({ ...pkt, currentHopIndex: arrivedHopIndex, progress: 0 });
            continue;
          }

          // ==================== FINAL HOP DELIVERY EFFECTS ====================
          updatedCapturedMap.set(pkt.id, {
            ...pkt,
            currentHopIndex: arrivedHopIndex,
            progress: 1,
            status: 'delivered',
          });

          // Target load saturation for all DoS/DDoS attacks
          if (
            pkt.attackType === 'syn-flood' ||
            pkt.attackType === 'http-flood' ||
            (pkt.attackType === 'udp-flood' && pkt.protocol === 'UDP') ||
            (pkt.attackType === 'icmp-flood' && pkt.shortTag === 'ICMP!') ||
            (pkt.attackType === 'ntp-amplification' && pkt.meta?.isAmplified)
          ) {
            recordExploitOutcome(pkt.id);
            const loadBump = pkt.meta?.isAmplified ? 14 : pkt.attackType === 'http-flood' ? 18 : 15;
            setNodes((ns) =>
              ns.map((n) => {
                if (n.id !== arrivedNode.id) return n;
                const nextBacklog = Math.min(100, n.synBacklog + loadBump);
                return {
                  ...n,
                  synBacklog: nextBacklog,
                  status: nextBacklog >= 70 ? 'under_attack' : 'nominal',
                };
              })
            );
          }

          // UDP Flood -> Target generates ICMP Destination Unreachable reply
          if (pkt.attackType === 'udp-flood' && pkt.protocol === 'UDP') {
            const attackerNode = currentNodes.find((n) => n.role === 'attacker');
            if (attackerNode) {
              const replyPath = findPath(currentLinks, arrivedNode.id, attackerNode.id, firewallPlacedRef.current);
              newlySpawned.push(
                buildIcmpUnreachablePacket(arrivedNode, attackerNode, pkt.meta?.udpPort ?? 42000, replyPath)
              );
            }
          }

          // ICMP Flood -> Target tries to send 1472B Echo Reply back
          if (pkt.attackType === 'icmp-flood' && pkt.shortTag === 'ICMP!') {
            const attackerNode = currentNodes.find((n) => n.role === 'attacker');
            if (attackerNode) {
              const replyPath = findPath(currentLinks, arrivedNode.id, attackerNode.id, firewallPlacedRef.current);
              newlySpawned.push(buildIcmpFloodPacket(arrivedNode, attackerNode, replyPath, true));
            }
          }

          // NTP Amplification -> Open NTP Reflector explodes into 3 amplified UDP bursts toward Bank Web Server!
          if (pkt.attackType === 'ntp-amplification' && pkt.shortTag === 'MON?') {
            const victimServer = currentNodes.find((n) => n.role === 'webserver');
            if (victimServer) {
              const reflectPath = findPath(currentLinks, arrivedNode.id, victimServer.id, firewallPlacedRef.current);
              for (let b = 1; b <= 3; b++) {
                const ampPkt = buildNtpAmplifiedResponsePacket(arrivedNode, victimServer, b, reflectPath);
                newlySpawned.push({
                  ...ampPkt,
                  progress: (b - 1) * 0.22, // Staggered burst visibly trailing across wire
                });
              }
              appendTerminalLines('attacker', [
                {
                  type: 'alert',
                  text: `[NTP REFLECTION] ${arrivedNode.ip} reflected 3x 4,800B UDP bursts (100x amp) → ${victimServer.ip}`,
                },
              ]);
            }
          }

          // Email Hijacking -> Victim tricked into sending wire/credential reply to attacker
          if (pkt.attackType === 'email-hijacking' && pkt.meta?.isSpoofedEmail) {
            const attackerNode = currentNodes.find((n) => n.role === 'attacker');
            setNodes((ns) =>
              ns.map((n) => (n.id === arrivedNode.id ? { ...n, status: 'compromised' } : n))
            );
            if (attackerNode) {
              const replyPath = findPath(currentLinks, arrivedNode.id, attackerNode.id, firewallPlacedRef.current);
              newlySpawned.push(buildEmailVictimReplyPacket(arrivedNode, attackerNode, replyPath));
            }
          }

          if (pkt.attackType === 'email-hijacking' && pkt.shortTag === 'WIRE' && arrivedNode.role === 'attacker') {
            recordExploitOutcome(pkt.id);
            appendTerminalLines('attacker', [
              { type: 'alert', text: '[EMAIL HIJACK SUCCESS] Received victim Acct #99812041 · PIN 8824 · $14,500 wire auth!' },
            ]);
          }

          // IP Spoofing delivery
          if (pkt.attackType === 'ip-spoofing') {
            recordExploitOutcome(pkt.id);
            setNodes((ns) =>
              ns.map((n) => (n.id === arrivedNode.id ? { ...n, status: 'compromised' } : n))
            );
            appendTerminalLines('attacker', [
              { type: 'alert', text: `[IP SPOOF ACCEPTED] ${arrivedNode.label} trusted forged source IP ${pkt.srcIp}` },
            ]);
          }

          // HTTPS Spoofing delivery
          if (pkt.attackType === 'https-spoofing') {
            recordExploitOutcome(pkt.id);
            setNodes((ns) =>
              ns.map((n) => (n.id === arrivedNode.id || n.role === 'client' ? { ...n, status: 'poisoned' } : n))
            );
            appendTerminalLines('attacker', [
              { type: 'alert', text: '[ROGUE HTTPS] Decrypted SSO credentials from https://p0rtal-corp.local (user=m.silva)' },
            ]);
          }

          // ARP Spoofing delivery
          if (pkt.attackType === 'arp-spoof' && pkt.meta?.spoofTargetIp && pkt.meta?.spoofMac) {
            recordExploitOutcome(pkt.id);
            setArpPoisoned(true);
            setArpTable((prev) =>
              prev.map((entry) =>
                entry.ip === pkt.meta!.spoofTargetIp
                  ? { ...entry, mac: pkt.meta!.spoofMac!, status: 'poisoned' }
                  : entry
              )
            );
            setNodes((ns) =>
              ns.map((n) => (n.id === arrivedNode.id ? { ...n, status: 'poisoned' } : n))
            );
          }

          // SQL Injection chain
          if (pkt.attackType === 'sql-injection' && pkt.protocol === 'HTTP' && arrivedNode.role === 'webserver') {
            const dbNode = currentNodes.find((n) => n.role === 'database');
            if (dbNode) {
              const sqlPath = findPath(currentLinks, arrivedNode.id, dbNode.id, firewallPlacedRef.current);
              newlySpawned.push(
                buildSqlQueryPacket(arrivedNode, dbNode, sqlPath, pkt.meta?.sqlQuery ?? "' OR '1'='1'--")
              );
            }
          }

          if (pkt.attackType === 'sql-injection' && pkt.protocol === 'SQL' && arrivedNode.role === 'database') {
            const attackerNode = currentNodes.find((n) => n.role === 'attacker');
            setNodes((ns) =>
              ns.map((n) => (n.id === arrivedNode.id ? { ...n, status: 'compromised' } : n))
            );
            if (attackerNode) {
              const exfilPath = findPath(currentLinks, arrivedNode.id, attackerNode.id, firewallPlacedRef.current);
              newlySpawned.push(buildSqlExfilPacket(arrivedNode, attackerNode, exfilPath));
            }
          }

          if (pkt.attackType === 'sql-injection' && pkt.shortTag === 'LEAK' && arrivedNode.role === 'attacker') {
            recordExploitOutcome(pkt.id);
            appendTerminalLines('attacker', [
              { type: 'alert', text: '[EXFILTRATED] 142 rows from users table: admin ($2b$12$9x...), cfo_lee ($2b$12$7k...)' },
            ]);
          }

          // Port Scan chain
          if (pkt.attackType === 'port-scan' && pkt.shortTag.startsWith(':')) {
            const attackerNode = currentNodes.find((n) => n.role === 'attacker');
            const port = pkt.meta?.scannedPort ?? 80;
            const portEntry = arrivedNode.ports.find((p) => p.port === port);
            const isOpen = portEntry ? portEntry.state === 'open' : port === 80 || port === 443;
            const service = portEntry?.service ?? 'unknown';
            if (attackerNode) {
              const replyPath = findPath(currentLinks, arrivedNode.id, attackerNode.id, firewallPlacedRef.current);
              newlySpawned.push(buildPortScanReplyPacket(arrivedNode, attackerNode, port, service, isOpen, replyPath));
            }
          }

          if (pkt.attackType === 'port-scan' && (pkt.shortTag === 'OPEN' || pkt.shortTag === 'RST')) {
            const port = pkt.meta?.scannedPort ?? 80;
            const state = pkt.meta?.portState ?? 'closed';
            if (state === 'open') {
              recordExploitOutcome(pkt.id);
            }
            const webNode = currentNodes.find((n) => n.role === 'webserver');
            const svc = webNode?.ports.find((p) => p.port === port)?.service ?? 'tcp';
            setPortScanResults((prev) => {
              const next = prev.filter((r) => r.port !== port);
              return [...next, { port, service: svc, state }].sort((a, b) => a.port - b.port);
            });
            appendTerminalLines('attacker', [
              { type: state === 'open' ? 'alert' : 'output', text: `${String(port).padEnd(8)} ${state.padEnd(9)} ${svc}` },
            ]);
          }

          // DNS Spoofing delivery
          if (pkt.attackType === 'dns-spoof' && pkt.meta?.dnsDomain && pkt.meta?.dnsResolvedIp) {
            recordExploitOutcome(pkt.id);
            setDnsPoisoned(true);
            setDnsCache((prev) =>
              prev.map((d) =>
                d.domain === pkt.meta!.dnsDomain
                  ? { ...d, ip: pkt.meta!.dnsResolvedIp!, status: 'spoofed' }
                  : d
              )
            );
            setNodes((ns) =>
              ns.map((n) =>
                n.id === arrivedNode.id || n.role === 'rogue' ? { ...n, status: 'poisoned' } : n
              )
            );
          }

          // Redirected client traffic arriving at rogue server
          if (pkt.meta?.isRogueRedirect && arrivedNode.role === 'rogue') {
            recordExploitOutcome(pkt.id);
          }

          // Diagnostic ICMP Ping
          if (pkt.protocol === 'ICMP' && pkt.shortTag === 'PING') {
            const srcNode = currentNodes.find((n) => n.id === pkt.srcNodeId);
            if (srcNode) {
              const replyPath = findPath(currentLinks, arrivedNode.id, srcNode.id);
              newlySpawned.push(buildIcmpPingPacket(arrivedNode, srcNode, replyPath, true));
            }
          }

          if (pkt.protocol === 'ICMP' && pkt.shortTag === 'PONG') {
            appendTerminalLines(arrivedNode.id, [
              { type: 'success', text: `64 bytes from ${pkt.srcIp}: icmp_seq=1 ttl=64 time=1.4 ms` },
            ]);
          }
        }

        return [...remaining, ...newlySpawned].slice(-36);
      });

      if (newlySpawned.length > 0 || updatedCapturedMap.size > 0) {
        for (const spawned of newlySpawned) {
          recordPacketSpawn(spawned);
        }
        setCapturedPackets((prev) => {
          const updated = prev.map((p) => updatedCapturedMap.get(p.id) ?? p);
          return [...newlySpawned, ...updated].slice(0, 130);
        });
      }
      queueMicrotask(syncMetricsCounters);
    },
    [
      addDropEffect,
      appendTerminalLines,
      markObjective,
      pushFirewallEvent,
      recordBlockedOutcome,
      recordExploitOutcome,
      recordPacketSpawn,
      syncMetricsCounters,
    ]
  );

  // Main animation frame loop
  useEffect(() => {
    let frameId: number;
    let lastTime = performance.now();

    const tick = (now: number) => {
      const dtSec = Math.min(0.08, (now - lastTime) / 1000);
      lastTime = now;

      if (!isPausedRef.current) {
        const hopSpeed = 1.15 * speedRef.current;
        processPacketStep(dtSec * hopSpeed);
      }
      frameId = requestAnimationFrame(tick);
    };

    frameId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frameId);
  }, [processPacketStep]);

  // Periodic background traffic + target load natural decay
  useEffect(() => {
    const initialTimer = setTimeout(() => {
      if (!isPausedRef.current) {
        spawnBaselinePacket();
      }
    }, 350);

    const interval = setInterval(() => {
      if (isPausedRef.current) return;

      spawnBaselinePacket();

      // Natural target load recovery when not under an active unmitigated DoS flood
      setNodes((ns) =>
        ns.map((n) => {
          if (n.synBacklog <= 6) return n;
          const sc = activeScenarioRef.current;
          const d = defensesRef.current;
          const underUnmitigatedDos =
            attackActiveRef.current &&
            ((sc === 'syn-flood' && !d.synCookies) ||
              (sc === 'http-flood' && !d.l7HttpRateLimit) ||
              (sc === 'udp-flood' && !d.udpRateLimit) ||
              (sc === 'icmp-flood' && !d.icmpRateLimit) ||
              (sc === 'ntp-amplification' && !d.ntpMonlistDisable) ||
              (sc === 'all-out-defense' &&
                (!firewallPlacedRef.current ||
                  !d.synCookies ||
                  !d.l7HttpRateLimit ||
                  !d.udpRateLimit ||
                  !d.icmpRateLimit ||
                  !d.ntpMonlistDisable)));
          if (underUnmitigatedDos) return n;
          const nextBacklog = Math.max(6, n.synBacklog - 15);
          return {
            ...n,
            synBacklog: nextBacklog,
            status: nextBacklog < 55 && n.status === 'under_attack' ? 'nominal' : n.status,
          };
        })
      );
    }, Math.round(2500 / speed));

    return () => {
      clearTimeout(initialTimer);
      clearInterval(interval);
    };
  }, [spawnBaselinePacket, speed, topologyId]);

  // Attack wave generator when attackActive is true
  useEffect(() => {
    if (!attackActive) return;

    const baseMs =
      activeScenario === 'all-out-defense'
        ? 550
        : activeScenario === 'syn-flood'
        ? 420
        : activeScenario === 'http-flood'
        ? 480
        : activeScenario === 'udp-flood'
        ? 620
        : activeScenario === 'icmp-flood'
        ? 580
        : activeScenario === 'port-scan'
        ? 900
        : activeScenario === 'ntp-amplification'
        ? 1800
        : activeScenario === 'email-hijacking' || activeScenario === 'sql-injection'
        ? 2200
        : 1650;

    const interval = setInterval(() => {
      if (isPausedRef.current) return;
      spawnAttackWave();
    }, Math.round(baseMs / speed));

    return () => clearInterval(interval);
  }, [attackActive, activeScenario, speed, spawnAttackWave]);

  // 1-second rolling telemetry sampler for Attack Metrics Dashboard Widget
  useEffect(() => {
    const interval = setInterval(() => {
      if (isPausedRef.current) return;

      const bucket = metricsBucketRef.current;
      metricsBucketRef.current = { packets: 0, bytes: 0, exploits: 0, blocked: 0 };

      const totals = metricsTotalsRef.current;
      const pps = bucket.packets;
      if (pps > totals.peakPps) {
        totals.peakPps = pps;
      }

      const kbps = Math.round((bucket.bytes * 8) / 1000);
      const maxTargetLoad = nodesRef.current.reduce(
        (m, n) => (n.role === 'webserver' || n.role === 'database' ? Math.max(m, n.synBacklog) : m),
        0
      );
      const byteUtilPct = (kbps / 120) * 100;
      const rawBwPct = Math.round(
        Math.min(
          100,
          Math.max(byteUtilPct, pps > 0 ? Math.max(2, maxTargetLoad * 0.85) : 0)
        )
      );

      const totalAttempted = totals.exploits + totals.blocked;
      const mitigationRatePct =
        totalAttempted > 0 ? Math.round((totals.blocked / totalAttempted) * 100) : 0;

      setAttackMetrics((prev) => ({
        pps,
        peakPps: totals.peakPps,
        kbps,
        bandwidthPct: rawBwPct,
        successfulExploits: totals.exploits,
        blockedPackets: totals.blocked,
        mitigationRatePct,
        totalPackets: totals.totalPackets,
        history: [
          ...prev.history.slice(-(SPARKLINE_POINTS - 1)),
          {
            pps,
            bandwidthPct: rawBwPct,
            exploitsDelta: bucket.exploits,
            blockedDelta: bucket.blocked,
          },
        ],
      }));
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  const resetForTopology = useCallback((nextTopologyId: TopologyId, nextScenarioId: ScenarioId) => {
    resetPacketCounter();
    const freshNodes = createInitialNodes(nextTopologyId);
    setTopologyId(nextTopologyId);
    setNodes(freshNodes);
    setSelectedNodeId('attacker');
    setInFlightPackets([]);
    setCapturedPackets([]);
    setSelectedPacketId(null);
    setDropEffects([]);
    setDefenses(INITIAL_DEFENSES);
    setAttackActive(false);
    setIsPaused(false);
    setArpPoisoned(false);
    setDnsPoisoned(false);
    setWifiEvilTwinActive(false);
    setFirewallPlaced(nextScenarioId !== 'all-out-defense' && nextTopologyId !== 'firewall-sandbox');
    setArpTable(createInitialArpTable(freshNodes));
    setDnsCache(createInitialDnsCache(freshNodes));
    setFirewallEvents([]);
    setPortScanResults([]);
    setCompletedObjectives({});
    setTerminals(createWelcomeTerminals(freshNodes, nextScenarioId));
    portScanCursorRef.current = 0;
    allOutCursorRef.current = 0;
    metricsBucketRef.current = { packets: 0, bytes: 0, exploits: 0, blocked: 0 };
    metricsTotalsRef.current = { exploits: 0, blocked: 0, totalPackets: 0, peakPps: 0 };
    countedSpawnIdsRef.current.clear();
    countedOutcomeIdsRef.current.clear();
    setAttackMetrics(createInitialAttackMetrics());
  }, []);

  const selectScenario = useCallback(
    (scenarioId: ScenarioId) => {
      setActiveScenario(scenarioId);
      resetForTopology(SCENARIOS[scenarioId].defaultTopologyId, scenarioId);
    },
    [resetForTopology]
  );

  const selectTopology = useCallback(
    (nextTopologyId: TopologyId) => {
      resetForTopology(nextTopologyId, activeScenarioRef.current);
    },
    [resetForTopology]
  );

  const resetLab = useCallback(() => {
    resetForTopology(topologyIdRef.current, activeScenarioRef.current);
  }, [resetForTopology]);

  const resetNodePositions = useCallback(() => {
    const template = TOPOLOGIES[topologyIdRef.current].nodes;
    setNodes((prev) =>
      prev.map((n) => {
        const orig = template.find((t) => t.id === n.id);
        return orig ? { ...n, x: orig.x, y: orig.y } : n;
      })
    );
  }, []);

  const moveNode = useCallback((nodeId: string, x: number, y: number) => {
    const clampedX = Math.max(58, Math.min(842, x));
    const clampedY = Math.max(52, Math.min(388, y));
    setNodes((prev) => prev.map((n) => (n.id === nodeId ? { ...n, x: clampedX, y: clampedY } : n)));
  }, []);

  const toggleAttack = useCallback(() => {
    setAttackActive((prev) => {
      const next = !prev;
      if (next) {
        setIsPaused(false);
        markObjective('launch-attack');
        spawnAttackWave(activeScenarioRef.current);
        appendTerminalLines('attacker', [
          {
            type: 'alert',
            text: `Started ${SCENARIOS[activeScenarioRef.current].name}: ${SCENARIOS[activeScenarioRef.current].attackCommandExample}`,
          },
        ]);
      } else {
        setWifiEvilTwinActive(false);
        appendTerminalLines('attacker', [{ type: 'info', text: 'Stopped active attack stream.' }]);
      }
      return next;
    });
  }, [appendTerminalLines, markObjective, spawnAttackWave]);

  const stepForward = useCallback(() => {
    setIsPaused(true);
    if (inFlightPackets.length === 0) {
      if (attackActiveRef.current) {
        spawnAttackWave();
      } else {
        spawnBaselinePacket();
      }
    } else {
      processPacketStep(0.38);
    }
  }, [inFlightPackets.length, processPacketStep, spawnAttackWave, spawnBaselinePacket]);

  const toggleDefense = useCallback(
    (key: DefenseKey, forcedValue?: boolean) => {
      setDefenses((prev) => {
        const nextVal = forcedValue !== undefined ? forcedValue : !prev[key];
        const nextState = { ...prev, [key]: nextVal };

        if (key === 'dynamicArpInspection' && nextVal) {
          setArpPoisoned(false);
          setArpTable(createInitialArpTable(nodesRef.current));
          setNodes((ns) =>
            ns.map((n) =>
              n.role === 'switch'
                ? { ...n, status: 'defended' }
                : n.status === 'poisoned'
                ? { ...n, status: 'nominal' }
                : n
            )
          );
        }

        if (key === 'dnssecValidation' && nextVal) {
          setDnsPoisoned(false);
          setDnsCache(createInitialDnsCache(nodesRef.current));
          setNodes((ns) =>
            ns.map((n) =>
              n.role === 'dns'
                ? { ...n, status: 'defended' }
                : n.status === 'poisoned'
                ? { ...n, status: 'nominal' }
                : n
            )
          );
        }

        if (key === 'vpnWpa3Encryption' && nextVal) {
          setNodes((ns) =>
            ns.map((n) => (n.role === 'wifi_ap' || n.role === 'client' ? { ...n, status: 'defended' } : n))
          );
        }

        if (key === 'spfDkimDmarc' && nextVal) {
          setNodes((ns) =>
            ns.map((n) =>
              n.role === 'mail'
                ? { ...n, status: 'defended' }
                : n.status === 'compromised'
                ? { ...n, status: 'nominal' }
                : n
            )
          );
        }

        if (key === 'ntpMonlistDisable' && nextVal) {
          setNodes((ns) => ns.map((n) => (n.role === 'ntp' ? { ...n, status: 'defended' } : n)));
        }

        if (key === 'urpfIpFiltering' && nextVal) {
          setNodes((ns) =>
            ns.map((n) =>
              n.role === 'router'
                ? { ...n, status: 'defended' }
                : n.status === 'compromised'
                ? { ...n, status: 'nominal' }
                : n
            )
          );
        }

        if (key === 'hstsCertPinning' && nextVal) {
          setNodes((ns) =>
            ns.map((n) =>
              n.role === 'client'
                ? { ...n, status: 'defended' }
                : n.status === 'poisoned'
                ? { ...n, status: 'nominal' }
                : n
            )
          );
        }

        if (
          (key === 'synCookies' ||
            key === 'wafParameterizedSql' ||
            key === 'firewallPortFilter' ||
            key === 'l7HttpRateLimit' ||
            key === 'udpRateLimit' ||
            key === 'icmpRateLimit') &&
          nextVal
        ) {
          setNodes((ns) =>
            ns.map((n) =>
              n.role === 'firewall'
                ? { ...n, status: 'defended' }
                : n.status === 'compromised'
                ? { ...n, status: 'nominal' }
                : n
            )
          );
        }

        if ((SCENARIOS[activeScenarioRef.current].primaryDefense === key || activeScenarioRef.current === 'all-out-defense') && nextVal) {
          markObjective('enable-defense');
        }

        return nextState;
      });
    },
    [markObjective]
  );

  const toggleFirewallPlaced = useCallback(
    (forcedValue?: boolean) => {
      setFirewallPlaced((prev) => {
        const nextVal = forcedValue !== undefined ? forcedValue : !prev;
        if (nextVal) {
          markObjective('enable-firewall');
          addDropEffect('firewall', 'FW INLINE');
          pushFirewallEvent(
            'Perimeter Firewall',
            'ALERT',
            'FW-INLINE',
            'Perimeter Firewall placed inline between Edge Router and Core Switch.'
          );
        } else {
          pushFirewallEvent(
            'Perimeter Firewall',
            'ALERT',
            'FW-BYPASS',
            'Perimeter Firewall bypassed — direct unprotected path active.'
          );
        }
        return nextVal;
      });
    },
    [addDropEffect, markObjective, pushFirewallEvent]
  );

  const applyAllDefenses = useCallback(
    (enabled: boolean) => {
      setDefenses({
        synCookies: enabled,
        dynamicArpInspection: enabled,
        wafParameterizedSql: enabled,
        firewallPortFilter: enabled,
        dnssecValidation: enabled,
        vpnWpa3Encryption: enabled,
        spfDkimDmarc: enabled,
        urpfIpFiltering: enabled,
        hstsCertPinning: enabled,
        l7HttpRateLimit: enabled,
        udpRateLimit: enabled,
        icmpRateLimit: enabled,
        ntpMonlistDisable: enabled,
      });

      if (enabled) {
        setArpPoisoned(false);
        setDnsPoisoned(false);
        setArpTable(createInitialArpTable(nodesRef.current));
        setDnsCache(createInitialDnsCache(nodesRef.current));
        setNodes((ns) =>
          ns.map((n) =>
            n.role === 'firewall' || n.role === 'switch' || n.role === 'router' || n.role === 'dns' || n.role === 'mail' || n.role === 'ntp'
              ? { ...n, status: 'defended' }
              : n.status === 'compromised' || n.status === 'poisoned'
              ? { ...n, status: 'nominal' }
              : n
          )
        );
        markObjective('enable-defense');
        pushFirewallEvent(
          'Perimeter Firewall',
          'BLOCKED',
          'FULL-POLICY',
          'Applied all 13 Firewall & Network Defense rulesets.'
        );
      } else {
        setNodes((ns) =>
          ns.map((n) => (n.status === 'defended' ? { ...n, status: 'nominal' } : n))
        );
      }
    },
    [markObjective, pushFirewallEvent]
  );

  const selectPacket = useCallback(
    (packetId: string | null) => {
      setSelectedPacketId(packetId);
      if (packetId) {
        markObjective('inspect-packet');
      }
    },
    [markObjective]
  );

  const clearCapture = useCallback(() => {
    setCapturedPackets([]);
    setSelectedPacketId(null);
  }, []);

  const executeTerminalCommand = useCallback(
    (nodeId: string, commandText: string) => {
      const node = nodesRef.current.find((n) => n.id === nodeId);
      if (!node) return;

      appendTerminalLines(nodeId, [{ type: 'input', text: commandText }]);

      const result = interpretCommand(commandText, {
        node,
        allNodes: nodesRef.current,
        defenses: defensesRef.current,
        arpTable,
        dnsCache,
        activeScenario: activeScenarioRef.current,
        attackActive: attackActiveRef.current,
      });

      if (result.clearTerminal) {
        setTerminals((prev) => ({ ...prev, [nodeId]: [] }));
        return;
      }

      if (result.lines.length > 0) {
        appendTerminalLines(nodeId, result.lines);
      }

      if (result.startAttack) {
        setIsPaused(false);
        setActiveScenario(result.startAttack);
        setAttackActive(true);
        markObjective('launch-attack');
        spawnAttackWave(result.startAttack, result.triggerSingleSqlInjection);
      }

      if (result.stopAttack) {
        setAttackActive(false);
        setWifiEvilTwinActive(false);
      }

      if (result.toggleFirewallPlace !== undefined) {
        toggleFirewallPlaced(result.toggleFirewallPlace);
      }

      if (result.toggleAllDefenses !== undefined) {
        applyAllDefenses(result.toggleAllDefenses);
      }

      if (result.toggleDefense) {
        toggleDefense(result.toggleDefense.key, result.toggleDefense.enabled);
      }

      if (result.triggerPingTargetId) {
        const target = nodesRef.current.find((n) => n.id === result.triggerPingTargetId);
        if (target) {
          const path = findPath(TOPOLOGIES[topologyIdRef.current].links, node.id, target.id, firewallPlacedRef.current);
          enqueuePacket(buildIcmpPingPacket(node, target, path, false));
        }
      }

      if (result.triggerDnsQuery) {
        const dnsNode = nodesRef.current.find((n) => n.role === 'dns');
        if (dnsNode && dnsNode.id !== node.id) {
          const path = findPath(TOPOLOGIES[topologyIdRef.current].links, node.id, dnsNode.id, firewallPlacedRef.current);
          enqueuePacket(buildDnsQueryPacket(node, dnsNode, result.triggerDnsQuery, path));
        }
      }
    },
    [appendTerminalLines, applyAllDefenses, arpTable, dnsCache, enqueuePacket, markObjective, spawnAttackWave, toggleDefense, toggleFirewallPlaced]
  );

  const selectedPacket = useMemo(
    () =>
      capturedPackets.find((p) => p.id === selectedPacketId) ??
      inFlightPackets.find((p) => p.id === selectedPacketId) ??
      null,
    [capturedPackets, inFlightPackets, selectedPacketId]
  );

  const objectives: LabObjective[] = useMemo(() => {
    return SCENARIOS[activeScenario].objectives.map((obj) => ({
      ...obj,
      completed: Boolean(completedObjectives[obj.id]),
    }));
  }, [activeScenario, completedObjectives]);

  return {
    activeScenario,
    topologyId,
    nodes,
    links,
    selectedNodeId,
    setSelectedNodeId,
    inFlightPackets,
    capturedPackets,
    selectedPacket,
    selectedPacketId,
    selectPacket,
    clearCapture,
    dropEffects,
    defenses,
    toggleDefense,
    applyAllDefenses,
    firewallPlaced,
    toggleFirewallPlaced,
    isPaused,
    setIsPaused,
    speed,
    setSpeed,
    attackActive,
    toggleAttack,
    stepForward,
    selectScenario,
    selectTopology,
    resetLab,
    resetNodePositions,
    moveNode,
    arpTable,
    dnsCache,
    firewallEvents,
    portScanResults,
    arpPoisoned,
    dnsPoisoned,
    wifiEvilTwinActive,
    terminals,
    executeTerminalCommand,
    objectives,
    attackMetrics,
  };
}
