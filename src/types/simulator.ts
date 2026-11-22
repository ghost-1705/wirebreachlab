export type ScenarioCategory = 'mitm' | 'dos' | 'web-recon' | 'firewall-lab';

export type ScenarioId =
  | 'arp-spoof'
  | 'wifi-eavesdropping'
  | 'email-hijacking'
  | 'dns-spoof'
  | 'ip-spoofing'
  | 'https-spoofing'
  | 'syn-flood'
  | 'http-flood'
  | 'udp-flood'
  | 'icmp-flood'
  | 'ntp-amplification'
  | 'sql-injection'
  | 'port-scan'
  | 'all-out-defense';

export type TopologyId =
  | 'perimeter-dmz'
  | 'corporate-lan'
  | 'web-db-tier'
  | 'public-services'
  | 'firewall-sandbox';

export type DeviceRole =
  | 'attacker'
  | 'client'
  | 'switch'
  | 'router'
  | 'firewall'
  | 'webserver'
  | 'database'
  | 'dns'
  | 'rogue'
  | 'wifi_ap'
  | 'mail'
  | 'ntp';

export type NodeStatus =
  | 'nominal'
  | 'under_attack'
  | 'compromised'
  | 'defended'
  | 'poisoned';

export type ProtocolType =
  | 'TCP'
  | 'UDP'
  | 'HTTP'
  | 'HTTPS'
  | 'ARP'
  | 'SQL'
  | 'DNS'
  | 'ICMP'
  | 'SMTP'
  | 'NTP'
  | 'WIFI';

export type PacketCategory =
  | 'normal'
  | 'attack'
  | 'spoof'
  | 'blocked'
  | 'response';

export interface PortInfo {
  port: number;
  service: string;
  state: 'open' | 'closed' | 'filtered';
}

export interface NetworkNode {
  id: string;
  label: string;
  hostname: string;
  role: DeviceRole;
  ip: string;
  mac: string;
  subnet: string;
  x: number;
  y: number;
  status: NodeStatus;
  os: string;
  ports: PortInfo[];
  synBacklog: number; // 0 - 100 (target load / backlog / bandwidth saturation)
  interceptedCount: number;
}

export interface NetworkLink {
  id: string;
  sourceId: string;
  targetId: string;
  bandwidth: string;
  sourceInterface: string;
  targetInterface: string;
}

export interface TopologyDefinition {
  id: TopologyId;
  name: string;
  shortName: string;
  description: string;
  nodes: Omit<NetworkNode, 'status' | 'synBacklog' | 'interceptedCount'>[];
  links: NetworkLink[];
}

export interface PacketLayerField {
  label: string;
  value: string;
  highlight?: 'attack' | 'spoof' | 'blocked' | 'normal';
}

export interface PacketLayers {
  l2: {
    title: string;
    fields: PacketLayerField[];
  };
  l3?: {
    title: string;
    fields: PacketLayerField[];
  };
  l4?: {
    title: string;
    fields: PacketLayerField[];
  };
  l7?: {
    title: string;
    fields: PacketLayerField[];
  };
}

export interface SimulatedPacket {
  id: string;
  seqNo: number;
  timestamp: string;
  protocol: ProtocolType;
  category: PacketCategory;
  shortTag: string;
  summary: string;
  srcNodeId: string;
  dstNodeId: string;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  path: string[];
  currentHopIndex: number;
  progress: number; // 0 to 1 along current hop
  status: 'in_flight' | 'delivered' | 'dropped';
  droppedAtNodeId?: string;
  dropReason?: string;
  lengthBytes: number;
  layers: PacketLayers;
  rawPayload: string;
  hexLines: { offset: string; hex: string; ascii: string }[];
  educationalNote: string;
  attackType?: ScenarioId;
  meta?: {
    scannedPort?: number;
    portState?: 'open' | 'closed' | 'filtered';
    spoofTargetIp?: string;
    spoofMac?: string;
    dnsDomain?: string;
    dnsResolvedIp?: string;
    sqlQuery?: string;
    isMitmDetour?: boolean;
    isRogueRedirect?: boolean;
    udpPort?: number;
    isAmplified?: boolean;
    isSpoofedEmail?: boolean;
    isWifiSniff?: boolean;
    isRogueTls?: boolean;
  };
}

export interface DropEffect {
  id: string;
  nodeId: string;
  label: string;
  createdAt: number;
}

export interface DefenseState {
  synCookies: boolean;
  dynamicArpInspection: boolean;
  wafParameterizedSql: boolean;
  firewallPortFilter: boolean;
  dnssecValidation: boolean;
  vpnWpa3Encryption: boolean;
  spfDkimDmarc: boolean;
  urpfIpFiltering: boolean;
  hstsCertPinning: boolean;
  l7HttpRateLimit: boolean;
  udpRateLimit: boolean;
  icmpRateLimit: boolean;
  ntpMonlistDisable: boolean;
}

export type DefenseKey = keyof DefenseState;

export interface DefenseDefinition {
  key: DefenseKey;
  name: string;
  enforcedBy: string;
  scenarioId: ScenarioId;
  cliFlag: string;
  description: string;
  mechanism: string;
}

export interface TerminalLine {
  id: string;
  type: 'input' | 'output' | 'error' | 'alert' | 'success' | 'info';
  text: string;
  timestamp?: string;
}

export interface ArpEntry {
  ip: string;
  mac: string;
  interfaceName: string;
  status: 'valid' | 'poisoned';
  ownerLabel: string;
}

export interface DnsCacheEntry {
  domain: string;
  ip: string;
  ttl: number;
  status: 'verified' | 'spoofed';
}

export interface FirewallEvent {
  id: string;
  timestamp: string;
  nodeLabel: string;
  action: 'BLOCKED' | 'ALERT' | 'ALLOWED';
  rule: string;
  detail: string;
}

export interface LabObjective {
  id: string;
  title: string;
  hint: string;
  completed: boolean;
}

export interface QuickCommand {
  label: string;
  command: string;
  roles: DeviceRole[];
  kind: 'attack' | 'diagnostic' | 'defense';
}

export interface ScenarioDefinition {
  id: ScenarioId;
  category: ScenarioCategory;
  name: string;
  shortLabel: string;
  layerBadge: string;
  loadMeterLabel?: string;
  defaultTopologyId: TopologyId;
  primaryDefense: DefenseKey;
  summary: string;
  howItWorks: string;
  mitigationSummary: string;
  attackCommandExample: string;
  quickCommands: QuickCommand[];
  objectives: Omit<LabObjective, 'completed'>[];
}

export type PlaybackSpeed = 0.5 | 1 | 2;

export interface AttackMetricsSample {
  pps: number;
  bandwidthPct: number;
  exploitsDelta: number;
  blockedDelta: number;
}

export interface AttackMetricsState {
  pps: number;
  peakPps: number;
  kbps: number;
  bandwidthPct: number;
  successfulExploits: number;
  blockedPackets: number;
  mitigationRatePct: number;
  totalPackets: number;
  history: AttackMetricsSample[];
}

