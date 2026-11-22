import {
  NetworkNode,
  PacketCategory,
  PacketLayers,
  ProtocolType,
  ScenarioId,
  SimulatedPacket,
} from '../types/simulator';

let packetCounter = 1;

export function resetPacketCounter() {
  packetCounter = 1;
}

export function formatSimTime(): string {
  const now = new Date();
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  const ms = String(now.getMilliseconds()).padStart(3, '0');
  return `${hh}:${mm}:${ss}.${ms}`;
}

export function buildHexDump(headerSeed: string, payload: string): { offset: string; hex: string; ascii: string }[] {
  const combined = `${headerSeed}${payload}`;
  const bytes: number[] = [];
  for (let i = 0; i < Math.min(combined.length, 96); i++) {
    bytes.push(combined.charCodeAt(i) & 0xff);
  }
  while (bytes.length < 32) {
    bytes.push(0x00);
  }

  const lines: { offset: string; hex: string; ascii: string }[] = [];
  for (let row = 0; row < bytes.length; row += 16) {
    const slice = bytes.slice(row, row + 16);
    const offset = row.toString(16).padStart(4, '0');
    const hex = slice
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ')
      .padEnd(47, ' ');
    const ascii = slice
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push({ offset, hex, ascii });
  }
  return lines;
}

export function randomSpoofedIp(): string {
  const a = 45 + Math.floor(Math.random() * 140);
  const b = 10 + Math.floor(Math.random() * 230);
  const c = 1 + Math.floor(Math.random() * 250);
  const d = 2 + Math.floor(Math.random() * 250);
  return `${a}.${b}.${c}.${d}`;
}

export function randomEphemeralPort(): number {
  return 49152 + Math.floor(Math.random() * 15000);
}

interface BuildPacketArgs {
  protocol: ProtocolType;
  category: PacketCategory;
  shortTag: string;
  summary: string;
  srcNode: NetworkNode;
  dstNode: NetworkNode;
  overrideSrcIp?: string;
  overrideDstIp?: string;
  srcPort?: number;
  dstPort?: number;
  path: string[];
  layers: PacketLayers;
  rawPayload: string;
  educationalNote: string;
  attackType?: ScenarioId;
  meta?: SimulatedPacket['meta'];
}

export function createPacket(args: BuildPacketArgs): SimulatedPacket {
  const seqNo = packetCounter++;
  const srcIp = args.overrideSrcIp ?? args.srcNode.ip;
  const dstIp = args.overrideDstIp ?? args.dstNode.ip;
  const headerSeed = `${args.protocol}|${srcIp}>${dstIp}|`;
  const hexLines = buildHexDump(headerSeed, args.rawPayload);

  return {
    id: `pkt-${seqNo}-${Math.random().toString(36).slice(2, 6)}`,
    seqNo,
    timestamp: formatSimTime(),
    protocol: args.protocol,
    category: args.category,
    shortTag: args.shortTag,
    summary: args.summary,
    srcNodeId: args.srcNode.id,
    dstNodeId: args.dstNode.id,
    srcIp,
    dstIp,
    srcPort: args.srcPort,
    dstPort: args.dstPort,
    path: args.path,
    currentHopIndex: 0,
    progress: 0,
    status: 'in_flight',
    lengthBytes: Math.max(54, 42 + args.rawPayload.length),
    layers: args.layers,
    rawPayload: args.rawPayload,
    hexLines,
    educationalNote: args.educationalNote,
    attackType: args.attackType,
    meta: args.meta,
  };
}

export function buildNormalHttpPacket(
  src: NetworkNode,
  dst: NetworkNode,
  path: string[],
  isMitmDetour = false,
  isRogueRedirect = false
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const payload = isRogueRedirect
    ? `POST /signin HTTP/1.1\r\nHost: portal.corp.local\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=j.patel&pass=Winter2026!`
    : `GET /dashboard HTTP/1.1\r\nHost: ${dst.hostname}\r\nAccept: text/html\r\nCookie: session_id=9a81f3c2e04b`;

  const category: PacketCategory = isRogueRedirect || isMitmDetour ? 'spoof' : 'normal';
  const shortTag = isRogueRedirect ? 'HIJACK' : isMitmDetour ? 'MITM' : 'HTTP';

  return createPacket({
    protocol: 'HTTP',
    category,
    shortTag,
    summary: isRogueRedirect
      ? `POST /signin → Rogue Server (${dst.ip}) via poisoned DNS`
      : isMitmDetour
      ? `GET /dashboard (Intercepted via MITM ARP detour)`
      : `GET /dashboard HTTP/1.1 (${src.hostname} → ${dst.hostname})`,
    srcNode: src,
    dstNode: dst,
    srcPort,
    dstPort: 80,
    path,
    rawPayload: payload,
    educationalNote: isRogueRedirect
      ? 'Because the client cached a forged DNS A-record, this legitimate login request and plaintext credentials were silently sent to the Rogue Phishing Server.'
      : isMitmDetour
      ? 'Due to a poisoned ARP table, the Victim addressed the Ethernet frame to the Attacker MAC. The Attacker reads the unencrypted session cookie before forwarding it.'
      : 'Baseline legitimate HTTP request traversing the expected route with valid Ethernet MAC and IPv4 addressing.',
    meta: { isMitmDetour, isRogueRedirect },
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: src.mac },
          {
            label: 'Destination MAC',
            value: isMitmDetour ? 'DE:AD:BE:EF:66:66 (Attacker MITM)' : dst.mac,
            highlight: isMitmDetour ? 'spoof' : 'normal',
          },
          { label: 'EtherType', value: '0x0800 (IPv4)' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: src.ip },
          {
            label: 'Destination IP',
            value: isRogueRedirect ? `${dst.ip} (Spoofed A-Record)` : dst.ip,
            highlight: isRogueRedirect ? 'spoof' : 'normal',
          },
          { label: 'TTL', value: '64' },
          { label: 'Protocol', value: '6 (TCP)' },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: '80 (HTTP)' },
          { label: 'TCP Flags', value: '[PSH, ACK]' },
          { label: 'Window Size', value: '64240' },
        ],
      },
      l7: {
        title: 'Hypertext Transfer Protocol (Layer 7)',
        fields: [
          { label: 'Method & URI', value: isRogueRedirect ? 'POST /signin' : 'GET /dashboard' },
          {
            label: 'Sensitive Data',
            value: isRogueRedirect
              ? 'user=j.patel&pass=Winter2026! (Exposed)'
              : 'Cookie: session_id=9a81f3c2e04b',
            highlight: isRogueRedirect || isMitmDetour ? 'spoof' : 'normal',
          },
        ],
      },
    },
  });
}

export function buildSynFloodPacket(
  attacker: NetworkNode,
  target: NetworkNode,
  path: string[]
): SimulatedPacket {
  const spoofedIp = randomSpoofedIp();
  const srcPort = randomEphemeralPort();
  const seq = 100000 + Math.floor(Math.random() * 899999);
  const payload = `TCP_SYN_FLOOD src=${spoofedIp}:${srcPort} dst=${target.ip}:80 seq=${seq} flags=SYN win=512`;

  return createPacket({
    protocol: 'TCP',
    category: 'attack',
    shortTag: 'SYN',
    summary: `TCP SYN Flood ${spoofedIp}:${srcPort} → ${target.ip}:80 [SYN] Seq=${seq}`,
    srcNode: attacker,
    dstNode: target,
    overrideSrcIp: spoofedIp,
    srcPort,
    dstPort: 80,
    path,
    rawPayload: payload,
    attackType: 'syn-flood',
    educationalNote:
      'Spoofed source IP with only the SYN flag set. The server reserves backlog memory waiting for a final ACK that will never arrive because SYN-ACK replies go to unreachable spoofed hosts.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac },
          { label: 'Destination MAC', value: target.mac },
          { label: 'EtherType', value: '0x0800 (IPv4)' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: `${spoofedIp} (Spoofed)`, highlight: 'attack' },
          { label: 'Destination IP', value: target.ip },
          { label: 'TTL', value: '64' },
          { label: 'Protocol', value: '6 (TCP)' },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: '80 (HTTP)' },
          { label: 'Flags', value: '0x002 [SYN]', highlight: 'attack' },
          { label: 'Sequence Number', value: String(seq) },
          { label: 'Ack Number', value: '0' },
        ],
      },
    },
  });
}

export function buildArpSpoofPacket(
  attacker: NetworkNode,
  victim: NetworkNode,
  impersonatedNode: NetworkNode,
  path: string[]
): SimulatedPacket {
  const payload = `ARP_REPLY op=2 sender_ip=${impersonatedNode.ip} sender_mac=${attacker.mac} target_ip=${victim.ip} target_mac=${victim.mac}`;

  return createPacket({
    protocol: 'ARP',
    category: 'spoof',
    shortTag: 'ARP',
    summary: `Gratuitous ARP Reply: ${impersonatedNode.ip} is at ${attacker.mac} (Forged)`,
    srcNode: attacker,
    dstNode: victim,
    overrideSrcIp: impersonatedNode.ip,
    path,
    rawPayload: payload,
    attackType: 'arp-spoof',
    meta: {
      spoofTargetIp: impersonatedNode.ip,
      spoofMac: attacker.mac,
    },
    educationalNote:
      'Unsolicited ARP Reply (Opcode 2) falsely claiming the Gateway IP belongs to the Attacker MAC address. Without Dynamic ARP Inspection, the victim blindly overwrites its ARP cache.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac, highlight: 'spoof' },
          { label: 'Destination MAC', value: victim.mac },
          { label: 'EtherType', value: '0x0806 (ARP)' },
        ],
      },
      l4: {
        title: 'Address Resolution Protocol (Layer 2/3)',
        fields: [
          { label: 'Opcode', value: '2 (ARP Reply — Unsolicited)', highlight: 'spoof' },
          { label: 'Sender IP (Claimed)', value: `${impersonatedNode.ip} (${impersonatedNode.label})`, highlight: 'spoof' },
          { label: 'Sender MAC (Attacker)', value: attacker.mac, highlight: 'spoof' },
          { label: 'Target IP', value: victim.ip },
          { label: 'Target MAC', value: victim.mac },
        ],
      },
    },
  });
}

export function buildSqlInjectionHttpPacket(
  attacker: NetworkNode,
  webServer: NetworkNode,
  path: string[],
  injectedInput = "' OR '1'='1'--"
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const payload = `POST /api/login HTTP/1.1\r\nHost: ${webServer.ip}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin${injectedInput}&password=x`;

  return createPacket({
    protocol: 'HTTP',
    category: 'attack',
    shortTag: 'SQLi',
    summary: `POST /api/login payload="admin${injectedInput}"`,
    srcNode: attacker,
    dstNode: webServer,
    srcPort,
    dstPort: 80,
    path,
    rawPayload: payload,
    attackType: 'sql-injection',
    meta: { sqlQuery: injectedInput },
    educationalNote:
      'Malicious SQL syntax embedded inside the HTTP username parameter. The quote closes the string literal, OR 1=1 makes the WHERE clause always true, and -- comments out the password check.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac },
          { label: 'Destination MAC', value: webServer.mac },
          { label: 'EtherType', value: '0x0800 (IPv4)' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: attacker.ip },
          { label: 'Destination IP', value: webServer.ip },
          { label: 'TTL', value: '62' },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: '80 (HTTP)' },
          { label: 'Flags', value: '[PSH, ACK]' },
        ],
      },
      l7: {
        title: 'HTTP Application Payload (Layer 7)',
        fields: [
          { label: 'Request Line', value: 'POST /api/login HTTP/1.1' },
          { label: 'Injected Form Body', value: `username=admin${injectedInput}&password=x`, highlight: 'attack' },
        ],
      },
    },
  });
}

export function buildSqlQueryPacket(
  webServer: NetworkNode,
  dbServer: NetworkNode,
  path: string[],
  injectedInput = "' OR '1'='1'--"
): SimulatedPacket {
  const query = `SELECT id, username, role, password_hash FROM users WHERE username='admin${injectedInput}' AND pass='x';`;

  return createPacket({
    protocol: 'SQL',
    category: 'attack',
    shortTag: 'SQL',
    summary: `MySQL Query: SELECT * FROM users WHERE username='admin${injectedInput}'`,
    srcNode: webServer,
    dstNode: dbServer,
    srcPort: randomEphemeralPort(),
    dstPort: 3306,
    path,
    rawPayload: query,
    attackType: 'sql-injection',
    meta: { sqlQuery: query },
    educationalNote:
      'Because the Web Server concatenated raw input without parameterized queries, the Database executes the altered tautology and matches every row in the users table.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: webServer.mac },
          { label: 'Destination MAC', value: dbServer.mac },
          { label: 'EtherType', value: '0x0800 (IPv4)' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: webServer.ip },
          { label: 'Destination IP', value: dbServer.ip },
          { label: 'TTL', value: '64' },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Destination Port', value: '3306 (MySQL)' },
          { label: 'Flags', value: '[PSH, ACK]' },
        ],
      },
      l7: {
        title: 'SQL Wire Protocol (Layer 7)',
        fields: [
          { label: 'Command', value: 'COM_QUERY (0x03)' },
          { label: 'Executed Statement', value: query, highlight: 'attack' },
        ],
      },
    },
  });
}

export function buildSqlExfilPacket(
  dbServer: NetworkNode,
  attacker: NetworkNode,
  path: string[]
): SimulatedPacket {
  const payload = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{"id":1,"user":"admin","hash":"$2b$12$9x..."},{"id":2,"user":"cfo_lee","hash":"$2b$12$7k..."},{"rows_leaked":142}]`;

  return createPacket({
    protocol: 'SQL',
    category: 'response',
    shortTag: 'LEAK',
    summary: `Data Exfiltration: 142 user rows returned (admin, cfo_lee, ...)`,
    srcNode: dbServer,
    dstNode: attacker,
    srcPort: 3306,
    dstPort: randomEphemeralPort(),
    path,
    rawPayload: payload,
    attackType: 'sql-injection',
    educationalNote:
      'Unauthorized database rows exfiltrated back through the web application to the attacker because the injected SQL bypassed authentication.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: dbServer.mac },
          { label: 'Destination MAC', value: attacker.mac },
          { label: 'EtherType', value: '0x0800 (IPv4)' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: dbServer.ip },
          { label: 'Destination IP', value: attacker.ip },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: '3306 / 80' },
          { label: 'Flags', value: '[PSH, ACK]' },
        ],
      },
      l7: {
        title: 'Leaked Result Set (Layer 7)',
        fields: [
          { label: 'Row Count', value: '142 records dumped', highlight: 'attack' },
          { label: 'Sample Data', value: 'admin ($2b$12$9x...), cfo_lee ($2b$12$7k...)', highlight: 'attack' },
        ],
      },
    },
  });
}

export function buildPortScanProbePacket(
  attacker: NetworkNode,
  target: NetworkNode,
  port: number,
  service: string,
  path: string[]
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const payload = `NMAP_SYN_PROBE target=${target.ip}:${port} (${service}) flags=SYN`;

  return createPacket({
    protocol: 'TCP',
    category: 'spoof',
    shortTag: `:${port}`,
    summary: `Nmap SYN Probe ${attacker.ip}:${srcPort} → ${target.ip}:${port} (${service})`,
    srcNode: attacker,
    dstNode: target,
    srcPort,
    dstPort: port,
    path,
    rawPayload: payload,
    attackType: 'port-scan',
    meta: { scannedPort: port },
    educationalNote: `Stealth TCP SYN probe targeting port ${port} (${service}). A SYN-ACK response confirms an open service; an RST indicates the port is closed; silence means filtered.`,
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac },
          { label: 'Destination MAC', value: target.mac },
          { label: 'EtherType', value: '0x0800 (IPv4)' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: attacker.ip },
          { label: 'Destination IP', value: target.ip },
          { label: 'TTL', value: '54' },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: `${port} (${service})`, highlight: 'spoof' },
          { label: 'Flags', value: '0x002 [SYN] (Stealth Recon)', highlight: 'spoof' },
          { label: 'Window Size', value: '1024 (Nmap Fingerprint)' },
        ],
      },
    },
  });
}

export function buildPortScanReplyPacket(
  target: NetworkNode,
  attacker: NetworkNode,
  port: number,
  service: string,
  isOpen: boolean,
  path: string[]
): SimulatedPacket {
  const flags = isOpen ? '[SYN, ACK]' : '[RST, ACK]';
  const payload = `TCP_REPLY port=${port} (${service}) state=${isOpen ? 'OPEN' : 'CLOSED'} flags=${flags}`;

  return createPacket({
    protocol: 'TCP',
    category: isOpen ? 'response' : 'normal',
    shortTag: isOpen ? 'OPEN' : 'RST',
    summary: `Port ${port} (${service}) ${isOpen ? 'OPEN → [SYN, ACK]' : 'CLOSED → [RST, ACK]'}`,
    srcNode: target,
    dstNode: attacker,
    srcPort: port,
    dstPort: randomEphemeralPort(),
    path,
    rawPayload: payload,
    attackType: 'port-scan',
    meta: { scannedPort: port, portState: isOpen ? 'open' : 'closed' },
    educationalNote: isOpen
      ? `Target replied with SYN-ACK on port ${port} (${service}), confirming to Nmap that this service is actively listening.`
      : `Target replied with RST-ACK on port ${port} (${service}), indicating no daemon is listening on this port.`,
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: target.mac },
          { label: 'Destination MAC', value: attacker.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: target.ip },
          { label: 'Destination IP', value: attacker.ip },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: `${port} (${service})` },
          { label: 'Flags', value: flags, highlight: isOpen ? 'spoof' : 'normal' },
        ],
      },
    },
  });
}

export function buildDnsQueryPacket(
  client: NetworkNode,
  dnsServer: NetworkNode,
  domain: string,
  path: string[]
): SimulatedPacket {
  const txId = `0x${Math.floor(0x1000 + Math.random() * 0xefff).toString(16)}`;
  const payload = `DNS_QUERY txid=${txId} qname=${domain} qtype=A qclass=IN`;

  return createPacket({
    protocol: 'DNS',
    category: 'normal',
    shortTag: 'DNS?',
    summary: `Standard DNS Query A ${domain} (TxID ${txId})`,
    srcNode: client,
    dstNode: dnsServer,
    srcPort: randomEphemeralPort(),
    dstPort: 53,
    path,
    rawPayload: payload,
    meta: { dnsDomain: domain },
    educationalNote:
      'Unencrypted UDP/53 DNS query asking the resolver for the IPv4 A-record of the internal corporate portal.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: client.mac },
          { label: 'Destination MAC', value: dnsServer.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: client.ip },
          { label: 'Destination IP', value: dnsServer.ip },
          { label: 'Protocol', value: '17 (UDP)' },
        ],
      },
      l4: {
        title: 'User Datagram Protocol (Layer 4)',
        fields: [
          { label: 'Destination Port', value: '53 (DNS)' },
          { label: 'Length', value: '44 bytes' },
        ],
      },
      l7: {
        title: 'Domain Name System Query (Layer 7)',
        fields: [
          { label: 'Transaction ID', value: txId },
          { label: 'Question Name', value: domain },
          { label: 'Record Type', value: 'A (Host Address)' },
        ],
      },
    },
  });
}

export function buildDnsSpoofReplyPacket(
  attacker: NetworkNode,
  victim: NetworkNode,
  domain: string,
  rogueIp: string,
  path: string[]
): SimulatedPacket {
  const payload = `DNS_RESPONSE_FORGED qname=${domain} answer_A=${rogueIp} ttl=300 rrsig=MISSING`;

  return createPacket({
    protocol: 'DNS',
    category: 'spoof',
    shortTag: 'DNS!',
    summary: `Forged DNS Reply: ${domain} → ${rogueIp} (No RRSIG)`,
    srcNode: attacker,
    dstNode: victim,
    srcPort: 53,
    dstPort: randomEphemeralPort(),
    path,
    rawPayload: payload,
    attackType: 'dns-spoof',
    meta: { dnsDomain: domain, dnsResolvedIp: rogueIp },
    educationalNote:
      'Attacker raced the legitimate DNS server with an unsigned forged A-record pointing portal.corp.local to the Rogue Server IP. DNSSEC rejects this missing RRSIG signature.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac, highlight: 'spoof' },
          { label: 'Destination MAC', value: victim.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: `${attacker.ip} (Spoofing DNS)`, highlight: 'spoof' },
          { label: 'Destination IP', value: victim.ip },
          { label: 'Protocol', value: '17 (UDP)' },
        ],
      },
      l4: {
        title: 'User Datagram Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: '53 (DNS)' },
          { label: 'Checksum', value: '0x4f1a (Valid)' },
        ],
      },
      l7: {
        title: 'Domain Name System Response (Layer 7)',
        fields: [
          { label: 'Query Name', value: domain },
          { label: 'Forged Answer (A)', value: `${rogueIp} (Rogue Host)`, highlight: 'spoof' },
          { label: 'DNSSEC RRSIG', value: 'None / Invalid Signature', highlight: 'attack' },
        ],
      },
    },
  });
}

export function buildIcmpPingPacket(
  src: NetworkNode,
  dst: NetworkNode,
  path: string[],
  isReply = false
): SimulatedPacket {
  const payload = `ICMP_${isReply ? 'ECHO_REPLY' : 'ECHO_REQUEST'} seq=1 ttl=64 data=abcdef0123456789`;

  return createPacket({
    protocol: 'ICMP',
    category: isReply ? 'response' : 'normal',
    shortTag: isReply ? 'PONG' : 'PING',
    summary: `ICMP Echo ${isReply ? 'Reply' : 'Request'} ${src.ip} → ${dst.ip} ttl=64`,
    srcNode: src,
    dstNode: dst,
    path,
    rawPayload: payload,
    educationalNote: isReply
      ? 'ICMP Type 0 Echo Reply confirming Layer-3 reachability back from the destination host.'
      : 'ICMP Type 8 Echo Request generated by the terminal ping diagnostic command.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: src.mac },
          { label: 'Destination MAC', value: dst.mac },
          { label: 'EtherType', value: '0x0800 (IPv4)' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: src.ip },
          { label: 'Destination IP', value: dst.ip },
          { label: 'Protocol', value: '1 (ICMP)' },
        ],
      },
      l4: {
        title: 'Internet Control Message Protocol (Layer 3)',
        fields: [
          { label: 'Type', value: isReply ? '0 (Echo Reply)' : '8 (Echo Request)' },
          { label: 'Code', value: '0' },
          { label: 'Identifier', value: '0x14a2' },
        ],
      },
    },
  });
}

// ==================== NEW MITM PACKET BUILDERS ====================

export function buildWifiEavesdropPacket(
  client: NetworkNode,
  bankServer: NetworkNode,
  path: string[],
  encrypted = false
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const payload = encrypted
    ? `WG_VPN_ENC nonce=0x88f1c9a0 ciphertext=9e4b2a7d10fc3e81a529b0c7... [AEAD ChaCha20-Poly1305]`
    : `POST /checkout HTTP/1.1\r\nHost: bank.firstbank.com\r\nSSID: Cafe-Business-WiFi (Evil Twin)\r\n\r\ncard=4532-8910-4421-7790&cvv=482&login=alex.chen`;

  return createPacket({
    protocol: 'WIFI',
    category: encrypted ? 'normal' : 'spoof',
    shortTag: encrypted ? 'VPN' : 'WIFI',
    summary: encrypted
      ? `Encrypted WPA3 + VPN Tunnel (${client.ip} → ${bankServer.ip})`
      : `Evil Twin Sniffed: Card 4532-xxxx-7790 & Login over Rogue Wi-Fi`,
    srcNode: client,
    dstNode: bankServer,
    srcPort,
    dstPort: encrypted ? 51820 : 80,
    path,
    rawPayload: payload,
    attackType: 'wifi-eavesdropping',
    meta: { isWifiSniff: !encrypted, isMitmDetour: !encrypted },
    educationalNote: encrypted
      ? 'DEFENSE ACTIVE: Client connected to the verified WPA3-Enterprise AP with an active VPN tunnel. Even if wireless frames were captured, payment card data is encrypted.'
      : 'The victim associated with the attacker’s fraudulent Evil Twin Wi-Fi hotspot ("Cafe-Business-WiFi"). Payment card numbers and login credentials are exposed in cleartext as they traverse the rogue AP.',
    layers: {
      l2: {
        title: 'IEEE 802.11 Wireless LAN (Layer 2)',
        fields: [
          { label: 'Client MAC', value: client.mac },
          {
            label: 'Associated BSSID / SSID',
            value: encrypted ? '00:1C:B3:AA:00:01 (WPA3-Enterprise)' : 'DE:AD:BE:EF:55:66 (Evil Twin Open)',
            highlight: encrypted ? 'blocked' : 'spoof',
          },
          { label: 'Encryption', value: encrypted ? 'GCMP-256 + WireGuard VPN' : 'NONE (Open Rogue AP)', highlight: encrypted ? 'blocked' : 'attack' },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: client.ip },
          { label: 'Destination IP', value: bankServer.ip },
          { label: 'Protocol', value: encrypted ? '17 (UDP / VPN)' : '6 (TCP / Cleartext)' },
        ],
      },
      l7: {
        title: encrypted ? 'Encrypted VPN Payload (Layer 7)' : 'Intercepted Payment Payload (Layer 7)',
        fields: encrypted
          ? [{ label: 'Ciphertext', value: '9e4b2a7d10fc3e81a529... (Unreadable)', highlight: 'blocked' }]
          : [
              { label: 'Captured Payment Card', value: '4532-8910-4421-7790 (CVV 482)', highlight: 'attack' },
              { label: 'Captured Account', value: 'login=alex.chen', highlight: 'spoof' },
            ],
      },
    },
  });
}

export function buildEmailHijackPacket(
  attacker: NetworkNode,
  victim: NetworkNode,
  path: string[]
): SimulatedPacket {
  const payload = `MAIL FROM:<alerts@firstbank.com>\r\nRCPT TO:<user@corp.local>\r\nSubject: URGENT: Confirm Wire Transfer #88412\r\nReply-To: wire-verify@firstbank-desk.evil\r\n\r\nPlease reply with account PIN & wire confirmation code.`;

  return createPacket({
    protocol: 'SMTP',
    category: 'spoof',
    shortTag: 'SMTP!',
    summary: `Spoofed Bank Email: From <alerts@firstbank.com> (Reply-To attacker)`,
    srcNode: attacker,
    dstNode: victim,
    srcPort: randomEphemeralPort(),
    dstPort: 25,
    path,
    rawPayload: payload,
    attackType: 'email-hijacking',
    meta: { isSpoofedEmail: true },
    educationalNote:
      'Attacker forged the SMTP MAIL FROM header to impersonate FirstBank while setting Reply-To to an attacker-controlled address. SPF/DKIM/DMARC detects the unauthorized sender IP and rejects it.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac, highlight: 'spoof' },
          { label: 'Destination MAC', value: victim.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Actual Sender IP', value: `${attacker.ip} (Unauthorized Relay)`, highlight: 'attack' },
          { label: 'Destination IP', value: victim.ip },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Destination Port', value: '25 (SMTP)' },
          { label: 'Flags', value: '[PSH, ACK]' },
        ],
      },
      l7: {
        title: 'Simple Mail Transfer Protocol (Layer 7)',
        fields: [
          { label: 'Forged From', value: 'alerts@firstbank.com (SPF FAIL)', highlight: 'attack' },
          { label: 'Hijacked Reply-To', value: 'wire-verify@firstbank-desk.evil', highlight: 'spoof' },
          { label: 'DKIM Signature', value: 'Missing / Invalid', highlight: 'attack' },
        ],
      },
    },
  });
}

export function buildEmailVictimReplyPacket(
  victim: NetworkNode,
  attacker: NetworkNode,
  path: string[]
): SimulatedPacket {
  const payload = `MAIL FROM:<user@corp.local>\r\nRCPT TO:<wire-verify@firstbank-desk.evil>\r\nSubject: Re: Confirm Wire Transfer #88412\r\n\r\nRouting: 021000021 Acct: 99812041 PIN: 8824 — Approved $14,500 wire.`;

  return createPacket({
    protocol: 'SMTP',
    category: 'response',
    shortTag: 'WIRE',
    summary: `Victim Replied to Spoofed Email: Sent Account PIN & $14,500 Wire Auth`,
    srcNode: victim,
    dstNode: attacker,
    srcPort: randomEphemeralPort(),
    dstPort: 25,
    path,
    rawPayload: payload,
    attackType: 'email-hijacking',
    educationalNote:
      'Tricked by the spoofed bank sender header, the victim followed the fraudulent email instructions and sent account credentials and wire approval straight to the attacker.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: victim.mac },
          { label: 'Destination MAC', value: attacker.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: victim.ip },
          { label: 'Destination IP', value: `${attacker.ip} (Attacker Inbox)`, highlight: 'attack' },
        ],
      },
      l7: {
        title: 'Hijacked Email Reply (Layer 7)',
        fields: [
          { label: 'Exposed Banking Info', value: 'Acct 99812041 · PIN 8824 · $14,500 Wire', highlight: 'attack' },
        ],
      },
    },
  });
}

export function buildIpSpoofPacket(
  attacker: NetworkNode,
  target: NetworkNode,
  impersonatedIp: string,
  path: string[]
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const payload = `GET /internal-admin/session HTTP/1.1\r\nHost: ${target.ip}\r\nX-Forwarded-Trust: internal\r\n[FORGED_IP_HEADER src=${impersonatedIp}]`;

  return createPacket({
    protocol: 'TCP',
    category: 'spoof',
    shortTag: 'IP!',
    summary: `Forged Source IP ${impersonatedIp} (Real MAC: ${attacker.mac}) → ${target.ip}:80`,
    srcNode: attacker,
    dstNode: target,
    overrideSrcIp: impersonatedIp,
    srcPort,
    dstPort: 80,
    path,
    rawPayload: payload,
    attackType: 'ip-spoofing',
    meta: { spoofTargetIp: impersonatedIp },
    educationalNote:
      `Attacker forged the IPv4 Source IP field to ${impersonatedIp} to impersonate a trusted internal/website host. Compare Layer 2 Source MAC (${attacker.mac}) against the external ingress link — uRPF catches this mismatch.`,
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Actual Source MAC', value: `${attacker.mac} (External Attacker)`, highlight: 'attack' },
          { label: 'Destination MAC', value: target.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Forged Source IP', value: `${impersonatedIp} (Impersonated Host)`, highlight: 'spoof' },
          { label: 'Destination IP', value: target.ip },
          { label: 'TTL', value: '64' },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: '80 (HTTP)' },
          { label: 'Flags', value: '[SYN, PSH]' },
        ],
      },
    },
  });
}

export function buildHttpsSpoofPacket(
  client: NetworkNode,
  rogueHost: NetworkNode,
  path: string[]
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const payload = `TLSv1.3 Application Data [SNI: p0rtal-corp.local]\r\nCert-Issuer: CN=Rogue-SelfSigned-CA (UNTRUSTED)\r\nPOST /sso-login -> user=m.silva&pass=CorpPass99!`;

  return createPacket({
    protocol: 'HTTPS',
    category: 'spoof',
    shortTag: 'TLS!',
    summary: `Spoofed HTTPS (https://p0rtal-corp.local) — Self-Signed Rogue Cert`,
    srcNode: client,
    dstNode: rogueHost,
    srcPort,
    dstPort: 443,
    path,
    rawPayload: payload,
    attackType: 'https-spoofing',
    meta: { isRogueTls: true, isRogueRedirect: true },
    educationalNote:
      'Although the browser shows "HTTPS" in the address bar, the URL uses a lookalike zero (p0rtal-corp.local) and a rogue TLS certificate. Traffic is encrypted to the attacker, who decrypts the user’s SSO credentials.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: client.mac },
          { label: 'Destination MAC', value: rogueHost.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: client.ip },
          { label: 'Destination IP', value: `${rogueHost.ip} (Rogue HTTPS Server)`, highlight: 'spoof' },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Destination Port', value: '443 (HTTPS / TLS)' },
          { label: 'Flags', value: '[PSH, ACK]' },
        ],
      },
      l7: {
        title: 'TLS Handshake & Lookalike HTTPS (Layer 6/7)',
        fields: [
          { label: 'Lookalike SNI Host', value: 'https://p0rtal-corp.local (Zero "0")', highlight: 'spoof' },
          { label: 'Certificate Issuer', value: 'CN=Rogue-SelfSigned-CA (Pin Mismatch)', highlight: 'attack' },
          { label: 'Stolen Form Data', value: 'user=m.silva&pass=CorpPass99!', highlight: 'attack' },
        ],
      },
    },
  });
}

// ==================== NEW DOS / DDOS PACKET BUILDERS ====================

export function buildHttpFloodPacket(
  attacker: NetworkNode,
  webServer: NetworkNode,
  path: string[]
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const routes = ['/search?q=annual_report&limit=9999', '/checkout/recalculate?items=500', '/api/export?format=pdf&full=true'];
  const uri = routes[Math.floor(Math.random() * routes.length)];
  const payload = `GET ${uri} HTTP/1.1\r\nHost: ${webServer.hostname}\r\nUser-Agent: Mozilla/5.0 (Botnet-Node-${Math.floor(Math.random() * 900 + 100)})\r\nCache-Control: no-cache`;

  return createPacket({
    protocol: 'HTTP',
    category: 'attack',
    shortTag: 'GET!',
    summary: `L7 HTTP Flood: GET ${uri} (CPU-intensive query)`,
    srcNode: attacker,
    dstNode: webServer,
    srcPort,
    dstPort: 80,
    path,
    rawPayload: payload,
    attackType: 'http-flood',
    educationalNote:
      'Layer-7 HTTP Flood uses fully valid TCP connections and legitimate-looking GET requests with Cache-Control: no-cache to force maximum CPU and database allocation per request.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac },
          { label: 'Destination MAC', value: webServer.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: attacker.ip },
          { label: 'Destination IP', value: webServer.ip },
        ],
      },
      l4: {
        title: 'Transmission Control Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: '80 (HTTP)' },
          { label: 'Flags', value: '[PSH, ACK] (Valid Session)' },
        ],
      },
      l7: {
        title: 'HTTP Flood Request (Layer 7)',
        fields: [
          { label: 'Expensive URI', value: `GET ${uri}`, highlight: 'attack' },
          { label: 'Cache Bypass', value: 'Cache-Control: no-cache (Forces Origin CPU)', highlight: 'attack' },
        ],
      },
    },
  });
}

export function buildUdpFloodPacket(
  attacker: NetworkNode,
  target: NetworkNode,
  path: string[]
): SimulatedPacket {
  const srcPort = randomEphemeralPort();
  const randDstPort = 35000 + Math.floor(Math.random() * 28000);
  const payload = `UDP_FLOOD_JUNK dst_port=${randDstPort} len=1024 data=0xFF4A91C0...`;

  return createPacket({
    protocol: 'UDP',
    category: 'attack',
    shortTag: 'UDP',
    summary: `UDP Flood ${attacker.ip}:${srcPort} → ${target.ip}:${randDstPort} (Random Closed Port)`,
    srcNode: attacker,
    dstNode: target,
    srcPort,
    dstPort: randDstPort,
    path,
    rawPayload: payload,
    attackType: 'udp-flood',
    meta: { udpPort: randDstPort },
    educationalNote:
      `Stateless UDP datagram blasted at random closed port ${randDstPort}. The victim OS must check its port table and emit an ICMP Destination Unreachable packet for every single datagram.`,
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac },
          { label: 'Destination MAC', value: target.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: attacker.ip },
          { label: 'Destination IP', value: target.ip },
          { label: 'Protocol', value: '17 (UDP)' },
        ],
      },
      l4: {
        title: 'User Datagram Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: String(srcPort) },
          { label: 'Destination Port', value: `${randDstPort} (Random / Closed)`, highlight: 'attack' },
          { label: 'Payload Length', value: '1024 bytes (Junk Data)' },
        ],
      },
    },
  });
}

export function buildIcmpUnreachablePacket(
  target: NetworkNode,
  attacker: NetworkNode,
  closedPort: number,
  path: string[]
): SimulatedPacket {
  const payload = `ICMP_DEST_UNREACHABLE type=3 code=3 (Port ${closedPort} Unreachable)`;

  return createPacket({
    protocol: 'ICMP',
    category: 'response',
    shortTag: 'UNRCH',
    summary: `ICMP Type 3 Code 3: Port ${closedPort} Unreachable (${target.ip} → ${attacker.ip})`,
    srcNode: target,
    dstNode: attacker,
    path,
    rawPayload: payload,
    attackType: 'udp-flood',
    educationalNote:
      `Because nothing listens on UDP/${closedPort}, the target host was forced to waste CPU and outbound bandwidth generating this ICMP Destination Unreachable reply.`,
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: target.mac },
          { label: 'Destination MAC', value: attacker.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: target.ip },
          { label: 'Destination IP', value: attacker.ip },
          { label: 'Protocol', value: '1 (ICMP)' },
        ],
      },
      l4: {
        title: 'ICMP Error Message (Layer 3)',
        fields: [
          { label: 'Type / Code', value: 'Type 3 / Code 3 (Port Unreachable)', highlight: 'spoof' },
          { label: 'Triggered By', value: `Unsolicited UDP/${closedPort}` },
        ],
      },
    },
  });
}

export function buildIcmpFloodPacket(
  src: NetworkNode,
  dst: NetworkNode,
  path: string[],
  isReply = false
): SimulatedPacket {
  const seq = 100 + Math.floor(Math.random() * 8900);
  const payload = `ICMP_FLOOD_${isReply ? 'REPLY' : 'REQ'} seq=${seq} size=1472B pattern=0xAAAAAAAAAAAA...`;

  const pkt = createPacket({
    protocol: 'ICMP',
    category: isReply ? 'response' : 'attack',
    shortTag: isReply ? 'ECHO0' : 'ICMP!',
    summary: isReply
      ? `ICMP Flood Echo Reply (1472 B) ${src.ip} → ${dst.ip} [Outbound Saturated]`
      : `ICMP Ping Flood Echo Request (1472 B) ${src.ip} → ${dst.ip} Seq=${seq}`,
    srcNode: src,
    dstNode: dst,
    path,
    rawPayload: payload,
    attackType: 'icmp-flood',
    educationalNote: isReply
      ? 'Target server struggling to transmit a full 1472-byte ICMP Echo Reply for every flooded ping, consuming outbound link capacity.'
      : 'Oversized 1472-byte ICMP Type 8 Echo Request flood designed to saturate both inbound and outbound network bandwidth simultaneously.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: src.mac },
          { label: 'Destination MAC', value: dst.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP', value: src.ip },
          { label: 'Destination IP', value: dst.ip },
          { label: 'Total IP Length', value: '1500 bytes (Max MTU)', highlight: 'attack' },
          { label: 'Protocol', value: '1 (ICMP)' },
        ],
      },
      l4: {
        title: 'Internet Control Message Protocol (Layer 3)',
        fields: [
          { label: 'Type', value: isReply ? '0 (Echo Reply — Flooded)' : '8 (Echo Request — Flood)', highlight: isReply ? 'spoof' : 'attack' },
          { label: 'Sequence', value: String(seq) },
          { label: 'Payload Size', value: '1472 bytes' },
        ],
      },
    },
  });
  return { ...pkt, lengthBytes: 1514 };
}

export function buildNtpMonlistRequestPacket(
  attacker: NetworkNode,
  ntpServer: NetworkNode,
  victimServer: NetworkNode,
  path: string[]
): SimulatedPacket {
  const payload = `NTPv2 Mode=7 REQ_MON_GETLIST_1 (48 bytes) spoofed_src=${victimServer.ip}`;

  const pkt = createPacket({
    protocol: 'NTP',
    category: 'spoof',
    shortTag: 'MON?',
    summary: `Spoofed 48B NTP monlist Request (Src Forged: ${victimServer.ip}) → NTP Server`,
    srcNode: attacker,
    dstNode: ntpServer,
    overrideSrcIp: victimServer.ip,
    srcPort: randomEphemeralPort(),
    dstPort: 123,
    path,
    rawPayload: payload,
    attackType: 'ntp-amplification',
    meta: { spoofTargetIp: victimServer.ip },
    educationalNote:
      `Tiny 48-byte NTP Mode 7 "monlist" query with the Source IP forged to ${victimServer.ip}. The Open NTP Server will reflect an amplified response up to 200x larger straight at the victim!`,
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: attacker.mac },
          { label: 'Destination MAC', value: ntpServer.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Forged Source IP (Victim)', value: `${victimServer.ip} (Spoofed for Reflection)`, highlight: 'spoof' },
          { label: 'Destination IP', value: `${ntpServer.ip} (Open NTP Reflector)` },
          { label: 'Protocol', value: '17 (UDP)' },
        ],
      },
      l4: {
        title: 'User Datagram Protocol (Layer 4)',
        fields: [
          { label: 'Destination Port', value: '123 (NTP)' },
          { label: 'Datagram Size', value: '48 bytes (Tiny Trigger)' },
        ],
      },
      l7: {
        title: 'Network Time Protocol (Layer 7)',
        fields: [
          { label: 'NTP Mode / Command', value: 'Mode 7 · REQ_MON_GETLIST_1 (monlist)', highlight: 'attack' },
          { label: 'Expected Amplification', value: '1:50 to 1:200 reflection factor', highlight: 'spoof' },
        ],
      },
    },
  });
  return { ...pkt, lengthBytes: 48 };
}

export function buildNtpAmplifiedResponsePacket(
  ntpServer: NetworkNode,
  victimServer: NetworkNode,
  burstIndex: number,
  path: string[]
): SimulatedPacket {
  const payload = `NTPv2 Mode=7 MONLIST_RESPONSE chunk=${burstIndex}/3 (4800 bytes — 100x Amplified Reflection containing 600 cached peer records)`;

  const pkt = createPacket({
    protocol: 'NTP',
    category: 'attack',
    shortTag: 'AMP!',
    summary: `Reflected NTP Amplification Burst #${burstIndex} (4,800 B · 100x) → ${victimServer.ip}`,
    srcNode: ntpServer,
    dstNode: victimServer,
    srcPort: 123,
    dstPort: randomEphemeralPort(),
    path,
    rawPayload: payload,
    attackType: 'ntp-amplification',
    meta: { isAmplified: true },
    educationalNote:
      'Reflected UDP/123 monlist response from the Open NTP Server. Because the attacker forged the victim’s IP on a 48-byte request, the victim gets slammed with 100x amplified traffic.',
    layers: {
      l2: {
        title: 'Ethernet II (Layer 2)',
        fields: [
          { label: 'Source MAC', value: ntpServer.mac },
          { label: 'Destination MAC', value: victimServer.mac },
        ],
      },
      l3: {
        title: 'Internet Protocol v4 (Layer 3)',
        fields: [
          { label: 'Source IP (Reflector)', value: `${ntpServer.ip} (Open NTP Server)` },
          { label: 'Destination IP (Victim)', value: victimServer.ip, highlight: 'attack' },
          { label: 'Protocol', value: '17 (UDP)' },
        ],
      },
      l4: {
        title: 'User Datagram Protocol (Layer 4)',
        fields: [
          { label: 'Source Port', value: '123 (NTP)' },
          { label: 'Amplified Size', value: '4,800 bytes (100x vs 48B query)', highlight: 'attack' },
        ],
      },
      l7: {
        title: 'NTP Amplified Monlist Payload (Layer 7)',
        fields: [
          { label: 'Reflected Burst', value: `Fragment #${burstIndex} of 600 peer records`, highlight: 'attack' },
          { label: 'Mitigation', value: 'Disable NTP monlist + BCP38 Anti-Spoofing' },
        ],
      },
    },
  });
  return { ...pkt, lengthBytes: 4800 };
}


