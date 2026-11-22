import { DEFENSE_DEFINITIONS } from '../data/scenarios';
import {
  ArpEntry,
  DefenseKey,
  DefenseState,
  DnsCacheEntry,
  NetworkNode,
  ScenarioId,
  TerminalLine,
} from '../types/simulator';

export interface CommandExecutionResult {
  lines: Omit<TerminalLine, 'id'>[];
  clearTerminal?: boolean;
  startAttack?: ScenarioId;
  stopAttack?: boolean;
  toggleDefense?: { key: DefenseKey; enabled: boolean };
  toggleAllDefenses?: boolean;
  toggleFirewallPlace?: boolean;
  triggerPingTargetId?: string;
  triggerDnsQuery?: string;
  triggerSingleSqlInjection?: string;
}

interface CommandContext {
  node: NetworkNode;
  allNodes: NetworkNode[];
  defenses: DefenseState;
  arpTable: ArpEntry[];
  dnsCache: DnsCacheEntry[];
  activeScenario: ScenarioId;
  attackActive: boolean;
}

export function interpretCommand(rawInput: string, ctx: CommandContext): CommandExecutionResult {
  const input = rawInput.trim();
  if (!input) {
    return { lines: [] };
  }

  const lower = input.toLowerCase();
  const tokens = input.split(/\s+/);
  const cmd = tokens[0].toLowerCase();

  if (cmd === 'clear' || cmd === 'cls') {
    return { lines: [], clearTerminal: true };
  }

  if (cmd === 'help' || cmd === '?') {
    const roleSpecific: Omit<TerminalLine, 'id'>[] = [];
    if (ctx.node.role === 'attacker' || ctx.node.role === 'rogue') {
      roleSpecific.push(
        { type: 'info', text: 'Offensive Lab Tools (MitM, DoS/DDoS, Web & Recon):' },
        { type: 'output', text: '  arpspoof -i eth0 -t <victim> <gw>       ARP Spoofing MITM' },
        { type: 'output', text: '  airbase-ng -e "Cafe-Business-WiFi"      Wi-Fi Evil Twin Eavesdropping' },
        { type: 'output', text: '  swaks --from alerts@firstbank.com       Email Hijacking (SMTP Spoof)' },
        { type: 'output', text: '  dnsspoof -i eth0 portal.corp.local      DNS Spoofing & Redirection' },
        { type: 'output', text: '  hping3 -a <spoof_ip> -p 80 <target>     IP Spoofing Impersonation' },
        { type: 'output', text: '  httpspoof --domain p0rtal-corp.local    HTTPS Spoofing (Rogue TLS)' },
        { type: 'output', text: '  hping3 -S -p 80 --flood <ip>            SYN Flood DDoS' },
        { type: 'output', text: '  httpflood -u http://<ip>/search         L7 HTTP Flood DDoS' },
        { type: 'output', text: '  hping3 --udp --flood <ip>               UDP Flood DDoS' },
        { type: 'output', text: '  ping -f -s 1472 <ip>                    ICMP Ping Flood' },
        { type: 'output', text: '  ntpdc -n -c monlist <ntp_ip>            NTP Amplification DDoS' },
        { type: 'output', text: '  sqlmap -u http://<ip>/login ...         SQL Injection' },
        { type: 'output', text: '  nmap -sS -p 22,80,443,3306 <ip>         TCP SYN Port Scan' },
        { type: 'output', text: '  allattack --simultaneous <ip>           Launch ALL attacks at once' },
        { type: 'output', text: '  stop                                    Halt active attack stream' }
      );
    } else {
      roleSpecific.push(
        { type: 'info', text: 'Blue-Team & Firewall Commands:' },
        { type: 'output', text: '  firewall place | bypass                 Place or bypass inline firewall' },
        { type: 'output', text: '  defense enable all | disable all        Apply or clear all 13 firewall rules' },
        { type: 'output', text: '  defense enable <syn-cookies|dai|waf|port-filter|dnssec|vpn-wpa3|dmarc|urpf|hsts-pin|http-limit|udp-limit|icmp-limit|ntp-bcp38>' },
        { type: 'output', text: '  defense disable <module>' },
        { type: 'output', text: '  iptables -L                             Show all 13 security policies' }
      );
    }

    return {
      lines: [
        { type: 'info', text: `Available commands on ${ctx.node.hostname} (${ctx.node.ip}):` },
        { type: 'output', text: '  ifconfig / ip a                         Display network interfaces & MAC' },
        { type: 'output', text: '  arp -a                                  Inspect local ARP cache table' },
        { type: 'output', text: '  netstat -an                             View listening ports & server load' },
        { type: 'output', text: '  ping <ip>                               Send ICMP Echo diagnostic probe' },
        { type: 'output', text: '  dig <domain>                            Query DNS A-record resolution' },
        { type: 'output', text: '  whoami / hostname / clear               Host info & clear terminal' },
        ...roleSpecific,
      ],
    };
  }

  if (cmd === 'whoami') {
    const user =
      ctx.node.role === 'attacker' || ctx.node.role === 'rogue'
        ? 'kali'
        : ctx.node.role === 'firewall' || ctx.node.role === 'router' || ctx.node.role === 'switch' || ctx.node.role === 'wifi_ap'
        ? 'netadmin'
        : ctx.node.role === 'client'
        ? 'j.patel'
        : 'root';
    return { lines: [{ type: 'output', text: user }] };
  }

  if (cmd === 'hostname') {
    return { lines: [{ type: 'output', text: ctx.node.hostname }] };
  }

  if (cmd === 'ifconfig' || (cmd === 'ip' && (tokens[1] === 'a' || tokens[1] === 'addr'))) {
    const iface = ctx.node.role === 'wifi_ap' ? 'wlan0' : 'eth0';
    return {
      lines: [
        { type: 'output', text: `${iface}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500` },
        { type: 'output', text: `        inet ${ctx.node.ip}  netmask 255.255.255.0  subnet ${ctx.node.subnet}` },
        { type: 'output', text: `        ether ${ctx.node.mac}  txqueuelen 1000  (Ethernet)` },
        { type: 'output', text: `        os "${ctx.node.os}"  status ${ctx.node.status.toUpperCase()}` },
      ],
    };
  }

  if (cmd === 'arp') {
    if (ctx.arpTable.length === 0) {
      return { lines: [{ type: 'output', text: 'ARP cache is empty.' }] };
    }
    const header = { type: 'info' as const, text: 'Address            HWaddress          Iface   State' };
    const rows = ctx.arpTable.map((entry) => ({
      type: entry.status === 'poisoned' ? ('alert' as const) : ('output' as const),
      text: `${entry.ip.padEnd(18)} ${entry.mac.padEnd(18)} ${entry.interfaceName.padEnd(7)} ${
        entry.status === 'poisoned' ? 'POISONED (MITM)' : 'REACHABLE'
      }`,
    }));
    return { lines: [header, ...rows] };
  }

  if (cmd === 'netstat' || cmd === 'ss') {
    const lines: Omit<TerminalLine, 'id'>[] = [
      { type: 'info', text: 'Proto  Local Address         Service      State' },
      ...ctx.node.ports.map((p) => ({
        type: 'output' as const,
        text: `tcp    ${`${ctx.node.ip}:${p.port}`.padEnd(21)} ${p.service.padEnd(12)} ${
          p.state === 'open' ? 'LISTEN' : p.state.toUpperCase()
        }`,
      })),
    ];
    if (ctx.node.role === 'webserver' || ctx.node.synBacklog > 6) {
      lines.push({
        type: ctx.node.synBacklog > 60 ? 'alert' : 'info',
        text: `Server Resource / Backlog Load: ${Math.round(ctx.node.synBacklog)}% ${
          ctx.node.synBacklog >= 80 ? '[SATURATED — SERVICE DEGRADED]' : '[NOMINAL]'
        }`,
      });
    }
    return { lines };
  }

  if (cmd === 'iptables' || lower.startsWith('firewall status')) {
    const lines: Omit<TerminalLine, 'id'>[] = [
      { type: 'info', text: `Active Security Policies (${ctx.node.hostname}):` },
      ...DEFENSE_DEFINITIONS.map((d) => ({
        type: ctx.defenses[d.key] ? ('success' as const) : ('output' as const),
        text: `  [${ctx.defenses[d.key] ? 'ENABLED ' : 'DISABLED'}] ${d.name} (${d.cliFlag})`,
      })),
    ];
    return { lines };
  }

  if (cmd === 'firewall' && !lower.startsWith('firewall status')) {
    const sub = tokens[1]?.toLowerCase();
    if (sub === 'place' || sub === 'enable' || sub === 'inline' || sub === 'on') {
      return {
        toggleFirewallPlace: true,
        lines: [
          { type: 'success', text: 'Perimeter Firewall placed inline between Edge Router and Core Switch.' },
          { type: 'info', text: 'Tip: Apply rules with "defense enable all" or toggle individual rules in Defenses.' },
        ],
      };
    }
    if (sub === 'bypass' || sub === 'remove' || sub === 'off') {
      return {
        toggleFirewallPlace: false,
        lines: [
          { type: 'alert', text: 'Perimeter Firewall bypassed — traffic now flows directly across unprotected link.' },
        ],
      };
    }
    if (sub === 'apply-rules' || sub === 'harden') {
      return {
        toggleFirewallPlace: true,
        toggleAllDefenses: true,
        lines: [
          { type: 'success', text: 'Placed Perimeter Firewall inline and applied all 13 security rules!' },
        ],
      };
    }
    return {
      lines: [{ type: 'error', text: 'Usage: firewall <place|bypass|apply-rules|status>' }],
    };
  }

  if (cmd === 'defense') {
    const action = tokens[1]?.toLowerCase();
    const targetFlag = tokens[2]?.toLowerCase();
    const allFlags = DEFENSE_DEFINITIONS.map((d) => d.cliFlag).join('|');
    if ((action !== 'enable' && action !== 'disable') || !targetFlag) {
      return {
        lines: [{ type: 'error', text: `Usage: defense <enable|disable> <all|${allFlags}>` }],
      };
    }
    const enabled = action === 'enable';
    if (targetFlag === 'all') {
      return {
        toggleAllDefenses: enabled,
        lines: [
          {
            type: enabled ? 'success' : 'alert',
            text: enabled
              ? 'Applied ALL 13 firewall & network defense rules.'
              : 'Cleared all 13 firewall & network defense rules (ALLOW ANY).',
          },
        ],
      };
    }
    const def = DEFENSE_DEFINITIONS.find((d) => d.cliFlag === targetFlag);
    if (!def) {
      return {
        lines: [{ type: 'error', text: `Unknown defense module "${targetFlag}". Valid: all|${allFlags}` }],
      };
    }
    return {
      toggleDefense: { key: def.key, enabled },
      lines: [
        {
          type: enabled ? 'success' : 'alert',
          text: `${enabled ? 'Enabled' : 'Disabled'} ${def.name} on ${def.enforcedBy}.`,
        },
      ],
    };
  }

  // Ping Flood (-f) vs normal diagnostic ping
  if (cmd === 'ping') {
    if (tokens.includes('-f') || lower.includes('--flood')) {
      if (ctx.node.role !== 'attacker') {
        return { lines: [{ type: 'error', text: 'Permission denied: flood ping (-f) requires Attacker privileges.' }] };
      }
      return {
        startAttack: 'icmp-flood',
        lines: [
          { type: 'alert', text: `PING FLOOD ${tokens[tokens.length - 1] || '10.0.2.20'} 1472(1500) bytes of data.` },
          { type: 'alert', text: 'Sending high-rate ICMP Echo Request barrage...' },
        ],
      };
    }

    const targetArg = tokens[1];
    const targetNode = targetArg
      ? ctx.allNodes.find((n) => n.ip === targetArg || n.hostname === targetArg || n.id === targetArg)
      : ctx.allNodes.find((n) => n.id !== ctx.node.id && (n.role === 'router' || n.role === 'webserver'));

    if (!targetNode) {
      return {
        lines: [{ type: 'error', text: `ping: ${targetArg ?? ''}: Host unreachable or not in current topology.` }],
      };
    }
    return {
      triggerPingTargetId: targetNode.id,
      lines: [
        { type: 'output', text: `PING ${targetNode.hostname} (${targetNode.ip}) 56(84) bytes of data.` },
        { type: 'success', text: `Dispatched ICMP Echo Request → ${targetNode.ip} (watch topology wire)` },
      ],
    };
  }

  if (cmd === 'dig' || cmd === 'nslookup') {
    const domain = tokens[1] || 'portal.corp.local';
    const cached = ctx.dnsCache.find((d) => d.domain === domain);
    const resolvedIp = cached ? cached.ip : '10.20.0.10';
    const isSpoofed = cached?.status === 'spoofed';

    return {
      triggerDnsQuery: domain,
      lines: [
        { type: 'output', text: `; <<>> DiG 9.18 <<>> ${domain}` },
        { type: 'info', text: ';; ANSWER SECTION:' },
        {
          type: isSpoofed ? 'alert' : 'success',
          text: `${domain}.    300   IN   A   ${resolvedIp}  ${
            isSpoofed ? '; [SPOOFED — ROGUE HOST]' : '; [VERIFIED]'
          }`,
        },
      ],
    };
  }

  if (lower === 'show tables' || lower.startsWith('select ')) {
    if (ctx.node.role !== 'database') {
      return {
        lines: [{ type: 'error', text: 'MySQL client not connected. Click the SQL Database node to inspect tables.' }],
      };
    }
    return {
      lines: [
        { type: 'info', text: '+----------------------+' },
        { type: 'output', text: '| Tables_in_corp_prod  |' },
        { type: 'info', text: '+----------------------+' },
        { type: 'output', text: '| users (142 rows)     |' },
        { type: 'output', text: '| payroll_records      |' },
        { type: 'output', text: '| api_tokens           |' },
        { type: 'info', text: '+----------------------+' },
      ],
    };
  }

  if (cmd === 'stop' || lower === 'ctrl+c') {
    if (!ctx.attackActive) {
      return { lines: [{ type: 'info', text: 'No active attack stream is currently running.' }] };
    }
    return {
      stopAttack: true,
      lines: [{ type: 'info', text: '^C Attack stream terminated.' }],
    };
  }

  // ==================== OFFENSIVE COMMANDS ====================

  if (cmd === 'hping3') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: hping3 is installed on the Attacker node.' }] };
    }
    if (tokens.includes('--udp') || tokens.includes('-2')) {
      return {
        startAttack: 'udp-flood',
        lines: [
          { type: 'alert', text: `HPING ${tokens[tokens.length - 1] || '10.0.2.20'} (eth0): udp mode set, random high ports` },
          { type: 'alert', text: 'Flooding target with stateless UDP datagrams (triggering ICMP Unreachable)...' },
        ],
      };
    }
    if (tokens.includes('--icmp') || tokens.includes('-1')) {
      return {
        startAttack: 'icmp-flood',
        lines: [
          { type: 'alert', text: `HPING ${tokens[tokens.length - 1] || '10.0.2.20'} (eth0): icmp mode set, 1472 data bytes` },
          { type: 'alert', text: 'Flooding target with ICMP Echo Requests...' },
        ],
      };
    }
    if (tokens.includes('-a') || tokens.includes('--spoof')) {
      return {
        startAttack: 'ip-spoofing',
        lines: [
          { type: 'alert', text: `HPING IP SPOOF: Forging Source IPv4 header (${tokens[tokens.indexOf('-a') + 1] ?? '10.0.2.53'})` },
          { type: 'info', text: 'Transmitting impersonated IPv4 frames toward target...' },
        ],
      };
    }
    return {
      startAttack: 'syn-flood',
      lines: [
        { type: 'alert', text: `HPING ${tokens[tokens.length - 1] || '10.0.2.20'} (eth0): S set, 40 headers + 0 data bytes` },
        { type: 'alert', text: 'hping in flood mode — sending spoofed TCP SYN packets...' },
      ],
    };
  }

  if (cmd === 'arpspoof') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: arpspoof must be executed from the Attacker node.' }] };
    }
    return {
      startAttack: 'arp-spoof',
      lines: [
        { type: 'alert', text: `Sending forged gratuitous ARP replies (${ctx.node.mac}) to LAN hosts...` },
        { type: 'info', text: 'IP forwarding enabled. Intercepted traffic will route through this host.' },
      ],
    };
  }

  if (cmd === 'airbase-ng' || cmd === 'eviltwin') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: airbase-ng must be executed from the Attacker node.' }] };
    }
    return {
      startAttack: 'wifi-eavesdropping',
      lines: [
        { type: 'alert', text: 'Evil Twin AP active: broadcasting open SSID "Cafe-Business-WiFi" on wlan1' },
        { type: 'info', text: 'Victim laptop associated — sniffing payment card & login traffic...' },
      ],
    };
  }

  if (cmd === 'swaks' || cmd === 'sendemail') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: swaks SMTP spoofing must run on the Attacker node.' }] };
    }
    return {
      startAttack: 'email-hijacking',
      lines: [
        { type: 'alert', text: 'SMTP -> MAIL FROM:<alerts@firstbank.com> (Forged Bank Sender)' },
        { type: 'info', text: 'Delivering wire-transfer phishing email via SMTP Mail Server...' },
      ],
    };
  }

  if (cmd === 'httpspoof' || cmd === 'sslstrip') {
    if (ctx.node.role !== 'attacker' && ctx.node.role !== 'rogue') {
      return { lines: [{ type: 'error', text: 'Permission denied: httpspoof must run on the Attacker or Rogue host.' }] };
    }
    return {
      startAttack: 'https-spoofing',
      lines: [
        { type: 'alert', text: 'Serving lookalike HTTPS portal: https://p0rtal-corp.local (Rogue Self-Signed Cert)' },
        { type: 'info', text: 'Waiting for browser SSO submissions...' },
      ],
    };
  }

  if (cmd === 'httpflood' || cmd === 'wrk' || cmd === 'slowloris') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: httpflood must run on the Attacker node.' }] };
    }
    return {
      startAttack: 'http-flood',
      lines: [
        { type: 'alert', text: 'Launching L7 HTTP Flood: 250 concurrent GET /search & POST /checkout threads' },
        { type: 'info', text: 'Exhausting application worker pool with valid HTTP requests...' },
      ],
    };
  }

  if (cmd === 'ntpdc' || cmd === 'ntpamp') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: ntpdc amplification tool must run on the Attacker node.' }] };
    }
    return {
      startAttack: 'ntp-amplification',
      lines: [
        { type: 'alert', text: 'Sending spoofed 48-byte NTP Mode 7 monlist queries to Open NTP Server (UDP/123)' },
        { type: 'alert', text: 'Source IP forged to Victim Bank Web Server — triggering 1:100 reflection flood...' },
      ],
    };
  }

  if (cmd === 'sqlmap' || cmd === 'curl') {
    if (ctx.node.role !== 'attacker' && cmd === 'sqlmap') {
      return { lines: [{ type: 'error', text: 'Permission denied: sqlmap is installed on the Attacker node.' }] };
    }
    const payloadMatch = input.match(/payload=["']?([^"']+)/i);
    const sqli = payloadMatch ? payloadMatch[1] : "' OR '1'='1'--";
    return {
      startAttack: 'sql-injection',
      triggerSingleSqlInjection: sqli,
      lines: [
        { type: 'alert', text: `Testing parameter 'username' with payload: admin${sqli}` },
        { type: 'info', text: 'Dispatching crafted HTTP POST request toward Application Web Server...' },
      ],
    };
  }

  if (cmd === 'nmap') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: nmap is installed on the Attacker node.' }] };
    }
    return {
      startAttack: 'port-scan',
      lines: [
        { type: 'info', text: 'Starting Nmap 7.95 ( https://nmap.org )' },
        { type: 'alert', text: 'Initiating SYN Stealth Scan against target ports 22, 80, 443, 3306, 8080...' },
      ],
    };
  }

  if (cmd === 'dnsspoof') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: dnsspoof is installed on the Attacker node.' }] };
    }
    return {
      startAttack: 'dns-spoof',
      lines: [
        { type: 'alert', text: 'dnsspoof: listening on eth0 [udp dst port 53]' },
        { type: 'alert', text: 'Injecting forged A-record: portal.corp.local -> 192.168.10.99' },
      ],
    };
  }

  if (cmd === 'allattack' || cmd === 'chaos') {
    if (ctx.node.role !== 'attacker') {
      return { lines: [{ type: 'error', text: 'Permission denied: allattack must be launched from the Attacker node.' }] };
    }
    return {
      startAttack: 'all-out-defense',
      lines: [
        { type: 'alert', text: 'LAUNCHING MULTI-VECTOR STORM: SYN + HTTP + UDP + ICMP + NTP + SQLi + Nmap + MitM!' },
        { type: 'info', text: 'All 13 attack vectors firing concurrently. Place a Firewall & apply rules to mitigate!' },
      ],
    };
  }

  return {
    lines: [
      { type: 'error', text: `${cmd}: command not found on ${ctx.node.hostname}. Type "help" for available commands.` },
    ],
  };
}
