# WireBreach Lab

Interactive 3D isometric cyber attack and firewall defense simulator built with React, TypeScript, and Tailwind CSS. Explore how Layer 2–7 network attacks propagate across enterprise topologies, inspect live OSI frames, execute terminal commands per host, and test Blue-Team firewall mitigations in real time.

## Key Capabilities

- **3D Isometric Topology Stage**: Drag and inspect hardware nodes (Edge Router, Core L2 Switch, Perimeter NGFW Firewall, Web Portal, SQL Database, DNS, SMTP Mail, Open NTP, Wi-Fi AP, and Workstations) rendered with CSS 3D isometric depth, live status halos, and real-time packet animations.
- **14 Hands-On Attack & Defense Labs Across 4 Sessions**:
  - **MitM Attacks (6 Labs)**: ARP Cache Spoofing, DNS Cache Poisoning, SSL/HTTPS Downgrade & Strip, ICMP Redirect Hijack, Evil Twin Wi-Fi Intercept, and Email / IP Spoofing.
  - **DoS & DDoS (5 Labs)**: TCP SYN Flood, HTTP GET Flood (L7), UDP Random-Port Flood, ICMP Ping Flood, and NTP Amplification (`monlist` reflection).
  - **Web & Recon (2 Labs)**: SQL Injection (`OR 1=1`) and Nmap Stealth Port Scanning.
  - **Firewall Lab (1 Unified Lab)**: **All-Out Attack vs. Firewall** on an 11-node Firewall Sandbox where all vectors fire concurrently while the Perimeter Firewall starts **Bypassed**. Place the firewall inline and apply individual or all 13 Blue-Team rules to observe live drops and mitigation metrics.
- **5 Switchable Preset Topologies**: Perimeter DMZ, Corporate LAN, Public Wi-Fi Zone, Amplification Lab, and Firewall Sandbox.
- **Attack Telemetry Widget**: Collapsible live dashboard strip inside the Packet Inspector displaying **Packets / Sec**, **Bandwidth Utilization**, **Exploits Landed**, **Blocked & Mitigation Rate**, and a 24-second SVG sparkline.
- **OSI Payload Inspector**: Click any packet in flight or in the capture table to dissect Layer 2–7 headers, flags, and educational defense notes.
- **Per-Node Interactive Terminals**: Run simulated commands (`arp -a`, `nslookup`, `nmap`, `allattack`, `firewall place`, `firewall apply-rules`, `defense enable all`, `ping`) directly on selected hosts.

## Firewall Lab Workflow

1. Open **Firewall Lab** in the top navigation bar and click **Start Attack** (or run `allattack --simultaneous 10.50.2.20`).
2. Observe traffic bypassing the unplaced Perimeter Firewall over the direct `router -> switch` bypass link while attack vectors hit internal targets.
3. Click **Place Firewall** (or run `firewall place`) to route all traffic inline through the Perimeter Firewall in `ALLOW ANY` state.
4. Enable individual rules in **Defenses** or click **Apply All 13 Rules** (`firewall apply-rules`) to watch blocked packet counters and mitigation rates climb immediately.

## Tech Stack

- React 19 + TypeScript
- Vite 8 + Tailwind CSS v4
- Lucide React Icons

## Getting Started

```bash
# Install dependencies
npm install

# Start the local development server (http://localhost:3000)
npm run dev

# Type-check with TypeScript
npm run lint

# Build for production
npm run build
```

## Educational Notice

All network topologies, IP/MAC addresses, terminal commands, and packet payloads run exclusively inside an isolated browser simulation for cybersecurity education and defensive training.

## License

Licensed under the [MIT License](LICENSE).
