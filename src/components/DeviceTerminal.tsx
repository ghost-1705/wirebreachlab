import React, { useEffect, useMemo, useRef, useState } from 'react';
import { CornerDownLeft, Terminal } from 'lucide-react';
import { SCENARIOS } from '../data/scenarios';
import { NetworkNode, ScenarioId, TerminalLine } from '../types/simulator';

interface DeviceTerminalProps {
  nodes: NetworkNode[];
  selectedNodeId: string;
  onSelectNode: (id: string) => void;
  activeScenario: ScenarioId;
  lines: TerminalLine[];
  onExecuteCommand: (nodeId: string, command: string) => void;
}

export function DeviceTerminal({
  nodes,
  selectedNodeId,
  onSelectNode,
  activeScenario,
  lines,
  onExecuteCommand,
}: DeviceTerminalProps) {
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState<number>(-1);
  const outputRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? nodes[0],
    [nodes, selectedNodeId]
  );

  const quickCommands = useMemo(() => {
    const scenarioCmds = SCENARIOS[activeScenario].quickCommands.filter((q) =>
      q.roles.includes(selectedNode.role)
    );
    const defaults = [
      { label: 'ifconfig', command: 'ifconfig', roles: [selectedNode.role], kind: 'diagnostic' as const },
      { label: 'arp -a', command: 'arp -a', roles: [selectedNode.role], kind: 'diagnostic' as const },
      { label: 'help', command: 'help', roles: [selectedNode.role], kind: 'diagnostic' as const },
    ];
    const combined = [...scenarioCmds];
    for (const d of defaults) {
      if (!combined.some((c) => c.command === d.command) && combined.length < 5) {
        combined.push(d);
      }
    }
    return combined;
  }, [activeScenario, selectedNode.role]);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [lines, selectedNodeId]);

  const promptPrefix = useMemo(() => {
    const user =
      selectedNode.role === 'attacker'
        ? 'kali'
        : selectedNode.role === 'firewall' || selectedNode.role === 'router' || selectedNode.role === 'switch'
        ? 'admin'
        : selectedNode.role === 'client'
        ? 'user'
        : 'root';
    const sigil = selectedNode.role === 'firewall' || selectedNode.role === 'router' ? '#' : '$';
    return `${user}@${selectedNode.hostname}:~${sigil}`;
  }, [selectedNode]);

  const submitCommand = (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;
    setHistory((prev) => [trimmed, ...prev.slice(0, 29)]);
    setHistoryIdx(-1);
    onExecuteCommand(selectedNode.id, trimmed);
    setInput('');
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      submitCommand(input);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIdx = Math.min(history.length - 1, historyIdx + 1);
      setHistoryIdx(nextIdx);
      setInput(history[nextIdx]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIdx <= 0) {
        setHistoryIdx(-1);
        setInput('');
      } else {
        const nextIdx = historyIdx - 1;
        setHistoryIdx(nextIdx);
        setInput(history[nextIdx]);
      }
    }
  };

  return (
    <section
      aria-label="Interactive device terminal"
      className="flex flex-col bg-[#0F172A] border border-[#243247] rounded-lg overflow-hidden h-[270px] shrink-0"
    >
      {/* Terminal Header & Host Tabs */}
      <div className="flex items-center justify-between gap-4 px-4 py-2 border-b border-[#243247] bg-[#131C2E]">
        <div className="flex items-center gap-2 min-w-0">
          <Terminal className="w-4 h-4 text-sky-400 shrink-0" />
          <h2 className="text-xs font-semibold text-slate-100 whitespace-nowrap shrink-0">
            Device Console
          </h2>
          <span className="text-xs text-slate-500 hidden sm:inline">·</span>
          <span className="text-xs font-mono text-slate-400 truncate hidden sm:inline tabular-nums">
            {selectedNode.hostname} · {selectedNode.ip} · {selectedNode.os}
          </span>
        </div>

        {/* Clickable device switcher tabs */}
        <div className="flex items-center gap-1 overflow-x-auto max-w-[55%]">
          {nodes.map((node) => {
            const active = node.id === selectedNode.id;
            return (
              <button
                key={node.id}
                type="button"
                onClick={() => {
                  onSelectNode(node.id);
                  inputRef.current?.focus();
                }}
                className={`px-2 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#1B263B]'
                }`}
              >
                {node.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Quick Command Bar */}
      <div className="flex items-center gap-2 px-4 py-1.5 border-b border-[#1E2B40] bg-[#0D1526] overflow-x-auto">
        <span className="text-[11px] text-slate-500 whitespace-nowrap shrink-0">Quick commands:</span>
        {quickCommands.map((qc) => (
          <button
            key={qc.command}
            type="button"
            onClick={() => submitCommand(qc.command)}
            className={`px-2.5 py-0.5 text-[11px] font-mono rounded border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              qc.kind === 'attack'
                ? 'bg-red-950/50 border-red-500/40 text-red-200 hover:bg-red-900/60'
                : qc.kind === 'defense'
                ? 'bg-emerald-950/50 border-emerald-500/40 text-emerald-200 hover:bg-emerald-900/60'
                : 'bg-[#172135] border-[#293952] text-slate-300 hover:bg-[#1F2C45]'
            }`}
          >
            {qc.label}
          </button>
        ))}
      </div>

      {/* Scrollable Output */}
      <div
        ref={outputRef}
        onClick={() => inputRef.current?.focus()}
        className="flex-1 overflow-y-auto px-4 py-2.5 font-mono text-xs leading-relaxed space-y-1 bg-[#090F1D] cursor-text"
      >
        {lines.map((line) => (
          <div
            key={line.id}
            className={`whitespace-pre-wrap break-all ${
              line.type === 'input'
                ? 'text-sky-300 font-medium'
                : line.type === 'alert'
                ? 'text-red-300'
                : line.type === 'error'
                ? 'text-amber-300'
                : line.type === 'success'
                ? 'text-emerald-300'
                : line.type === 'info'
                ? 'text-slate-400'
                : 'text-slate-200'
            }`}
          >
            {line.type === 'input' ? (
              <span>
                <span className="text-slate-500 mr-2">{promptPrefix}</span>
                {line.text}
              </span>
            ) : (
              line.text
            )}
          </div>
        ))}
      </div>

      {/* Command Input Row */}
      <div className="flex items-center gap-2 px-4 py-2 border-t border-[#1E2B40] bg-[#0B1222]">
        <span className="font-mono text-xs text-sky-400 whitespace-nowrap shrink-0">{promptPrefix}</span>
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder='Type a command (e.g., "help", "arp -a", "netstat -an")...'
          aria-label="Terminal command input"
          className="flex-1 bg-transparent font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none min-w-0"
        />
        <button
          type="button"
          onClick={() => submitCommand(input)}
          className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-slate-200 bg-[#1B263B] hover:bg-[#243247] border border-[#2D3E58] rounded transition-colors cursor-pointer shrink-0"
        >
          <span>Run</span>
          <CornerDownLeft className="w-3 h-3" />
        </button>
      </div>
    </section>
  );
}
