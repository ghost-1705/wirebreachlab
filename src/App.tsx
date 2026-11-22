/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { BookOpen, Layers, Shield } from 'lucide-react';
import { DeviceTerminal } from './components/DeviceTerminal';
import { DefensePanel } from './components/DefensePanel';
import { LabGuidePanel } from './components/LabGuidePanel';
import { PacketInspector } from './components/PacketInspector';
import { TopBar } from './components/TopBar';
import { TopologyCanvas } from './components/TopologyCanvas';
import { DEFENSE_DEFINITIONS, SCENARIO_CATEGORIES, SCENARIO_LIST, SCENARIOS } from './data/scenarios';
import { useSimulation } from './hooks/useSimulation';
import { ScenarioCategory } from './types/simulator';

type InspectorTab = 'packets' | 'defenses' | 'guide';

export default function App() {
  const sim = useSimulation();
  const [rightTab, setRightTab] = useState<InspectorTab>('packets');

  const activeCategory = SCENARIOS[sim.activeScenario].category;
  const activeDefenseCount = Object.values(sim.defenses).filter(Boolean).length;
  const totalDefenseCount = DEFENSE_DEFINITIONS.length;
  const completedObjCount = sim.objectives.filter((o) => o.completed).length;

  const handleSelectCategory = (category: ScenarioCategory) => {
    if (category === activeCategory) return;
    const firstInCategory = SCENARIO_LIST.find((s) => s.category === category);
    if (firstInCategory) {
      sim.selectScenario(firstInCategory.id);
    }
  };

  const handleSelectCanvasPacket = (packetId: string) => {
    sim.selectPacket(packetId);
    setRightTab('packets');
  };

  const handleRunGuideCommand = (cmd: string) => {
    sim.setSelectedNodeId('attacker');
    sim.executeTerminalCommand('attacker', cmd);
  };

  return (
    <div className="min-h-screen lg:h-screen flex flex-col bg-[#0B1120] text-slate-100 overflow-x-hidden lg:overflow-hidden">
      {/* Strict 3-Zone Top Bar */}
      <TopBar
        activeCategory={activeCategory}
        onSelectCategory={handleSelectCategory}
        onResetLab={sim.resetLab}
      />

      {/* Mobile-only compact category strip */}
      <div className="md:hidden flex items-center gap-1.5 px-4 py-2 border-b border-[#243247] bg-[#0F172A] overflow-x-auto">
        {SCENARIO_CATEGORIES.map((cat) => (
          <button
            key={cat.id}
            type="button"
            onClick={() => handleSelectCategory(cat.id)}
            className={`px-2.5 py-1 text-xs font-medium rounded whitespace-nowrap shrink-0 cursor-pointer ${
              activeCategory === cat.id
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                : 'text-slate-400 bg-[#131C2E]'
            }`}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Main Two-Zone Operations Workspace */}
      <main
        id="workspace"
        className="flex-1 min-h-0 p-4 grid grid-cols-1 lg:grid-cols-12 gap-4 lg:overflow-hidden"
      >
        {/* Left Primary Column */}
        <div className="lg:col-span-7 xl:col-span-8 flex flex-col gap-4 min-h-0">
          <div className="flex-1 min-h-0 flex flex-col">
            <TopologyCanvas
              activeScenario={sim.activeScenario}
              onSelectScenario={sim.selectScenario}
              topologyId={sim.topologyId}
              nodes={sim.nodes}
              links={sim.links}
              selectedNodeId={sim.selectedNodeId}
              onSelectNode={sim.setSelectedNodeId}
              onMoveNode={sim.moveNode}
              onResetLayout={sim.resetNodePositions}
              onSelectTopology={sim.selectTopology}
              inFlightPackets={sim.inFlightPackets}
              selectedPacketId={sim.selectedPacketId}
              onSelectPacket={handleSelectCanvasPacket}
              dropEffects={sim.dropEffects}
              defenses={sim.defenses}
              firewallPlaced={sim.firewallPlaced}
              onToggleFirewallPlaced={sim.toggleFirewallPlaced}
              onApplyAllDefenses={sim.applyAllDefenses}
              arpPoisoned={sim.arpPoisoned}
              dnsPoisoned={sim.dnsPoisoned}
              wifiEvilTwinActive={sim.wifiEvilTwinActive}
              isPaused={sim.isPaused}
              onTogglePause={() => sim.setIsPaused((p) => !p)}
              speed={sim.speed}
              onChangeSpeed={sim.setSpeed}
              attackActive={sim.attackActive}
              onToggleAttack={sim.toggleAttack}
              onStepForward={sim.stepForward}
            />
          </div>

          <DeviceTerminal
            nodes={sim.nodes}
            selectedNodeId={sim.selectedNodeId}
            onSelectNode={sim.setSelectedNodeId}
            activeScenario={sim.activeScenario}
            lines={sim.terminals[sim.selectedNodeId] ?? []}
            onExecuteCommand={sim.executeTerminalCommand}
          />
        </div>

        {/* Right Inspector & Defense Workbench */}
        <aside
          aria-label="Packet inspector and defense workbench"
          className="lg:col-span-5 xl:col-span-4 flex flex-col bg-[#0F172A] border border-[#243247] rounded-lg overflow-hidden min-h-[540px] lg:min-h-0"
        >
          {/* Workbench Tab Strip */}
          <div className="flex items-center border-b border-[#243247] bg-[#131C2E] px-2 pt-1.5 gap-1 shrink-0">
            <button
              type="button"
              onClick={() => setRightTab('packets')}
              className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                rightTab === 'packets'
                  ? 'border-sky-400 text-sky-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Packet Inspector</span>
              <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                ({sim.capturedPackets.length})
              </span>
            </button>

            <button
              type="button"
              onClick={() => setRightTab('defenses')}
              className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                rightTab === 'defenses'
                  ? 'border-sky-400 text-sky-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span>Defenses</span>
              <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                ({activeDefenseCount}/{totalDefenseCount})
              </span>
            </button>

            <button
              type="button"
              onClick={() => setRightTab('guide')}
              className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                rightTab === 'guide'
                  ? 'border-sky-400 text-sky-300'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>Lab Guide</span>
              <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                ({completedObjCount}/{sim.objectives.length})
              </span>
            </button>
          </div>

          {/* Active Workbench View */}
          <div className="flex-1 min-h-0 overflow-hidden">
            {rightTab === 'packets' && (
              <PacketInspector
                packets={sim.capturedPackets}
                selectedPacket={sim.selectedPacket}
                onSelectPacket={sim.selectPacket}
                onClearCapture={sim.clearCapture}
                attackMetrics={sim.attackMetrics}
                isPaused={sim.isPaused}
                attackActive={sim.attackActive}
              />
            )}

            {rightTab === 'defenses' && (
              <DefensePanel
                activeScenario={sim.activeScenario}
                topologyId={sim.topologyId}
                defenses={sim.defenses}
                onToggleDefense={sim.toggleDefense}
                firewallPlaced={sim.firewallPlaced}
                onToggleFirewallPlaced={sim.toggleFirewallPlaced}
                onApplyAllDefenses={sim.applyAllDefenses}
                arpTable={sim.arpTable}
                dnsCache={sim.dnsCache}
                portScanResults={sim.portScanResults}
                firewallEvents={sim.firewallEvents}
              />
            )}

            {rightTab === 'guide' && (
              <LabGuidePanel
                activeScenario={sim.activeScenario}
                objectives={sim.objectives}
                onRunExampleCommand={handleRunGuideCommand}
              />
            )}
          </div>
        </aside>
      </main>
    </div>
  );
}
