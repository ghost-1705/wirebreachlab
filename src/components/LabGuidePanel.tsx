import { useState } from 'react';
import { Check, CheckCircle2, Circle, Copy } from 'lucide-react';
import { SCENARIOS } from '../data/scenarios';
import { LabObjective, ScenarioId } from '../types/simulator';

interface LabGuidePanelProps {
  activeScenario: ScenarioId;
  objectives: LabObjective[];
  onRunExampleCommand: (command: string) => void;
}

export function LabGuidePanel({
  activeScenario,
  objectives,
  onRunExampleCommand,
}: LabGuidePanelProps) {
  const scenario = SCENARIOS[activeScenario];
  const [copiedJson, setCopiedJson] = useState(false);

  const completedCount = objectives.filter((o) => o.completed).length;

  const handleCopyScenarioJson = () => {
    const json = JSON.stringify(scenario, null, 2);
    navigator.clipboard?.writeText(json).catch(() => {});
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 1800);
  };

  return (
    <div className="h-full overflow-y-auto p-4 space-y-5 bg-[#0F172A]">
      {/* Scenario Overview */}
      <div className="space-y-1.5">
        <div className="text-xs text-slate-400">
          {scenario.layerBadge} · Classroom Lab Walkthrough
        </div>
        <h3 className="text-base font-semibold text-slate-100">{scenario.name}</h3>
        <p className="text-xs text-slate-300 leading-relaxed">{scenario.summary}</p>
      </div>

      {/* Auto-tracked Lab Objectives */}
      <div className="space-y-2.5 pt-3 border-t border-[#243247]">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold text-slate-200">Student Lab Objectives</h4>
          <span className="text-xs font-mono text-sky-300 tabular-nums">
            {completedCount}/{objectives.length} completed
          </span>
        </div>

        <div className="space-y-2">
          {objectives.map((obj, index) => (
            <div
              key={obj.id}
              className={`p-3 rounded-md border transition-colors ${
                obj.completed
                  ? 'bg-emerald-950/20 border-emerald-500/35'
                  : 'bg-[#131C2E] border-[#243247]'
              }`}
            >
              <div className="flex items-start gap-2.5">
                {obj.completed ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <Circle className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                )}
                <div className="min-w-0">
                  <div
                    className={`text-xs font-medium ${
                      obj.completed ? 'text-emerald-200' : 'text-slate-100'
                    }`}
                  >
                    {index + 1}. {obj.title}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{obj.hint}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Example Attack Command */}
      <div className="space-y-2 pt-3 border-t border-[#243247]">
        <h4 className="text-xs font-semibold text-slate-200">Attacker CLI Command</h4>
        <div className="flex items-center justify-between gap-2 p-2.5 rounded-md bg-[#090F1D] border border-[#243247]">
          <code className="font-mono text-[11px] text-red-300 break-all">
            {scenario.attackCommandExample}
          </code>
          <button
            type="button"
            onClick={() => onRunExampleCommand(scenario.attackCommandExample)}
            className="px-2.5 py-1 text-[11px] font-semibold text-slate-100 bg-[#1B263B] hover:bg-[#243247] border border-[#334663] rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Run in Console
          </button>
        </div>
      </div>

      {/* How It Works & Defense Mechanism */}
      <div className="space-y-3 pt-3 border-t border-[#243247] text-xs leading-relaxed">
        <div>
          <h4 className="font-semibold text-slate-200 mb-1">Attack Mechanics</h4>
          <p className="text-slate-300">{scenario.howItWorks}</p>
        </div>
        <div>
          <h4 className="font-semibold text-slate-200 mb-1">How the Mitigation Works</h4>
          <p className="text-slate-300">{scenario.mitigationSummary}</p>
        </div>
      </div>

      {/* Instructor Extensibility Hook */}
      <div className="pt-3 border-t border-[#243247] space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h4 className="text-xs font-semibold text-slate-200">Expand for Your Class</h4>
            <p className="text-[11px] text-slate-400">
              Scenarios are data-driven objects — copy this playbook schema as a template for new labs.
            </p>
          </div>
          <button
            type="button"
            onClick={handleCopyScenarioJson}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-medium text-slate-200 bg-[#1B263B] hover:bg-[#243247] border border-[#2D3E58] rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copiedJson ? 'Copied JSON' : 'Copy Playbook'}
          </button>
        </div>
      </div>
    </div>
  );
}
