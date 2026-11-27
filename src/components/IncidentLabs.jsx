import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  CheckCircle2,
  ChevronRight,
  Circle,
  FileWarning,
  Lightbulb,
  Lock,
  RotateCcw,
  ShieldAlert,
  Terminal,
  Trophy,
  XCircle,
} from 'lucide-react';
import { XP_RULES, getDomain } from '../data/index.js';

const LETTERS = ['A', 'B', 'C', 'D'];
const SEVERITY = { Easy: 'P3 · Medium', Medium: 'P2 · High', Hard: 'P1 · Critical' };
const SEV_CLS = { Easy: 'text-amber-400 border-amber-500/40', Medium: 'text-orange-400 border-orange-500/40', Hard: 'text-red-400 border-red-500/40' };

function labRecord(progress, id) {
  return progress.labs[id] || { stepsDone: [], hints: [], wrong: {}, completed: false };
}

function LabList({ labs, progress, onOpen }) {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <Terminal className="h-6 w-6 text-cyber" /> Incident Labs
        </h1>
        <p className="text-sm text-gray-500">
          Work a live ticket end-to-end through a 5-step investigation. Close the incident for +{XP_RULES.labComplete} XP. Hints cost {XP_RULES.hintCost} XP.
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {labs.map((lab, i) => {
          const rec = labRecord(progress, lab.id);
          const done = rec.stepsDone.length;
          const d = getDomain(lab.domain);
          return (
            <button
              key={lab.id}
              onClick={() => onOpen(lab.id)}
              className="group flex flex-col rounded-xl border border-gray-800 bg-card p-5 text-left transition hover:border-cyber/50 hover:shadow-lg hover:shadow-cyber/5"
            >
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="text-gray-500">INC-{String(2400 + i * 37).padStart(5, '0')}</span>
                <span className={`rounded border px-1.5 py-0.5 ${SEV_CLS[lab.difficulty] || 'text-gray-400 border-gray-700'}`}>
                  {SEVERITY[lab.difficulty] || lab.difficulty}
                </span>
              </div>
              <h3 className="mt-3 text-lg font-semibold text-gray-100 group-hover:text-cyber">{lab.title}</h3>
              <div className="mt-1 font-mono text-xs text-gray-500">{d.code} · {d.short} · {lab.difficulty}</div>
              <p className="mt-3 line-clamp-3 text-sm text-gray-400">{lab.briefing}</p>
              <div className="mt-auto pt-4">
                <div className="mb-1 flex justify-between font-mono text-[11px]">
                  <span className={rec.completed ? 'text-emerald' : 'text-gray-500'}>
                    {rec.completed ? 'CLOSED' : done ? 'IN PROGRESS' : 'OPEN'}
                  </span>
                  <span className="text-gray-500">{done}/{lab.steps.length} steps</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-gray-800">
                  <div
                    className={`h-full ${rec.completed ? 'bg-emerald' : 'bg-cyber'}`}
                    style={{ width: `${(done / lab.steps.length) * 100}%` }}
                  />
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function Workstation({ lab, labIndex, progress, onBack, onAnswerStep, onUseHint, onResetLab }) {
  const rec = labRecord(progress, lab.id);
  const steps = [...lab.steps].sort((a, b) => a.stepNumber - b.stepNumber);
  const firstOpen = steps.find((s) => !rec.stepsDone.includes(s.stepNumber));
  const [viewStep, setViewStep] = useState((firstOpen || steps[steps.length - 1]).stepNumber);
  const [evidenceStep, setEvidenceStep] = useState(viewStep);
  const [picked, setPicked] = useState(null);
  const [feedback, setFeedback] = useState(null);

  const step = steps.find((s) => s.stepNumber === viewStep);
  const stepDone = rec.stepsDone.includes(step.stepNumber);
  const hintShown = rec.hints.includes(step.stepNumber);
  const unlocked = (n) => rec.stepsDone.includes(n) || (firstOpen && firstOpen.stepNumber === n);
  const d = getDomain(lab.domain);
  const ticketId = `INC-${String(2400 + labIndex * 37).padStart(5, '0')}`;

  useEffect(() => {
    setPicked(null);
    setFeedback(null);
    setEvidenceStep(viewStep);
  }, [viewStep]);

  const submit = (i) => {
    if (stepDone) return;
    setPicked(i);
    const { correct } = onAnswerStep(lab, step, i);
    setFeedback(correct ? 'correct' : 'wrong');
  };

  const advance = () => {
    const next = steps.find((s) => s.stepNumber > step.stepNumber);
    if (next) setViewStep(next.stepNumber);
  };

  const evidence = steps.find((s) => s.stepNumber === evidenceStep);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={onBack} className="flex items-center gap-1 rounded-md border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:text-cyber">
          <ArrowLeft className="h-4 w-4" /> All labs
        </button>
        <h1 className="text-xl font-bold text-gray-100">{lab.title}</h1>
        <button
          onClick={() => {
            onResetLab(lab);
            setViewStep(steps[0].stepNumber);
          }}
          className="ml-auto flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300"
        >
          <RotateCcw className="h-3.5 w-3.5" /> replay lab
        </button>
      </div>

      {rec.completed && rec.stepsDone.length === steps.length && (
        <div className="flex items-center gap-3 rounded-xl border border-emerald/50 bg-emerald/10 p-4">
          <Trophy className="h-8 w-8 text-emerald" />
          <div>
            <div className="font-semibold text-emerald">Incident closed: {ticketId}</div>
            <div className="text-sm text-gray-400">
              All five investigation steps complete. Review any step's walkthrough from the workflow tracker for your post-incident report.
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        {/* LEFT: Ticket + Evidence */}
        <div className="space-y-4">
          <div className="rounded-xl border border-gray-800 bg-card">
            <div className="flex items-center justify-between border-b border-gray-800 px-4 py-2.5">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                <span className="font-mono text-sm text-gray-200">{ticketId}</span>
              </div>
              <span className={`rounded border px-1.5 py-0.5 font-mono text-[11px] ${SEV_CLS[lab.difficulty] || ''}`}>
                {SEVERITY[lab.difficulty] || lab.difficulty}
              </span>
            </div>
            <div className="grid grid-cols-3 gap-2 border-b border-gray-800 px-4 py-2 font-mono text-[11px] text-gray-500">
              <div>DOMAIN <span className="block text-gray-300">{d.code} · {d.short}</span></div>
              <div>STATUS <span className={`block ${rec.completed ? 'text-emerald' : 'text-amber-400'}`}>{rec.completed ? 'Closed' : 'Investigating'}</span></div>
              <div>ASSIGNEE <span className="block text-gray-300">you</span></div>
            </div>
            <div className="px-4 py-3">
              <div className="mb-1 flex items-center gap-1 font-mono text-[11px] uppercase tracking-wider text-gray-500">
                <FileWarning className="h-3.5 w-3.5" /> Briefing
              </div>
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-gray-300">{lab.briefing}</p>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-gray-800 bg-[#05080F]">
            <div className="flex items-center gap-1 overflow-x-auto border-b border-gray-800 bg-gray-900/70 px-2 py-1.5">
              {steps.map((s) =>
                unlocked(s.stepNumber) ? (
                  <button
                    key={s.stepNumber}
                    onClick={() => setEvidenceStep(s.stepNumber)}
                    className={`whitespace-nowrap rounded px-2 py-1 font-mono text-[11px] ${
                      evidenceStep === s.stepNumber ? 'bg-cyber/15 text-cyber' : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    evidence_{s.stepNumber}.log
                  </button>
                ) : (
                  <span key={s.stepNumber} className="flex items-center gap-1 whitespace-nowrap px-2 py-1 font-mono text-[11px] text-gray-700">
                    <Lock className="h-3 w-3" /> evidence_{s.stepNumber}.log
                  </span>
                )
              )}
            </div>
            <div className="px-4 pt-3 font-mono text-[11px] text-emerald">
              analyst@soc-ws01:~/cases/{ticketId.toLowerCase()}$ <span className="text-gray-400">cat evidence_{evidenceStep}.log</span>
            </div>
            <pre className="log-block m-0 max-h-[520px] min-h-[260px] border-0 px-4 pb-4 pt-2 text-[12.5px] leading-relaxed">
              {evidence?.evidence}
            </pre>
          </div>
        </div>

        {/* RIGHT: Workflow */}
        <div className="space-y-4">
          <div className="rounded-xl border border-gray-800 bg-card p-4">
            <div className="mb-3 font-mono text-[11px] uppercase tracking-wider text-gray-500">Investigation workflow</div>
            <ol className="space-y-1.5">
              {steps.map((s) => {
                const done = rec.stepsDone.includes(s.stepNumber);
                const open = unlocked(s.stepNumber);
                const active = s.stepNumber === viewStep;
                return (
                  <li key={s.stepNumber}>
                    <button
                      disabled={!open}
                      onClick={() => setViewStep(s.stepNumber)}
                      className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition ${
                        active ? 'bg-cyber/10 ring-1 ring-cyber/40' : open ? 'hover:bg-gray-800/60' : 'opacity-40'
                      }`}
                    >
                      {done ? (
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald" />
                      ) : open ? (
                        <Circle className="h-4 w-4 shrink-0 text-cyber" />
                      ) : (
                        <Lock className="h-4 w-4 shrink-0 text-gray-600" />
                      )}
                      <span className="font-mono text-xs text-gray-500">STEP {s.stepNumber}</span>
                      <span className={`flex-1 ${done ? 'text-gray-400' : 'text-gray-200'}`}>{s.objective}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </div>

          <div className="space-y-4 rounded-xl border border-gray-800 bg-card p-5">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs text-cyber">STEP {step.stepNumber} / {steps.length}</span>
              {!stepDone && (
                <button
                  onClick={() => onUseHint(lab, step.stepNumber)}
                  disabled={hintShown}
                  className="flex items-center gap-1 rounded-md border border-amber-500/50 px-2.5 py-1 text-xs text-amber-400 hover:bg-amber-500/10 disabled:opacity-50"
                >
                  <Lightbulb className="h-3.5 w-3.5" /> {hintShown ? 'Hint revealed' : `Hint (-${XP_RULES.hintCost} XP)`}
                </button>
              )}
            </div>
            <div>
              <div className="text-xs uppercase tracking-wider text-gray-500">Objective</div>
              <div className="text-sm font-semibold text-gray-200">{step.objective}</div>
            </div>
            {hintShown && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-200">
                <Lightbulb className="mr-1 inline h-4 w-4" /> {step.hint}
              </div>
            )}
            <h3 className="whitespace-pre-wrap text-base font-medium leading-relaxed text-gray-100">{step.question}</h3>
            <div className="space-y-2">
              {step.options.map((opt, i) => {
                let cls = 'border-gray-700 hover:border-cyber/60 hover:bg-cyber/5';
                if (stepDone && i === step.correctIndex) cls = 'border-emerald bg-emerald/10';
                else if (stepDone) cls = 'border-gray-800 opacity-50';
                else if (picked === i && feedback === 'wrong') cls = 'border-red-500 bg-red-500/10';
                return (
                  <button
                    key={i}
                    disabled={stepDone}
                    onClick={() => submit(i)}
                    className={`flex w-full items-start gap-3 rounded-lg border px-4 py-3 text-left text-sm transition ${cls}`}
                  >
                    <span className="mt-0.5 rounded border border-gray-600 px-1.5 font-mono text-xs text-gray-400">{LETTERS[i]}</span>
                    <span className="flex-1 whitespace-pre-wrap text-gray-200">{opt}</span>
                  </button>
                );
              })}
            </div>

            {feedback === 'wrong' && !stepDone && (
              <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/5 p-3 text-sm text-red-300">
                <XCircle className="h-4 w-4" /> Not quite. Re-examine the evidence and try again.
              </div>
            )}

            {stepDone && (
              <div className="space-y-3">
                <div className="rounded-lg border border-emerald/40 bg-emerald/5 p-4">
                  <div className="mb-1 flex items-center gap-2 font-semibold text-emerald">
                    <CheckCircle2 className="h-4 w-4" /> Walkthrough
                  </div>
                  <p className="whitespace-pre-wrap text-sm leading-relaxed text-gray-300">{step.walkthrough}</p>
                </div>
                {steps.some((s) => s.stepNumber > step.stepNumber) && (
                  <button
                    onClick={advance}
                    className="flex items-center gap-1 rounded-lg bg-cyber px-4 py-2 text-sm font-semibold text-obsidian hover:bg-cyan-400"
                  >
                    Next step <ChevronRight className="h-4 w-4" />
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function IncidentLabs({ labs, progress, onAnswerStep, onUseHint, onResetLab }) {
  const [openId, setOpenId] = useState(null);
  const labIndex = useMemo(() => labs.findIndex((l) => l.id === openId), [labs, openId]);
  const lab = labs[labIndex];

  if (!lab) return <LabList labs={labs} progress={progress} onOpen={setOpenId} />;
  return (
    <Workstation
      key={lab.id}
      lab={lab}
      labIndex={labIndex}
      progress={progress}
      onBack={() => setOpenId(null)}
      onAnswerStep={onAnswerStep}
      onUseHint={onUseHint}
      onResetLab={onResetLab}
    />
  );
}
