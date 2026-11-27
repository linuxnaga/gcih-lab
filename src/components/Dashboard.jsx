import React, { useMemo, useState } from 'react';
import {
  Activity,
  Award,
  Crosshair,
  Flame,
  Layers,
  ListChecks,
  RotateCcw,
  Target,
  Terminal,
  TrendingDown,
  Zap,
} from 'lucide-react';
import { RANKS, XP_RULES, getRankIndex, getDomain } from '../data/index.js';

function StatTile({ icon: Icon, label, value, sub, accent = 'text-cyber' }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-card p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-gray-500">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <div className="mt-2 font-mono text-2xl font-bold text-gray-100">{value}</div>
      {sub && <div className="mt-1 text-xs text-gray-500">{sub}</div>}
    </div>
  );
}

function barColor(pct) {
  if (pct >= 70) return 'from-emerald to-emerald-400';
  if (pct >= 40) return 'from-cyber to-cyan-300';
  return 'from-amber-500 to-orange-400';
}

export default function Dashboard({ progress, dataset, mastery, onStartDrill, onNavigate, onResetProgress }) {
  const [confirmReset, setConfirmReset] = useState(false);
  const rankIndex = getRankIndex(progress.xp);
  const rank = RANKS[rankIndex];
  const nextRank = RANKS[rankIndex + 1];
  const pct = nextRank ? Math.round(((progress.xp - rank.minXp) / (nextRank.minXp - rank.minXp)) * 100) : 100;

  const stats = useMemo(() => {
    const qRecords = Object.values(progress.questions);
    const attempts = qRecords.reduce((s, r) => s + r.attempts, 0);
    const hits = qRecords.reduce((s, r) => s + r.correct, 0);
    const answered = dataset.questions.filter((q) => progress.questions[q.id]).length;
    const mastered = dataset.flashcards.filter((c) => progress.cards[c.id]?.rating === 2).length;
    const labsDone = dataset.labs.filter((l) => progress.labs[l.id]?.completed).length;
    return {
      attempts,
      accuracy: attempts ? Math.round((hits / attempts) * 100) : 0,
      answered,
      mastered,
      labsDone,
    };
  }, [progress, dataset]);

  const overall = Math.round(mastery.reduce((s, d) => s + d.mastery, 0) / mastery.length);

  const weakest = useMemo(() => {
    // Weakest = lowest mastery; ties broken by lower accuracy, then fewer answered.
    return [...mastery].sort(
      (a, b) => a.mastery - b.mastery || (a.accuracy ?? 0) - (b.accuracy ?? 0) || a.answered - b.answered
    )[0];
  }, [mastery]);

  const startQuickTriage = () => {
    const missed = dataset.questions.filter((q) => progress.questions[q.id] && !progress.questions[q.id].lastCorrect);
    const unanswered = dataset.questions.filter((q) => !progress.questions[q.id]);
    const rest = dataset.questions.filter((q) => progress.questions[q.id]?.lastCorrect);
    const shuffle = (arr) => [...arr].sort(() => Math.random() - 0.5);
    const picked = [...shuffle(missed), ...shuffle(unanswered), ...shuffle(rest)].slice(0, 10);
    onStartDrill({
      title: 'Quick Triage — 10-question rapid drill',
      questionIds: shuffle(picked).map((q) => q.id),
    });
  };

  const drillWeakest = () => {
    const pool = dataset.questions.filter((q) => Number(q.domain) === weakest.id);
    const notMastered = pool.filter((q) => !progress.questions[q.id]?.lastCorrect);
    const source = notMastered.length >= 5 ? notMastered : pool;
    const ids = [...source].sort(() => Math.random() - 0.5).map((q) => q.id);
    onStartDrill({ title: `Weakest domain drill — ${weakest.code} ${weakest.name}`, questionIds: ids, domain: weakest.id });
  };

  const recentExams = (progress.exams || []).slice(0, 5);

  return (
    <div className="space-y-6">
      {/* HUD */}
      <section className="grid gap-4 lg:grid-cols-3">
        <div className="relative overflow-hidden rounded-xl border border-gray-800 bg-card p-6 lg:col-span-2">
          <div className="absolute -right-10 -top-10 h-40 w-40 rounded-full bg-cyber/10 blur-3xl" />
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="font-mono text-xs uppercase tracking-[0.25em] text-gray-500">Analyst Profile</div>
              <div className="mt-2 flex items-center gap-3">
                <Award className="h-10 w-10" style={{ color: rank.color }} />
                <div>
                  <h1 className="text-2xl font-bold" style={{ color: rank.color }}>{rank.name}</h1>
                  <div className="font-mono text-sm text-gray-400">
                    <span className="text-emerald">{progress.xp}</span> XP
                    {nextRank && (
                      <span className="text-gray-500"> · {nextRank.minXp - progress.xp} XP to {nextRank.name}</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="font-mono text-xs uppercase tracking-wider text-gray-500">Exam Readiness</div>
              <div className={`font-mono text-4xl font-bold ${overall >= 70 ? 'text-emerald' : 'text-cyber'}`}>{overall}%</div>
            </div>
          </div>

          <div className="mt-5">
            <div className="h-2.5 overflow-hidden rounded-full bg-gray-800">
              <div className="h-full rounded-full bg-gradient-to-r from-cyber to-emerald transition-all" style={{ width: `${pct}%` }} />
            </div>
            <div className="mt-3 grid grid-cols-4 gap-2">
              {RANKS.map((r, i) => (
                <div key={r.name} className={`rounded-md border px-2 py-1.5 text-center ${i <= rankIndex ? 'border-gray-700 bg-gray-900' : 'border-gray-800/60 opacity-50'}`}>
                  <div className="truncate font-mono text-[10px] sm:text-[11px]" style={{ color: i <= rankIndex ? r.color : undefined }}>{r.name}</div>
                  <div className="font-mono text-[10px] text-gray-500">{r.minXp} XP</div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-6 flex flex-wrap gap-3">
            <button
              onClick={drillWeakest}
              className="flex items-center gap-2 rounded-lg bg-amber-500/90 px-4 py-2.5 font-semibold text-obsidian hover:bg-amber-400"
            >
              <TrendingDown className="h-4 w-4" />
              Drill Weakest Domain
              <span className="rounded bg-obsidian/20 px-1.5 font-mono text-xs">{weakest.code}</span>
            </button>
            <button
              onClick={startQuickTriage}
              className="flex items-center gap-2 rounded-lg bg-cyber px-4 py-2.5 font-semibold text-obsidian hover:bg-cyan-400"
            >
              <Zap className="h-4 w-4" />
              Quick Triage (10Q)
            </button>
            <button
              onClick={() => onNavigate('labs')}
              className="flex items-center gap-2 rounded-lg border border-emerald/50 px-4 py-2.5 font-semibold text-emerald hover:bg-emerald/10"
            >
              <Terminal className="h-4 w-4" />
              Open Incident Labs
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <StatTile
            icon={Flame}
            label="Daily Streak"
            value={`${progress.streak.count}d`}
            sub={`Best ${progress.streak.best || progress.streak.count}d`}
            accent="text-orange-400"
          />
          <StatTile
            icon={Target}
            label="Accuracy"
            value={`${stats.accuracy}%`}
            sub={`${stats.attempts} attempts`}
          />
          <StatTile
            icon={ListChecks}
            label="MCQs Seen"
            value={`${stats.answered}/${dataset.questions.length}`}
            sub={`Run ${progress.mcqRun} · best ${progress.bestMcqRun || 0}`}
            accent="text-emerald"
          />
          <StatTile
            icon={Layers}
            label="Cards Mastered"
            value={`${stats.mastered}/${dataset.flashcards.length}`}
            sub={`Labs ${stats.labsDone}/${dataset.labs.length}`}
          />
        </div>
      </section>

      {/* Domain readiness */}
      <section className="rounded-xl border border-gray-800 bg-card p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <Activity className="h-5 w-5 text-cyber" /> Domain Readiness
          </h2>
          <span className="font-mono text-xs text-gray-500">mastery = correct MCQs + mastered cards + closed labs (×5)</span>
        </div>
        <div className="space-y-4">
          {mastery.map((d) => (
            <div key={d.id} className="group">
              <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2">
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-xs text-cyber">{d.code}</span>
                  <span className="text-sm text-gray-200">{d.name}</span>
                  {d.id === weakest.id && (
                    <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] text-amber-400">WEAKEST</span>
                  )}
                </div>
                <div className="flex items-center gap-3 font-mono text-[11px] text-gray-500">
                  <span>Q {d.correctNow}/{d.totalQuestions}</span>
                  <span>Cards {d.cardsMastered}/{d.totalCards}</span>
                  <span>Labs {d.labsDone}/{d.totalLabs}</span>
                  <span>Acc {d.accuracy === null ? '—' : `${d.accuracy}%`}</span>
                  <span className="w-10 text-right text-sm font-bold text-gray-200">{d.mastery}%</span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-gray-800">
                  <div className={`h-full rounded-full bg-gradient-to-r ${barColor(d.mastery)} transition-all`} style={{ width: `${Math.max(d.mastery, 1)}%` }} />
                </div>
                <button
                  onClick={() =>
                    onStartDrill({
                      title: `${d.code} drill — ${d.name}`,
                      questionIds: dataset.questions
                        .filter((q) => Number(q.domain) === d.id)
                        .sort(() => Math.random() - 0.5)
                        .map((q) => q.id),
                      domain: d.id,
                    })
                  }
                  className="flex items-center gap-1 rounded border border-gray-700 px-2 py-0.5 font-mono text-[11px] text-gray-400 opacity-70 hover:border-cyber hover:text-cyber group-hover:opacity-100"
                >
                  <Crosshair className="h-3 w-3" /> drill
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-800 bg-card p-6">
          <h2 className="mb-3 text-lg font-semibold">XP Rules of Engagement</h2>
          <ul className="space-y-2 font-mono text-sm">
            <li className="flex justify-between"><span className="text-gray-400">Flashcard rated Mastered (first time)</span><span className="text-emerald">+{XP_RULES.flashcardMastered}</span></li>
            <li className="flex justify-between"><span className="text-gray-400">Correct MCQ</span><span className="text-emerald">+{XP_RULES.mcqCorrect}</span></li>
            <li className="flex justify-between"><span className="text-gray-400">Every {XP_RULES.mcqStreakEvery} correct in a row</span><span className="text-emerald">+{XP_RULES.mcqStreakBonus}</span></li>
            <li className="flex justify-between"><span className="text-gray-400">Incident Lab closed (first time)</span><span className="text-emerald">+{XP_RULES.labComplete}</span></li>
            <li className="flex justify-between"><span className="text-gray-400">Lab hint revealed</span><span className="text-red-400">-{XP_RULES.hintCost}</span></li>
          </ul>
        </div>
        <div className="rounded-xl border border-gray-800 bg-card p-6">
          <h2 className="mb-3 text-lg font-semibold">Recent Exam Simulations</h2>
          {recentExams.length === 0 ? (
            <p className="text-sm text-gray-500">
              No simulations yet. Run one from the Exam Bank to get a timed, domain-by-domain score breakdown.
            </p>
          ) : (
            <ul className="space-y-2">
              {recentExams.map((e) => {
                const score = Math.round((e.correct / e.total) * 100);
                return (
                  <li key={e.at} className="flex items-center justify-between rounded-md border border-gray-800 px-3 py-2 font-mono text-sm">
                    <span className="text-gray-400">{new Date(e.at).toLocaleString()}</span>
                    <span className="text-gray-500">{e.domain ? getDomain(e.domain).code : 'ALL'} · {e.total}Q</span>
                    <span className={score >= 70 ? 'text-emerald' : 'text-red-400'}>{score}%</span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </section>

      <div className="flex justify-end">
        {confirmReset ? (
          <div className="flex items-center gap-2 text-sm">
            <span className="text-red-400">Wipe all XP, streak and progress?</span>
            <button onClick={() => { onResetProgress(); setConfirmReset(false); }} className="rounded bg-red-500/80 px-3 py-1 text-white hover:bg-red-500">Yes, reset</button>
            <button onClick={() => setConfirmReset(false)} className="rounded border border-gray-700 px-3 py-1 text-gray-300">Cancel</button>
          </div>
        ) : (
          <button onClick={() => setConfirmReset(true)} className="flex items-center gap-1 text-xs text-gray-600 hover:text-red-400">
            <RotateCcw className="h-3 w-3" /> Reset progress
          </button>
        )}
      </div>
    </div>
  );
}
