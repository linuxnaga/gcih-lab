import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Award,
  Flame,
  Layers,
  LayoutDashboard,
  ListChecks,
  ShieldCheck,
  Terminal,
  Trophy,
  Upload,
  X,
  Zap,
} from 'lucide-react';
import Dashboard from './components/Dashboard.jsx';
import Flashcards from './components/Flashcards.jsx';
import QuestionBank from './components/QuestionBank.jsx';
import IncidentLabs from './components/IncidentLabs.jsx';
import ImportModal from './components/ImportModal.jsx';
import { DOMAINS, RANKS, XP_RULES, buildDataset, getRankIndex } from './data/index.js';

const PROGRESS_KEY = 'gcih-lab:progress:v1';
const CUSTOM_KEY = 'gcih-lab:custom:v1';

const DEFAULT_PROGRESS = {
  xp: 0,
  streak: { count: 0, best: 0, lastDate: null },
  mcqRun: 0,
  bestMcqRun: 0,
  cards: {},
  questions: {},
  labs: {},
  exams: [],
};

const DEFAULT_CUSTOM = { questions: [], flashcards: [], labs: [] };

const DAY_MS = 24 * 60 * 60 * 1000;

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw);
    return { ...fallback, ...parsed };
  } catch (err) {
    return fallback;
  }
}

function saveJSON(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (err) {
    // Storage full or blocked: progress stays in memory for this session.
  }
}

function localDateKey(date = new Date()) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function touchStreak(progress) {
  const today = localDateKey();
  const { streak } = progress;
  if (streak.lastDate === today) return progress;
  const yesterday = localDateKey(new Date(Date.now() - DAY_MS));
  const count = streak.lastDate === yesterday ? streak.count + 1 : 1;
  return {
    ...progress,
    streak: { count, best: Math.max(streak.best || 0, count), lastDate: today },
  };
}

// Spaced-repetition intervals (ms) by rating: 0 Needs Review, 1 Familiar, 2 Mastered.
function nextDue(rating, reviews) {
  if (rating === 0) return Date.now();
  if (rating === 1) return Date.now() + DAY_MS;
  return Date.now() + Math.min(30, 3 * Math.max(1, reviews)) * DAY_MS;
}

export function computeMastery(dataset, progress) {
  return DOMAINS.map((domain) => {
    const qs = dataset.questions.filter((q) => Number(q.domain) === domain.id);
    const cards = dataset.flashcards.filter((c) => Number(c.domain) === domain.id);
    const labs = dataset.labs.filter((l) => Number(l.domain) === domain.id);
    const qCorrect = qs.filter((q) => progress.questions[q.id]?.lastCorrect).length;
    const qAnswered = qs.filter((q) => progress.questions[q.id]?.attempts > 0).length;
    const qAttempts = qs.reduce((sum, q) => sum + (progress.questions[q.id]?.attempts || 0), 0);
    const qHits = qs.reduce((sum, q) => sum + (progress.questions[q.id]?.correct || 0), 0);
    const cardsMastered = cards.filter((c) => progress.cards[c.id]?.rating === 2).length;
    const labsDone = labs.filter((l) => progress.labs[l.id]?.completed).length;
    const LAB_WEIGHT = 5;
    const denom = qs.length + cards.length + labs.length * LAB_WEIGHT;
    const numer = qCorrect + cardsMastered + labsDone * LAB_WEIGHT;
    return {
      ...domain,
      mastery: denom ? Math.round((numer / denom) * 100) : 0,
      totalQuestions: qs.length,
      answered: qAnswered,
      correctNow: qCorrect,
      accuracy: qAttempts ? Math.round((qHits / qAttempts) * 100) : null,
      totalCards: cards.length,
      cardsMastered,
      totalLabs: labs.length,
      labsDone,
    };
  });
}

const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'flashcards', label: 'Flashcards', icon: Layers },
  { id: 'questions', label: 'Exam Bank', icon: ListChecks },
  { id: 'labs', label: 'Incident Labs', icon: Terminal },
];

export default function App() {
  const [progress, setProgress] = useState(() => touchStreakOnLoad(loadJSON(PROGRESS_KEY, DEFAULT_PROGRESS)));
  const [custom, setCustom] = useState(() => loadJSON(CUSTOM_KEY, DEFAULT_CUSTOM));
  const [view, setView] = useState('dashboard');
  const [qbPreset, setQbPreset] = useState(null);
  const [toasts, setToasts] = useState([]);
  const [rankUp, setRankUp] = useState(null);
  const [importOpen, setImportOpen] = useState(false);

  const progressRef = useRef(progress);
  const rankRef = useRef(getRankIndex(progress.xp));

  const dataset = useMemo(() => buildDataset(custom), [custom]);
  const mastery = useMemo(() => computeMastery(dataset, progress), [dataset, progress]);

  useEffect(() => saveJSON(PROGRESS_KEY, progress), [progress]);
  useEffect(() => saveJSON(CUSTOM_KEY, custom), [custom]);

  useEffect(() => {
    const idx = getRankIndex(progress.xp);
    if (idx > rankRef.current) setRankUp(RANKS[idx]);
    rankRef.current = idx;
  }, [progress.xp]);

  const commit = useCallback((updater) => {
    const next = updater(progressRef.current);
    progressRef.current = next;
    setProgress(next);
    return next;
  }, []);

  const pushToast = useCallback((amount, label) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setToasts((list) => [...list.slice(-4), { id, amount, label }]);
    setTimeout(() => setToasts((list) => list.filter((t) => t.id !== id)), 2100);
  }, []);

  const addXp = (p, amount) => ({ ...p, xp: Math.max(0, p.xp + amount) });

  // ---- MCQ ----
  const applyAnswer = (p, question, selectedIndex) => {
    const correct = selectedIndex === question.correctIndex;
    const prev = p.questions[question.id] || { attempts: 0, correct: 0 };
    const mcqRun = correct ? p.mcqRun + 1 : 0;
    const record = {
      attempts: prev.attempts + 1,
      correct: prev.correct + (correct ? 1 : 0),
      lastCorrect: correct,
      lastAnswer: selectedIndex,
      lastAt: Date.now(),
    };
    let gained = 0;
    let bonus = 0;
    if (correct) {
      gained = XP_RULES.mcqCorrect;
      if (mcqRun % XP_RULES.mcqStreakEvery === 0) bonus = XP_RULES.mcqStreakBonus;
    }
    const next = addXp(
      {
        ...p,
        mcqRun,
        bestMcqRun: Math.max(p.bestMcqRun || 0, mcqRun),
        questions: { ...p.questions, [question.id]: record },
      },
      gained + bonus
    );
    return { next, correct, gained, bonus, mcqRun };
  };

  const answerQuestion = useCallback(
    (question, selectedIndex) => {
      let result;
      commit((p) => {
        result = applyAnswer(touchStreak(p), question, selectedIndex);
        return result.next;
      });
      if (result.gained) pushToast(result.gained, 'Correct answer');
      if (result.bonus) pushToast(result.bonus, `${result.mcqRun} in a row!`);
      return result;
    },
    [commit, pushToast]
  );

  const submitExam = useCallback(
    (items, meta) => {
      // items: [{ question, selectedIndex }] ; unanswered items have selectedIndex === null
      let totalGained = 0;
      let totalBonus = 0;
      commit((p) => {
        let acc = touchStreak(p);
        items.forEach(({ question, selectedIndex }) => {
          if (selectedIndex === null || selectedIndex === undefined) {
            acc = {
              ...acc,
              mcqRun: 0,
              questions: {
                ...acc.questions,
                [question.id]: {
                  ...(acc.questions[question.id] || { attempts: 0, correct: 0 }),
                  attempts: (acc.questions[question.id]?.attempts || 0) + 1,
                  correct: acc.questions[question.id]?.correct || 0,
                  lastCorrect: false,
                  lastAnswer: null,
                  lastAt: Date.now(),
                },
              },
            };
            return;
          }
          const r = applyAnswer(acc, question, selectedIndex);
          totalGained += r.gained;
          totalBonus += r.bonus;
          acc = r.next;
        });
        const correctCount = items.filter((i) => i.selectedIndex === i.question.correctIndex).length;
        const exams = [
          { at: Date.now(), total: items.length, correct: correctCount, ...meta },
          ...(acc.exams || []),
        ].slice(0, 20);
        return { ...acc, exams };
      });
      if (totalGained) pushToast(totalGained, 'Exam answers');
      if (totalBonus) pushToast(totalBonus, 'Streak bonuses');
      return totalGained + totalBonus;
    },
    [commit, pushToast]
  );

  // ---- Flashcards ----
  const rateCard = useCallback(
    (card, rating) => {
      let awarded = false;
      commit((p) => {
        const base = touchStreak(p);
        const prev = base.cards[card.id] || { reviews: 0, masteredAwarded: false };
        const reviews = prev.reviews + 1;
        awarded = rating === 2 && !prev.masteredAwarded;
        const record = {
          rating,
          reviews,
          due: nextDue(rating, reviews),
          masteredAwarded: prev.masteredAwarded || rating === 2,
          lastAt: Date.now(),
        };
        const next = { ...base, cards: { ...base.cards, [card.id]: record } };
        return awarded ? addXp(next, XP_RULES.flashcardMastered) : next;
      });
      if (awarded) pushToast(XP_RULES.flashcardMastered, 'Card mastered');
    },
    [commit, pushToast]
  );

  // ---- Labs ----
  const getLabRecord = (p, labId) => p.labs[labId] || { stepsDone: [], hints: [], wrong: {}, completed: false };

  const spendLabHint = useCallback(
    (lab, stepNumber) => {
      let charged = false;
      commit((p) => {
        const rec = getLabRecord(p, lab.id);
        if (rec.hints.includes(stepNumber)) return p;
        charged = true;
        const next = {
          ...touchStreak(p),
          labs: { ...p.labs, [lab.id]: { ...rec, hints: [...rec.hints, stepNumber] } },
        };
        return addXp(next, -XP_RULES.hintCost);
      });
      if (charged) pushToast(-XP_RULES.hintCost, 'Hint used');
    },
    [commit, pushToast]
  );

  const answerLabStep = useCallback(
    (lab, step, selectedIndex) => {
      const correct = selectedIndex === step.correctIndex;
      let completedNow = false;
      commit((p) => {
        const base = touchStreak(p);
        const rec = getLabRecord(base, lab.id);
        if (!correct) {
          const wrong = { ...rec.wrong, [step.stepNumber]: (rec.wrong?.[step.stepNumber] || 0) + 1 };
          return { ...base, labs: { ...base.labs, [lab.id]: { ...rec, wrong } } };
        }
        const stepsDone = rec.stepsDone.includes(step.stepNumber) ? rec.stepsDone : [...rec.stepsDone, step.stepNumber];
        const allDone = lab.steps.every((s) => stepsDone.includes(s.stepNumber));
        completedNow = allDone && !rec.completed;
        const next = {
          ...base,
          labs: {
            ...base.labs,
            [lab.id]: { ...rec, stepsDone, completed: rec.completed || allDone, completedAt: completedNow ? Date.now() : rec.completedAt },
          },
        };
        return completedNow ? addXp(next, lab.xpReward || XP_RULES.labComplete) : next;
      });
      if (completedNow) pushToast(lab.xpReward || XP_RULES.labComplete, 'Incident closed');
      return { correct, completedNow };
    },
    [commit, pushToast]
  );

  const resetLab = useCallback(
    (lab) => {
      commit((p) => {
        const rec = getLabRecord(p, lab.id);
        // Keep completion status (XP is only awarded once) but clear the workflow so it can be replayed.
        return { ...p, labs: { ...p.labs, [lab.id]: { ...rec, stepsDone: [], hints: [], wrong: {} } } };
      });
    },
    [commit]
  );

  const resetProgress = useCallback(() => {
    commit(() => touchStreak({ ...DEFAULT_PROGRESS, streak: { ...DEFAULT_PROGRESS.streak } }));
    rankRef.current = 0;
  }, [commit]);

  // ---- Import ----
  const importContent = useCallback(
    (incoming) => {
      const summary = { questions: 0, flashcards: 0, labs: 0 };
      const existing = buildDataset(custom);
      const next = { ...custom };
      ['questions', 'flashcards', 'labs'].forEach((kind) => {
        const ids = new Set(existing[kind].map((i) => String(i.id)));
        const fresh = (incoming[kind] || []).filter((item) => {
          const key = String(item.id);
          if (ids.has(key)) return false;
          ids.add(key);
          return true;
        });
        summary[kind] = fresh.length;
        next[kind] = [...(custom[kind] || []), ...fresh];
      });
      setCustom(next);
      return summary;
    },
    [custom]
  );

  const clearCustom = useCallback(() => setCustom(DEFAULT_CUSTOM), []);

  // ---- Navigation helpers ----
  const startDrill = useCallback((preset) => {
    setQbPreset({ ...preset, key: Date.now() });
    setView('questions');
  }, []);

  const rankIndex = getRankIndex(progress.xp);
  const rank = RANKS[rankIndex];
  const nextRank = RANKS[rankIndex + 1];
  const rankPct = nextRank
    ? Math.round(((progress.xp - rank.minXp) / (nextRank.minXp - rank.minXp)) * 100)
    : 100;

  return (
    <div className="min-h-screen bg-obsidian text-gray-200 scanlines">
      <header className="sticky top-0 z-30 border-b border-gray-800 bg-obsidian/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyber/40 bg-cyber/10">
              <ShieldCheck className="h-5 w-5 text-cyber" />
            </div>
            <div className="leading-tight">
              <div className="font-mono text-sm font-bold tracking-wider text-cyber">GCIH//LAB</div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-gray-500">SOC Training Terminal</div>
            </div>
          </div>

          <nav className="order-3 flex w-full gap-1 overflow-x-auto md:order-none md:ml-6 md:w-auto">
            {NAV.map((item) => {
              const Icon = item.icon;
              const active = view === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setView(item.id)}
                  className={`flex items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm transition ${
                    active
                      ? 'bg-cyber/15 text-cyber ring-1 ring-cyber/40'
                      : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </button>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-md border border-gray-800 bg-card px-3 py-1.5 sm:flex" title="Daily streak">
              <Flame className={`h-4 w-4 ${progress.streak.count > 1 ? 'text-orange-400' : 'text-gray-500'}`} />
              <span className="font-mono text-sm">{progress.streak.count}d</span>
            </div>
            <div className="flex items-center gap-2 rounded-md border border-gray-800 bg-card px-3 py-1.5" title={`${rank.name}`}>
              <Award className="h-4 w-4" style={{ color: rank.color }} />
              <div className="leading-tight">
                <div className="font-mono text-[11px]" style={{ color: rank.color }}>{rank.name}</div>
                <div className="flex items-center gap-2">
                  <div className="h-1 w-20 overflow-hidden rounded bg-gray-800">
                    <div className="h-full bg-gradient-to-r from-cyber to-emerald" style={{ width: `${rankPct}%` }} />
                  </div>
                  <span className="font-mono text-[11px] text-emerald">{progress.xp} XP</span>
                </div>
              </div>
            </div>
            <button
              onClick={() => setImportOpen(true)}
              className="flex items-center gap-2 rounded-md border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:border-cyber/60 hover:text-cyber"
              title="Bulk import questions, flashcards, or labs"
            >
              <Upload className="h-4 w-4" />
              <span className="hidden lg:inline">Import</span>
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        {view === 'dashboard' && (
          <Dashboard
            progress={progress}
            dataset={dataset}
            mastery={mastery}
            onStartDrill={startDrill}
            onNavigate={setView}
            onResetProgress={resetProgress}
          />
        )}
        {view === 'flashcards' && <Flashcards cards={dataset.flashcards} progress={progress} onRate={rateCard} />}
        {view === 'questions' && (
          <QuestionBank
            questions={dataset.questions}
            progress={progress}
            preset={qbPreset}
            onClearPreset={() => setQbPreset(null)}
            onAnswer={answerQuestion}
            onSubmitExam={submitExam}
          />
        )}
        {view === 'labs' && (
          <IncidentLabs
            labs={dataset.labs}
            progress={progress}
            onAnswerStep={answerLabStep}
            onUseHint={spendLabHint}
            onResetLab={resetLab}
          />
        )}
      </main>

      <footer className="mx-auto max-w-7xl px-4 pb-8 pt-2 font-mono text-[11px] text-gray-600">
        Progress is stored locally in this browser (localStorage). Not affiliated with GIAC or SANS.
      </footer>

      {/* Floating XP toasts */}
      <div className="pointer-events-none fixed bottom-6 right-6 z-50 flex flex-col items-end gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`animate-floatUp flex items-center gap-2 rounded-lg border px-4 py-2 font-mono text-sm shadow-lg ${
              t.amount >= 0
                ? 'border-emerald/50 bg-emerald/15 text-emerald shadow-emerald/20'
                : 'border-red-500/50 bg-red-500/15 text-red-400 shadow-red-500/20'
            }`}
          >
            <Zap className="h-4 w-4" />
            <span className="font-bold">{t.amount >= 0 ? `+${t.amount}` : t.amount} XP</span>
            <span className="text-xs opacity-80">{t.label}</span>
          </div>
        ))}
      </div>

      {/* Rank-up modal */}
      {rankUp && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setRankUp(null)}>
          <div
            className="animate-popIn relative w-full max-w-md rounded-2xl border bg-card p-8 text-center shadow-2xl"
            style={{ borderColor: rankUp.color, boxShadow: `0 0 60px ${rankUp.color}40` }}
            onClick={(e) => e.stopPropagation()}
          >
            <button onClick={() => setRankUp(null)} className="absolute right-3 top-3 text-gray-500 hover:text-gray-300">
              <X className="h-5 w-5" />
            </button>
            <Trophy className="mx-auto h-16 w-16" style={{ color: rankUp.color }} />
            <div className="mt-4 font-mono text-xs uppercase tracking-[0.3em] text-gray-400">Promotion Authorized</div>
            <h2 className="mt-2 text-3xl font-bold" style={{ color: rankUp.color }}>{rankUp.name}</h2>
            <p className="mt-3 text-sm text-gray-400">
              Your clearance has been elevated. Keep triaging, hunting and closing incidents to climb the ladder.
            </p>
            <button
              onClick={() => setRankUp(null)}
              className="mt-6 rounded-lg bg-cyber px-6 py-2 font-semibold text-obsidian hover:bg-cyan-400"
            >
              Acknowledge
            </button>
          </div>
        </div>
      )}

      {importOpen && (
        <ImportModal
          onClose={() => setImportOpen(false)}
          onImport={importContent}
          onClear={clearCustom}
          customCounts={{
            questions: custom.questions?.length || 0,
            flashcards: custom.flashcards?.length || 0,
            labs: custom.labs?.length || 0,
          }}
        />
      )}
    </div>
  );
}

function touchStreakOnLoad(progress) {
  // Opening the app counts as daily activity, which keeps the streak honest.
  const merged = {
    ...DEFAULT_PROGRESS,
    ...progress,
    streak: { ...DEFAULT_PROGRESS.streak, ...(progress.streak || {}) },
  };
  return touchStreak(merged);
}
