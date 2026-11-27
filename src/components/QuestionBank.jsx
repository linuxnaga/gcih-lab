import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  Filter,
  Flag,
  GraduationCap,
  ListChecks,
  Play,
  Shuffle,
  Timer,
  X,
  XCircle,
} from 'lucide-react';
import { DIFFICULTIES, DOMAINS, getDomain } from '../data/index.js';

const LETTERS = ['A', 'B', 'C', 'D'];
const PASS_MARK = 70;

const DIFF_CLS = {
  Easy: 'bg-emerald/10 text-emerald',
  Medium: 'bg-cyber/10 text-cyber',
  Hard: 'bg-red-500/10 text-red-400',
};

function shuffled(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function matchesStatus(q, progress, status) {
  const rec = progress.questions[q.id];
  if (status === 'unanswered') return !rec;
  if (status === 'missed') return rec && !rec.lastCorrect;
  if (status === 'correct') return rec && rec.lastCorrect;
  return true;
}

function formatTime(sec) {
  const s = Math.max(0, sec);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return `${h > 0 ? `${h}:` : ''}${String(m).padStart(2, '0')}:${String(r).padStart(2, '0')}`;
}

export function ScenarioLog({ log }) {
  if (!log) return null;
  return (
    <div className="overflow-hidden rounded-lg border border-gray-800">
      <div className="flex items-center gap-1.5 border-b border-gray-800 bg-gray-900/80 px-3 py-1.5">
        <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-500/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-emerald/70" />
        <span className="ml-2 font-mono text-[11px] text-gray-500">evidence.log</span>
      </div>
      <pre className="log-block m-0 max-h-80 rounded-none border-0 p-4 text-[12.5px] leading-relaxed">{log}</pre>
    </div>
  );
}

function QuestionMeta({ question, index, total }) {
  const d = getDomain(question.domain);
  return (
    <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
      <span className="rounded bg-cyber/10 px-1.5 py-0.5 text-cyber">{d.code}</span>
      <span className={`rounded px-1.5 py-0.5 ${DIFF_CLS[question.difficulty] || 'bg-gray-800 text-gray-400'}`}>{question.difficulty}</span>
      <span className="text-gray-500">{question.id}</span>
      {total !== undefined && <span className="ml-auto text-gray-500">Q {index + 1} / {total}</span>}
    </div>
  );
}

function Options({ question, selected, revealed, onSelect, examMode }) {
  return (
    <div className="space-y-2">
      {question.options.map((opt, i) => {
        let cls = 'border-gray-700 hover:border-cyber/60 hover:bg-cyber/5';
        let icon = null;
        if (revealed) {
          if (i === question.correctIndex) {
            cls = 'border-emerald bg-emerald/10';
            icon = <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald" />;
          } else if (i === selected) {
            cls = 'border-red-500 bg-red-500/10';
            icon = <XCircle className="h-4 w-4 shrink-0 text-red-400" />;
          } else {
            cls = 'border-gray-800 opacity-60';
          }
        } else if (examMode && i === selected) {
          cls = 'border-cyber bg-cyber/10';
        }
        return (
          <button
            key={i}
            disabled={revealed}
            onClick={() => onSelect(i)}
            className={`flex w-full items-start gap-3 rounded-lg border px-4 py-3 text-left text-sm transition ${cls}`}
          >
            <span className="mt-0.5 rounded border border-gray-600 px-1.5 font-mono text-xs text-gray-400">{LETTERS[i]}</span>
            <span className="flex-1 whitespace-pre-wrap text-gray-200">{opt}</span>
            {icon}
          </button>
        );
      })}
    </div>
  );
}

function Explanation({ question, selected }) {
  const correct = selected === question.correctIndex;
  return (
    <div className={`rounded-lg border p-4 ${correct ? 'border-emerald/40 bg-emerald/5' : 'border-red-500/40 bg-red-500/5'}`}>
      <div className={`mb-2 flex items-center gap-2 font-semibold ${correct ? 'text-emerald' : 'text-red-400'}`}>
        {correct ? <CheckCircle2 className="h-5 w-5" /> : <XCircle className="h-5 w-5" />}
        {correct ? 'Correct' : selected === null || selected === undefined ? 'Not answered' : 'Incorrect'}
        <span className="font-mono text-xs text-gray-400">
          · answer {LETTERS[question.correctIndex]}
        </span>
      </div>
      <p className="whitespace-pre-wrap text-sm leading-relaxed text-gray-300">{question.explanation}</p>
      <div className="mt-3 space-y-1 border-t border-gray-800 pt-3">
        <div className="font-mono text-[11px] uppercase tracking-wider text-gray-500">Distractor review</div>
        {question.options.map((opt, i) =>
          i === question.correctIndex ? null : (
            <div key={i} className="flex gap-2 text-xs text-gray-500">
              <span className="font-mono text-red-400/80">✗ {LETTERS[i]}</span>
              <span className={i === selected ? 'text-red-300' : ''}>{opt}</span>
            </div>
          )
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Study mode
// ============================================================================
function StudyMode({ questions, progress, preset, onClearPreset, onAnswer }) {
  const [domain, setDomain] = useState('all');
  const [difficulty, setDifficulty] = useState('all');
  const [status, setStatus] = useState('all');
  const [poolIds, setPoolIds] = useState([]);
  const [idx, setIdx] = useState(0);
  const [answers, setAnswers] = useState({});
  const [shuffleKey, setShuffleKey] = useState(0);
  const [shuffleOn, setShuffleOn] = useState(false);

  const byId = useMemo(() => Object.fromEntries(questions.map((q) => [String(q.id), q])), [questions]);

  // Snapshot the pool on filter change so answering doesn't yank the current question away.
  useEffect(() => {
    let ids;
    if (preset?.questionIds) {
      ids = preset.questionIds.filter((id) => byId[String(id)]);
    } else {
      ids = questions
        .filter(
          (q) =>
            (domain === 'all' || Number(q.domain) === Number(domain)) &&
            (difficulty === 'all' || q.difficulty === difficulty) &&
            matchesStatus(q, progress, status)
        )
        .map((q) => q.id);
      if (shuffleOn) ids = shuffled(ids);
    }
    setPoolIds(ids);
    setIdx(0);
    setAnswers({});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [questions, domain, difficulty, status, preset?.key, shuffleKey, shuffleOn]);

  const current = byId[String(poolIds[idx])];
  const selected = current ? answers[current.id] : undefined;
  const revealed = selected !== undefined;

  const select = useCallback(
    (i) => {
      if (!current || answers[current.id] !== undefined) return;
      setAnswers((a) => ({ ...a, [current.id]: i }));
      onAnswer(current, i);
    },
    [current, answers, onAnswer]
  );

  const go = useCallback(
    (delta) => setIdx((i) => Math.min(Math.max(0, i + delta), Math.max(0, poolIds.length - 1))),
    [poolIds.length]
  );

  useEffect(() => {
    const onKey = (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      const k = e.key.toLowerCase();
      const map = { 1: 0, 2: 1, 3: 2, 4: 3, a: 0, b: 1, c: 2, d: 3 };
      if (k in map && !revealed) select(map[k]);
      else if (k === 'enter' || k === 'arrowright') go(1);
      else if (k === 'arrowleft') go(-1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [select, go, revealed]);

  const answeredCount = Object.keys(answers).length;
  const correctCount = Object.entries(answers).filter(([id, a]) => byId[String(id)]?.correctIndex === a).length;
  const drillDone = preset?.questionIds && poolIds.length > 0 && answeredCount === poolIds.length;

  return (
    <div className="space-y-4">
      {preset ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-500/40 bg-amber-500/5 px-4 py-2.5">
          <GraduationCap className="h-4 w-4 text-amber-400" />
          <span className="text-sm font-semibold text-amber-300">{preset.title}</span>
          <span className="font-mono text-xs text-gray-400">
            {answeredCount}/{poolIds.length} answered · {correctCount} correct
          </span>
          <button onClick={onClearPreset} className="ml-auto flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200">
            <X className="h-3.5 w-3.5" /> exit drill
          </button>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Filter className="h-4 w-4 text-gray-500" />
          <select value={domain} onChange={(e) => setDomain(e.target.value)} className="rounded-md border border-gray-700 bg-card px-2 py-1.5">
            <option value="all">All domains</option>
            {DOMAINS.map((d) => (
              <option key={d.id} value={d.id}>{d.code} · {d.short}</option>
            ))}
          </select>
          <select value={difficulty} onChange={(e) => setDifficulty(e.target.value)} className="rounded-md border border-gray-700 bg-card px-2 py-1.5">
            <option value="all">All difficulties</option>
            {DIFFICULTIES.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)} className="rounded-md border border-gray-700 bg-card px-2 py-1.5">
            <option value="all">All questions</option>
            <option value="unanswered">Unanswered</option>
            <option value="missed">Missed</option>
            <option value="correct">Answered correctly</option>
          </select>
          <button
            onClick={() => { setShuffleOn(true); setShuffleKey((k) => k + 1); }}
            className={`flex items-center gap-1 rounded-md border px-2 py-1.5 ${shuffleOn ? 'border-cyber/60 text-cyber' : 'border-gray-700 text-gray-400'} hover:text-cyber`}
          >
            <Shuffle className="h-3.5 w-3.5" /> shuffle
          </button>
          <span className="ml-auto font-mono text-xs text-gray-500">
            {poolIds.length} in pool · session {correctCount}/{answeredCount}
          </span>
        </div>
      )}

      {drillDone && (
        <div className="rounded-xl border border-emerald/40 bg-emerald/5 p-5">
          <div className="flex items-center gap-2 text-lg font-semibold text-emerald">
            <CheckCircle2 className="h-5 w-5" /> Drill complete: {correctCount}/{poolIds.length} ({Math.round((correctCount / poolIds.length) * 100)}%)
          </div>
          <p className="mt-1 text-sm text-gray-400">Review any question with the navigator below, or exit the drill to return to the full bank.</p>
        </div>
      )}

      {!current ? (
        <div className="rounded-xl border border-gray-800 bg-card p-12 text-center text-gray-500">
          No questions match these filters.
        </div>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[1fr_220px]">
          <div className="space-y-4 rounded-xl border border-gray-800 bg-card p-5">
            <QuestionMeta question={current} index={idx} total={poolIds.length} />
            <ScenarioLog log={current.scenarioLog} />
            <h2 className="whitespace-pre-wrap text-base font-medium leading-relaxed text-gray-100">{current.question}</h2>
            <Options question={current} selected={selected} revealed={revealed} onSelect={select} />
            {revealed && <Explanation question={current} selected={selected} />}
            <div className="flex items-center justify-between pt-1">
              <button onClick={() => go(-1)} disabled={idx === 0} className="flex items-center gap-1 rounded-md border border-gray-700 px-3 py-1.5 text-sm disabled:opacity-30">
                <ChevronLeft className="h-4 w-4" /> Prev
              </button>
              <span className="font-mono text-[11px] text-gray-600">keys: 1-4 / A-D answer · Enter next · ← prev</span>
              <button
                onClick={() => go(1)}
                disabled={idx >= poolIds.length - 1}
                className="flex items-center gap-1 rounded-md bg-cyber px-3 py-1.5 text-sm font-semibold text-obsidian disabled:opacity-30"
              >
                Next <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
          <Navigator
            ids={poolIds}
            idx={idx}
            onJump={setIdx}
            stateFor={(id) => {
              if (answers[id] === undefined) {
                const rec = progress.questions[id];
                return rec ? (rec.lastCorrect ? 'prev-correct' : 'prev-missed') : 'none';
              }
              return answers[id] === byId[String(id)]?.correctIndex ? 'correct' : 'wrong';
            }}
          />
        </div>
      )}
    </div>
  );
}

function Navigator({ ids, idx, onJump, stateFor }) {
  const cls = {
    none: 'border-gray-800 text-gray-500',
    'prev-correct': 'border-emerald/30 text-emerald/60',
    'prev-missed': 'border-red-500/30 text-red-400/60',
    correct: 'border-emerald bg-emerald/20 text-emerald',
    wrong: 'border-red-500 bg-red-500/20 text-red-400',
    answered: 'border-cyber/60 bg-cyber/15 text-cyber',
    flagged: 'border-amber-500 bg-amber-500/20 text-amber-400',
  };
  return (
    <div className="h-fit rounded-xl border border-gray-800 bg-card p-3 lg:sticky lg:top-24">
      <div className="mb-2 font-mono text-[11px] uppercase tracking-wider text-gray-500">Navigator</div>
      <div className="grid max-h-[60vh] grid-cols-6 gap-1 overflow-y-auto pr-1 lg:grid-cols-5">
        {ids.map((id, i) => (
          <button
            key={id}
            onClick={() => onJump(i)}
            className={`rounded border py-1 font-mono text-[11px] ${cls[stateFor(id)]} ${i === idx ? 'ring-2 ring-cyber' : ''}`}
          >
            {i + 1}
          </button>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Exam simulation mode
// ============================================================================
function ExamMode({ questions, progress, onSubmitExam }) {
  const [phase, setPhase] = useState('setup');
  const [cfg, setCfg] = useState({ domain: 'all', count: 50, minutesPer: 1.5, source: 'all' });
  const [exam, setExam] = useState(null); // { questions, answers, flags, idx, endsAt, startedAt }
  const [now, setNow] = useState(Date.now());
  const [result, setResult] = useState(null);
  const [confirmSubmit, setConfirmSubmit] = useState(false);

  const pool = useMemo(
    () =>
      questions.filter(
        (q) => (cfg.domain === 'all' || Number(q.domain) === Number(cfg.domain)) && matchesStatus(q, progress, cfg.source)
      ),
    [questions, cfg.domain, cfg.source, progress]
  );

  const start = () => {
    const picked = shuffled(pool).slice(0, Math.min(cfg.count, pool.length));
    const startedAt = Date.now();
    setExam({
      questions: picked,
      answers: {},
      flags: {},
      idx: 0,
      startedAt,
      endsAt: startedAt + Math.round(picked.length * cfg.minutesPer * 60 * 1000),
    });
    setResult(null);
    setConfirmSubmit(false);
    setPhase('running');
  };

  const submit = useCallback(() => {
    if (!exam) return;
    const items = exam.questions.map((q) => ({ question: q, selectedIndex: exam.answers[q.id] ?? null }));
    const correct = items.filter((i) => i.selectedIndex === i.question.correctIndex).length;
    const byDomain = DOMAINS.map((d) => {
      const di = items.filter((i) => Number(i.question.domain) === d.id);
      const dc = di.filter((i) => i.selectedIndex === i.question.correctIndex).length;
      return { ...d, total: di.length, correct: dc, pct: di.length ? Math.round((dc / di.length) * 100) : null };
    }).filter((d) => d.total > 0);
    const elapsed = Math.min(Date.now(), exam.endsAt) - exam.startedAt;
    const xp = onSubmitExam(items, { domain: cfg.domain === 'all' ? null : Number(cfg.domain), elapsed });
    setResult({ items, correct, total: items.length, byDomain, elapsed, xp, flags: exam.flags });
    setPhase('results');
  }, [exam, cfg.domain, onSubmitExam]);

  useEffect(() => {
    if (phase !== 'running') return undefined;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [phase]);

  useEffect(() => {
    if (phase === 'running' && exam && now >= exam.endsAt) submit();
  }, [now, phase, exam, submit]);

  const setAnswer = (i) =>
    setExam((e) => ({ ...e, answers: { ...e.answers, [e.questions[e.idx].id]: i } }));
  const toggleFlag = () =>
    setExam((e) => {
      const id = e.questions[e.idx].id;
      return { ...e, flags: { ...e.flags, [id]: !e.flags[id] } };
    });
  const jump = (i) => setExam((e) => ({ ...e, idx: Math.min(Math.max(0, i), e.questions.length - 1) }));

  useEffect(() => {
    if (phase !== 'running') return undefined;
    const onKey = (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      const k = e.key.toLowerCase();
      const map = { 1: 0, 2: 1, 3: 2, 4: 3, a: 0, b: 1, c: 2, d: 3 };
      if (k in map) setAnswer(map[k]);
      else if (k === 'f') toggleFlag();
      else if (k === 'arrowright' || k === 'enter') setExam((ex) => ({ ...ex, idx: Math.min(ex.idx + 1, ex.questions.length - 1) }));
      else if (k === 'arrowleft') setExam((ex) => ({ ...ex, idx: Math.max(ex.idx - 1, 0) }));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [phase]);

  if (phase === 'setup') {
    return (
      <div className="mx-auto max-w-2xl rounded-xl border border-gray-800 bg-card p-6">
        <h2 className="flex items-center gap-2 text-xl font-semibold">
          <Timer className="h-5 w-5 text-cyber" /> Exam Simulation
        </h2>
        <p className="mt-1 text-sm text-gray-500">
          Timed, no feedback until you submit. Flag questions to revisit. The real GCIH is 106 questions in 4 hours with a
          70% pass mark; the default here is 1.5 minutes per question.
        </p>
        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          <label className="text-sm">
            <span className="mb-1 block text-gray-400">Domain</span>
            <select value={cfg.domain} onChange={(e) => setCfg({ ...cfg, domain: e.target.value })} className="w-full rounded-md border border-gray-700 bg-obsidian px-2 py-2">
              <option value="all">All domains (mixed)</option>
              {DOMAINS.map((d) => (
                <option key={d.id} value={d.id}>{d.code} · {d.name}</option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-gray-400">Question source</span>
            <select value={cfg.source} onChange={(e) => setCfg({ ...cfg, source: e.target.value })} className="w-full rounded-md border border-gray-700 bg-obsidian px-2 py-2">
              <option value="all">All questions</option>
              <option value="unanswered">Unanswered only</option>
              <option value="missed">Missed only</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-gray-400">Number of questions</span>
            <select value={cfg.count} onChange={(e) => setCfg({ ...cfg, count: Number(e.target.value) })} className="w-full rounded-md border border-gray-700 bg-obsidian px-2 py-2">
              {[10, 25, 50, 75, 106, 200].map((n) => (
                <option key={n} value={n}>{n}{n === 106 ? ' (real exam length)' : ''}</option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-gray-400">Minutes per question</span>
            <select value={cfg.minutesPer} onChange={(e) => setCfg({ ...cfg, minutesPer: Number(e.target.value) })} className="w-full rounded-md border border-gray-700 bg-obsidian px-2 py-2">
              {[1, 1.5, 2, 2.25].map((n) => (
                <option key={n} value={n}>{n} min{n === 2.25 ? ' (real exam pace)' : ''}</option>
              ))}
            </select>
          </label>
        </div>
        <div className="mt-5 flex items-center justify-between">
          <span className="font-mono text-xs text-gray-500">
            {Math.min(cfg.count, pool.length)} questions · {formatTime(Math.round(Math.min(cfg.count, pool.length) * cfg.minutesPer * 60))} on the clock
          </span>
          <button
            onClick={start}
            disabled={pool.length === 0}
            className="flex items-center gap-2 rounded-lg bg-cyber px-5 py-2 font-semibold text-obsidian hover:bg-cyan-400 disabled:opacity-30"
          >
            <Play className="h-4 w-4" /> Start exam
          </button>
        </div>
      </div>
    );
  }

  if (phase === 'results' && result) {
    const pct = Math.round((result.correct / result.total) * 100);
    const passed = pct >= PASS_MARK;
    const missed = result.items.filter((i) => i.selectedIndex !== i.question.correctIndex);
    return (
      <div className="space-y-5">
        <div className={`rounded-xl border p-6 ${passed ? 'border-emerald/50 bg-emerald/5' : 'border-red-500/50 bg-red-500/5'}`}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="font-mono text-xs uppercase tracking-[0.25em] text-gray-500">Simulation Result</div>
              <div className={`text-4xl font-bold ${passed ? 'text-emerald' : 'text-red-400'}`}>{pct}% · {passed ? 'PASS' : 'FAIL'}</div>
              <div className="mt-1 font-mono text-sm text-gray-400">
                {result.correct}/{result.total} correct · {formatTime(Math.round(result.elapsed / 1000))} elapsed · +{result.xp} XP
              </div>
            </div>
            <button onClick={() => setPhase('setup')} className="rounded-lg bg-cyber px-4 py-2 font-semibold text-obsidian">
              New simulation
            </button>
          </div>
          <div className="mt-6 space-y-3">
            <div className="font-mono text-xs uppercase tracking-wider text-gray-500">Domain breakdown</div>
            {result.byDomain.map((d) => (
              <div key={d.id}>
                <div className="mb-1 flex justify-between text-sm">
                  <span><span className="font-mono text-cyber">{d.code}</span> {d.name}</span>
                  <span className={`font-mono ${d.pct >= PASS_MARK ? 'text-emerald' : 'text-red-400'}`}>{d.correct}/{d.total} · {d.pct}%</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-gray-800">
                  <div className={`h-full ${d.pct >= PASS_MARK ? 'bg-emerald' : 'bg-red-500'}`} style={{ width: `${Math.max(2, d.pct)}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Review missed &amp; unanswered ({missed.length})</h3>
          {missed.length === 0 && <p className="text-sm text-gray-500">Flawless. Nothing to review.</p>}
          {missed.map(({ question, selectedIndex }) => (
            <div key={question.id} className="space-y-3 rounded-xl border border-gray-800 bg-card p-5">
              <div className="flex items-center gap-2">
                <QuestionMeta question={question} />
                {result.flags[question.id] && <Flag className="h-3.5 w-3.5 text-amber-400" />}
              </div>
              <ScenarioLog log={question.scenarioLog} />
              <h4 className="whitespace-pre-wrap text-sm font-medium text-gray-100">{question.question}</h4>
              <Options question={question} selected={selectedIndex} revealed onSelect={() => {}} />
              <Explanation question={question} selected={selectedIndex} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  // Running
  const q = exam.questions[exam.idx];
  const remaining = Math.round((exam.endsAt - now) / 1000);
  const answered = Object.keys(exam.answers).length;
  const flaggedCount = Object.values(exam.flags).filter(Boolean).length;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4 rounded-lg border border-gray-800 bg-card px-4 py-2.5">
        <div className={`flex items-center gap-2 font-mono text-lg ${remaining < 300 ? 'text-red-400' : 'text-cyber'}`}>
          <Clock className="h-5 w-5" /> {formatTime(remaining)}
        </div>
        <span className="font-mono text-xs text-gray-400">answered {answered}/{exam.questions.length}</span>
        <span className="font-mono text-xs text-amber-400">flagged {flaggedCount}</span>
        <div className="ml-auto flex items-center gap-2">
          {confirmSubmit ? (
            <>
              <span className="text-xs text-amber-400">
                {exam.questions.length - answered > 0 ? `${exam.questions.length - answered} unanswered. ` : ''}Submit now?
              </span>
              <button onClick={submit} className="rounded bg-emerald px-3 py-1.5 text-sm font-semibold text-obsidian">Submit</button>
              <button onClick={() => setConfirmSubmit(false)} className="rounded border border-gray-700 px-3 py-1.5 text-sm">Cancel</button>
            </>
          ) : (
            <button onClick={() => setConfirmSubmit(true)} className="rounded bg-emerald px-3 py-1.5 text-sm font-semibold text-obsidian">
              Submit exam
            </button>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_220px]">
        <div className="space-y-4 rounded-xl border border-gray-800 bg-card p-5">
          <div className="flex items-center gap-2">
            <div className="flex-1"><QuestionMeta question={q} index={exam.idx} total={exam.questions.length} /></div>
          </div>
          <ScenarioLog log={q.scenarioLog} />
          <h2 className="whitespace-pre-wrap text-base font-medium leading-relaxed text-gray-100">{q.question}</h2>
          <Options question={q} selected={exam.answers[q.id]} revealed={false} onSelect={setAnswer} examMode />
          <div className="flex items-center justify-between pt-1">
            <button onClick={() => jump(exam.idx - 1)} disabled={exam.idx === 0} className="flex items-center gap-1 rounded-md border border-gray-700 px-3 py-1.5 text-sm disabled:opacity-30">
              <ChevronLeft className="h-4 w-4" /> Prev
            </button>
            <button
              onClick={toggleFlag}
              className={`flex items-center gap-1 rounded-md border px-3 py-1.5 text-sm ${exam.flags[q.id] ? 'border-amber-500 bg-amber-500/15 text-amber-400' : 'border-gray-700 text-gray-400'}`}
            >
              <Flag className="h-4 w-4" /> {exam.flags[q.id] ? 'Flagged' : 'Flag (F)'}
            </button>
            <button
              onClick={() => jump(exam.idx + 1)}
              disabled={exam.idx >= exam.questions.length - 1}
              className="flex items-center gap-1 rounded-md bg-cyber px-3 py-1.5 text-sm font-semibold text-obsidian disabled:opacity-30"
            >
              Next <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
        <Navigator
          ids={exam.questions.map((x) => x.id)}
          idx={exam.idx}
          onJump={jump}
          stateFor={(id) => (exam.flags[id] ? 'flagged' : exam.answers[id] !== undefined ? 'answered' : 'none')}
        />
      </div>
      {remaining < 300 && (
        <div className="flex items-center gap-2 text-sm text-red-400">
          <AlertTriangle className="h-4 w-4" /> Under five minutes left. The exam auto-submits at 00:00.
        </div>
      )}
    </div>
  );
}

// ============================================================================
export default function QuestionBank({ questions, progress, preset, onClearPreset, onAnswer, onSubmitExam }) {
  const [mode, setMode] = useState('study');

  useEffect(() => {
    if (preset) setMode('study');
  }, [preset?.key]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <ListChecks className="h-6 w-6 text-cyber" /> Exam Bank
          </h1>
          <p className="text-sm text-gray-500">{questions.length} scenario-driven MCQs across 5 GCIH domains.</p>
        </div>
        <div className="flex rounded-lg border border-gray-700 bg-card p-1">
          <button
            onClick={() => setMode('study')}
            className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-sm ${mode === 'study' ? 'bg-cyber/15 text-cyber' : 'text-gray-400'}`}
          >
            <BookOpen className="h-4 w-4" /> Study Mode
          </button>
          <button
            onClick={() => setMode('exam')}
            className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-sm ${mode === 'exam' ? 'bg-cyber/15 text-cyber' : 'text-gray-400'}`}
          >
            <Timer className="h-4 w-4" /> Exam Simulation
          </button>
        </div>
      </div>
      {mode === 'study' ? (
        <StudyMode questions={questions} progress={progress} preset={preset} onClearPreset={onClearPreset} onAnswer={onAnswer} />
      ) : (
        <ExamMode questions={questions} progress={progress} onSubmitExam={onSubmitExam} />
      )}
    </div>
  );
}
