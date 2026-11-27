import React, { useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileUp, Trash2, Upload, X } from 'lucide-react';

const SAMPLE = `[
  {
    "id": "custom-q-001",
    "domain": 1,
    "difficulty": "Medium",
    "scenarioLog": "$ tcpdump -nn -r capture.pcap 'tcp[13] & 2 != 0' | head -3",
    "question": "What does this BPF filter match?",
    "options": ["Packets with SYN set", "Packets with ACK set", "Only RST packets", "UDP traffic"],
    "correctIndex": 0,
    "explanation": "tcp[13] is the flags byte; bit value 2 is SYN."
  },
  {
    "id": "custom-fc-001",
    "domain": 5,
    "tag": "Registry",
    "front": "Per-user Run key path?",
    "back": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
  }
]`;

function normalizeDomain(value) {
  if (typeof value === 'number') return value;
  const m = String(value ?? '').match(/(\d)/);
  return m ? Number(m[1]) : NaN;
}

const isStr = (v) => typeof v === 'string' && v.trim().length > 0;
const isId = (v) => (typeof v === 'string' && v.trim()) || typeof v === 'number';
const fourStrings = (v) => Array.isArray(v) && v.length === 4 && v.every((o) => typeof o === 'string');
const validIndex = (v) => Number.isInteger(v) && v >= 0 && v <= 3;

function classify(item) {
  if (!item || typeof item !== 'object') return null;
  if (Array.isArray(item.steps)) return 'labs';
  if ('front' in item && 'back' in item) return 'flashcards';
  if ('question' in item && 'options' in item) return 'questions';
  return null;
}

function validate(kind, raw) {
  const errors = [];
  const item = { ...raw, domain: normalizeDomain(raw.domain) };
  if (!isId(item.id)) errors.push('missing id');
  if (!(item.domain >= 1 && item.domain <= 5)) errors.push('domain must be 1-5');
  if (kind === 'questions') {
    if (!isStr(item.difficulty)) item.difficulty = 'Medium';
    if (!isStr(item.question)) errors.push('missing question');
    if (!fourStrings(item.options)) errors.push('options must be 4 strings');
    if (!validIndex(item.correctIndex)) errors.push('correctIndex must be 0-3');
    if (!isStr(item.explanation)) errors.push('missing explanation');
    if (typeof item.scenarioLog !== 'string') item.scenarioLog = '';
  }
  if (kind === 'flashcards') {
    if (!isStr(item.tag)) item.tag = 'General';
    if (!isStr(item.front)) errors.push('missing front');
    if (!isStr(item.back)) errors.push('missing back');
  }
  if (kind === 'labs') {
    if (!isStr(item.title)) errors.push('missing title');
    if (!isStr(item.briefing)) errors.push('missing briefing');
    if (!isStr(item.difficulty)) item.difficulty = 'Medium';
    item.xpReward = Number.isFinite(item.xpReward) ? item.xpReward : 250;
    if (!Array.isArray(item.steps) || item.steps.length === 0) errors.push('steps must be a non-empty array');
    else {
      item.steps = item.steps.map((s, i) => ({ ...s, stepNumber: Number.isInteger(s.stepNumber) ? s.stepNumber : i + 1 }));
      item.steps.forEach((s) => {
        const p = `step ${s.stepNumber}`;
        ['objective', 'evidence', 'question', 'hint', 'walkthrough'].forEach((f) => {
          if (typeof s[f] !== 'string') errors.push(`${p}: missing ${f}`);
        });
        if (!fourStrings(s.options)) errors.push(`${p}: options must be 4 strings`);
        if (!validIndex(s.correctIndex)) errors.push(`${p}: correctIndex must be 0-3`);
      });
    }
  }
  return { item, errors };
}

// Accepts JSON, a bare JS array/object literal, or a JS module using `export const x = [...]` / `export default [...]`.
function parseInput(text) {
  const trimmed = text.trim();
  if (!trimmed) throw new Error('Nothing to import.');
  try {
    return JSON.parse(trimmed);
  } catch (jsonErr) {
    // Fall through to JS parsing.
  }
  const stripped = trimmed.replace(/^\s*import\s.+?;?\s*$/gm, '');
  if (/^[[{]/.test(stripped)) {
    // eslint-disable-next-line no-new-func
    return new Function(`"use strict"; return (${stripped});`)();
  }
  const body = stripped
    .replace(/export\s+default\s+/g, '__out.default = ')
    .replace(/export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g, '__out.$1 =')
    .replace(/^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/gm, '__out.$1 =')
    .replace(/^\s*export\s*\{[^}]*\};?\s*$/gm, '');
  // eslint-disable-next-line no-new-func
  return new Function('__out', `"use strict"; ${body}; return __out;`)({});
}

function collectItems(value, out = []) {
  if (Array.isArray(value)) {
    value.forEach((v) => {
      if (classify(v)) out.push(v);
      else if (Array.isArray(v)) collectItems(v, out);
    });
  } else if (value && typeof value === 'object') {
    if (classify(value)) out.push(value);
    else Object.values(value).forEach((v) => collectItems(v, out));
  }
  return out;
}

export default function ImportModal({ onClose, onImport, onClear, customCounts }) {
  const [text, setText] = useState('');
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState(null);
  const [done, setDone] = useState(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const fileRef = useRef(null);

  const analyze = (source = text) => {
    setError(null);
    setDone(null);
    try {
      const parsed = parseInput(source);
      const items = collectItems(parsed);
      const result = { questions: [], flashcards: [], labs: [], invalid: [] };
      items.forEach((raw, i) => {
        const kind = classify(raw);
        const { item, errors } = validate(kind, raw);
        if (errors.length) result.invalid.push({ id: raw.id ?? `#${i + 1}`, kind, errors });
        else result[kind].push(item);
      });
      if (!items.length) throw new Error('No flashcard, question, or lab objects found. Check the schema keys.');
      setPreview(result);
    } catch (err) {
      setPreview(null);
      setError(err.message || String(err));
    }
  };

  const onFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result || '');
      setText(content);
      analyze(content);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const commit = () => {
    if (!preview) return;
    const summary = onImport(preview);
    setDone(summary);
    setPreview(null);
    setText('');
  };

  const validCount = preview ? preview.questions.length + preview.flashcards.length + preview.labs.length : 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={onClose}>
      <div className="animate-popIn flex max-h-[90vh] w-full max-w-3xl flex-col rounded-2xl border border-gray-700 bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-3">
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <Upload className="h-5 w-5 text-cyber" /> Bulk Import
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-4 overflow-y-auto p-5">
          <p className="text-sm text-gray-400">
            Paste or upload a JSON array, a JS array literal, or a JS module (<code className="font-mono text-cyber">export const questions = [...]</code>).
            Questions, flashcards and labs are detected by their schema keys, validated, and saved to localStorage. Items whose
            <code className="font-mono text-cyber"> id</code> already exists are skipped.
          </p>
          <div className="flex flex-wrap gap-2 font-mono text-[11px] text-gray-500">
            <span className="rounded border border-gray-800 px-2 py-1">MCQ: id, domain, difficulty, scenarioLog, question, options[4], correctIndex, explanation</span>
            <span className="rounded border border-gray-800 px-2 py-1">Flashcard: id, domain, tag, front, back</span>
            <span className="rounded border border-gray-800 px-2 py-1">Lab: id, title, domain, difficulty, xpReward, briefing, steps[]</span>
          </div>

          <textarea
            value={text}
            onChange={(e) => { setText(e.target.value); setPreview(null); }}
            placeholder="Paste JSON or JS here…"
            spellCheck={false}
            className="h-64 w-full resize-y rounded-lg border border-gray-700 bg-obsidian p-3 font-mono text-xs text-emerald-400 placeholder:text-gray-600 focus:border-cyber focus:outline-none"
          />

          <div className="flex flex-wrap items-center gap-2">
            <button onClick={() => analyze()} className="rounded-lg bg-cyber px-4 py-2 text-sm font-semibold text-obsidian hover:bg-cyan-400">
              Validate
            </button>
            <button onClick={() => fileRef.current?.click()} className="flex items-center gap-1 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:border-cyber/60">
              <FileUp className="h-4 w-4" /> Upload .json / .js
            </button>
            <input ref={fileRef} type="file" accept=".json,.js,.mjs,.txt,application/json,text/javascript" className="hidden" onChange={onFile} />
            <button onClick={() => { setText(SAMPLE); setPreview(null); }} className="text-xs text-gray-500 hover:text-cyber">
              insert sample
            </button>
          </div>

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-500/5 p-3 text-sm text-red-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> {error}
            </div>
          )}

          {preview && (
            <div className="space-y-3 rounded-lg border border-gray-700 bg-obsidian p-4">
              <div className="grid grid-cols-4 gap-2 text-center font-mono text-sm">
                <div><div className="text-2xl text-cyber">{preview.questions.length}</div><div className="text-[11px] text-gray-500">questions</div></div>
                <div><div className="text-2xl text-cyber">{preview.flashcards.length}</div><div className="text-[11px] text-gray-500">flashcards</div></div>
                <div><div className="text-2xl text-cyber">{preview.labs.length}</div><div className="text-[11px] text-gray-500">labs</div></div>
                <div><div className={`text-2xl ${preview.invalid.length ? 'text-red-400' : 'text-gray-600'}`}>{preview.invalid.length}</div><div className="text-[11px] text-gray-500">invalid</div></div>
              </div>
              {preview.invalid.length > 0 && (
                <ul className="max-h-32 space-y-1 overflow-y-auto font-mono text-[11px] text-red-300">
                  {preview.invalid.map((inv) => (
                    <li key={`${inv.kind}-${inv.id}`}>[{inv.kind}] {String(inv.id)}: {inv.errors.join('; ')}</li>
                  ))}
                </ul>
              )}
              <button
                onClick={commit}
                disabled={!validCount}
                className="w-full rounded-lg bg-emerald py-2 text-sm font-semibold text-obsidian hover:bg-emerald-400 disabled:opacity-30"
              >
                Import {validCount} valid item{validCount === 1 ? '' : 's'}
              </button>
            </div>
          )}

          {done && (
            <div className="flex items-center gap-2 rounded-lg border border-emerald/40 bg-emerald/5 p-3 text-sm text-emerald">
              <CheckCircle2 className="h-4 w-4" />
              Imported {done.questions} questions, {done.flashcards} flashcards and {done.labs} labs. Duplicates were skipped.
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-gray-800 px-5 py-3 font-mono text-xs text-gray-500">
          <span>
            Imported so far: {customCounts.questions} Q · {customCounts.flashcards} cards · {customCounts.labs} labs
          </span>
          {confirmClear ? (
            <span className="flex items-center gap-2">
              <span className="text-red-400">Remove all imported content?</span>
              <button onClick={() => { onClear(); setConfirmClear(false); }} className="rounded bg-red-500/80 px-2 py-1 text-white">Yes</button>
              <button onClick={() => setConfirmClear(false)} className="rounded border border-gray-700 px-2 py-1">No</button>
            </span>
          ) : (
            <button
              onClick={() => setConfirmClear(true)}
              disabled={!customCounts.questions && !customCounts.flashcards && !customCounts.labs}
              className="flex items-center gap-1 hover:text-red-400 disabled:opacity-30"
            >
              <Trash2 className="h-3.5 w-3.5" /> clear imported
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
