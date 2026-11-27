import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { CheckCircle2, Eye, Filter, Layers, RefreshCw, RotateCw, Tag } from 'lucide-react';
import { DOMAINS, getDomain } from '../data/index.js';

const RATINGS = [
  { value: 0, key: '1', label: 'Needs Review', cls: 'border-red-500/50 text-red-400 hover:bg-red-500/10' },
  { value: 1, key: '2', label: 'Familiar', cls: 'border-amber-500/50 text-amber-400 hover:bg-amber-500/10' },
  { value: 2, key: '3', label: 'Mastered', cls: 'border-emerald/60 text-emerald hover:bg-emerald/10' },
];

// How far back in the session queue a card is re-inserted after rating.
const REQUEUE_OFFSET = { 0: 3, 1: 7 };

function priority(record) {
  if (!record) return 1; // unseen
  if (record.rating === 0) return 0; // needs review first
  if (record.rating === 1) return 2;
  return 3;
}

export default function Flashcards({ cards, progress, onRate }) {
  const [domain, setDomain] = useState('all');
  const [tag, setTag] = useState('all');
  const [includeMastered, setIncludeMastered] = useState(false);
  const [queue, setQueue] = useState([]);
  const [flipped, setFlipped] = useState(false);
  const [session, setSession] = useState({ reviewed: 0, mastered: 0 });
  const [deckKey, setDeckKey] = useState(0);

  const tags = useMemo(() => {
    const pool = domain === 'all' ? cards : cards.filter((c) => Number(c.domain) === Number(domain));
    return [...new Set(pool.map((c) => c.tag))].sort();
  }, [cards, domain]);

  useEffect(() => {
    if (tag !== 'all' && !tags.includes(tag)) setTag('all');
  }, [tags, tag]);

  // Build the deck only when filters change (not on every rating) so the session queue stays stable.
  useEffect(() => {
    const now = Date.now();
    const filtered = cards.filter(
      (c) => (domain === 'all' || Number(c.domain) === Number(domain)) && (tag === 'all' || c.tag === tag)
    );
    const eligible = filtered.filter((c) => {
      const rec = progress.cards[c.id];
      if (includeMastered) return true;
      return !rec || rec.rating !== 2 || (rec.due && rec.due <= now);
    });
    const ordered = [...eligible].sort((a, b) => {
      const pa = priority(progress.cards[a.id]);
      const pb = priority(progress.cards[b.id]);
      if (pa !== pb) return pa - pb;
      return (progress.cards[a.id]?.due || 0) - (progress.cards[b.id]?.due || 0) || Math.random() - 0.5;
    });
    setQueue(ordered.map((c) => c.id));
    setFlipped(false);
    setSession({ reviewed: 0, mastered: 0 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cards, domain, tag, includeMastered, deckKey]);

  const current = useMemo(() => cards.find((c) => c.id === queue[0]), [cards, queue]);

  const rate = useCallback(
    (rating) => {
      if (!current || !flipped) return;
      onRate(current, rating);
      setSession((s) => ({ reviewed: s.reviewed + 1, mastered: s.mastered + (rating === 2 ? 1 : 0) }));
      setQueue((q) => {
        const [head, ...rest] = q;
        if (rating === 2) return rest;
        const pos = Math.min(REQUEUE_OFFSET[rating], rest.length);
        return [...rest.slice(0, pos), head, ...rest.slice(pos)];
      });
      setFlipped(false);
    },
    [current, flipped, onRate]
  );

  useEffect(() => {
    const onKey = (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      if (e.code === 'Space') {
        e.preventDefault();
        setFlipped((f) => !f);
      } else if (['1', '2', '3'].includes(e.key)) {
        rate(Number(e.key) - 1);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [rate]);

  const totalFiltered = cards.filter(
    (c) => (domain === 'all' || Number(c.domain) === Number(domain)) && (tag === 'all' || c.tag === tag)
  );
  const masteredCount = totalFiltered.filter((c) => progress.cards[c.id]?.rating === 2).length;
  const record = current ? progress.cards[current.id] : null;
  const isMultiline = current && /\n/.test(current.back);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <Layers className="h-6 w-6 text-cyber" /> Flashcards
          </h1>
          <p className="text-sm text-gray-500">
            <kbd className="rounded border border-gray-700 px-1 font-mono text-xs">Space</kbd> flip ·{' '}
            <kbd className="rounded border border-gray-700 px-1 font-mono text-xs">1</kbd> Needs Review ·{' '}
            <kbd className="rounded border border-gray-700 px-1 font-mono text-xs">2</kbd> Familiar ·{' '}
            <kbd className="rounded border border-gray-700 px-1 font-mono text-xs">3</kbd> Mastered
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Filter className="h-4 w-4 text-gray-500" />
          <select value={domain} onChange={(e) => setDomain(e.target.value)} className="rounded-md border border-gray-700 bg-card px-2 py-1.5">
            <option value="all">All domains</option>
            {DOMAINS.map((d) => (
              <option key={d.id} value={d.id}>{d.code} · {d.short}</option>
            ))}
          </select>
          <Tag className="h-4 w-4 text-gray-500" />
          <select value={tag} onChange={(e) => setTag(e.target.value)} className="rounded-md border border-gray-700 bg-card px-2 py-1.5">
            <option value="all">All tags</option>
            {tags.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <label className="flex items-center gap-1.5 text-gray-400">
            <input type="checkbox" checked={includeMastered} onChange={(e) => setIncludeMastered(e.target.checked)} className="accent-cyan-500" />
            include mastered
          </label>
        </div>
      </div>

      <div className="flex flex-wrap gap-4 font-mono text-xs text-gray-500">
        <span>Queue <span className="text-cyber">{queue.length}</span></span>
        <span>Session reviewed <span className="text-gray-300">{session.reviewed}</span></span>
        <span>Session mastered <span className="text-emerald">{session.mastered}</span></span>
        <span>Deck mastery <span className="text-emerald">{masteredCount}/{totalFiltered.length}</span></span>
      </div>

      {!current ? (
        <div className="rounded-xl border border-emerald/30 bg-card p-12 text-center">
          <CheckCircle2 className="mx-auto h-12 w-12 text-emerald" />
          <h2 className="mt-3 text-xl font-semibold">Deck cleared</h2>
          <p className="mt-1 text-sm text-gray-500">
            Every card in this filter is mastered and not yet due for review.
          </p>
          <div className="mt-5 flex justify-center gap-3">
            <button onClick={() => setIncludeMastered(true)} className="rounded-lg border border-cyber/50 px-4 py-2 text-cyber hover:bg-cyber/10">
              Review mastered cards anyway
            </button>
          </div>
        </div>
      ) : (
        <div className="mx-auto max-w-3xl">
          <div className="perspective cursor-pointer select-none" onClick={() => setFlipped((f) => !f)}>
            <div
              className={`preserve-3d relative h-80 w-full transition-transform duration-500 ${flipped ? 'rotate-y-180' : ''}`}
            >
              {/* Front */}
              <div className="backface-hidden absolute inset-0 flex flex-col rounded-2xl border border-cyber/30 bg-card p-6 shadow-lg shadow-cyber/5">
                <CardMeta card={current} record={record} />
                <div className="flex flex-1 items-center justify-center px-4 text-center text-xl font-medium leading-relaxed text-gray-100">
                  {current.front}
                </div>
                <div className="flex items-center justify-center gap-2 text-xs text-gray-500">
                  <Eye className="h-3.5 w-3.5" /> click or press Space to reveal
                </div>
              </div>
              {/* Back */}
              <div className="backface-hidden rotate-y-180 absolute inset-0 flex flex-col rounded-2xl border border-emerald/30 bg-card p-6 shadow-lg shadow-emerald/5">
                <CardMeta card={current} record={record} />
                <div className="flex flex-1 items-center justify-center overflow-auto">
                  <div
                    className={`${isMultiline ? 'log-block w-full rounded-lg p-4 text-left text-sm' : 'px-4 text-center text-lg text-gray-100'} whitespace-pre-wrap leading-relaxed`}
                  >
                    {current.back}
                  </div>
                </div>
                <div className="flex items-center justify-center gap-2 text-xs text-gray-500">
                  <RotateCw className="h-3.5 w-3.5" /> rate your recall below
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 grid grid-cols-3 gap-3">
            {RATINGS.map((r) => (
              <button
                key={r.value}
                disabled={!flipped}
                onClick={() => rate(r.value)}
                className={`rounded-lg border bg-card px-3 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-30 ${r.cls}`}
              >
                <span className="mr-2 rounded border border-current px-1.5 font-mono text-xs">{r.key}</span>
                {r.label}
              </button>
            ))}
          </div>
          <div className="mt-3 flex justify-center">
            <button onClick={() => setDeckKey((k) => k + 1)} className="flex items-center gap-1 text-xs text-gray-500 hover:text-cyber">
              <RefreshCw className="h-3 w-3" /> rebuild deck
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function CardMeta({ card, record }) {
  const domain = getDomain(card.domain);
  const status = !record ? 'NEW' : ['NEEDS REVIEW', 'FAMILIAR', 'MASTERED'][record.rating];
  const statusCls = !record
    ? 'text-cyber'
    : ['text-red-400', 'text-amber-400', 'text-emerald'][record.rating];
  return (
    <div className="flex items-center justify-between font-mono text-[11px]">
      <div className="flex items-center gap-2">
        <span className="rounded bg-cyber/10 px-1.5 py-0.5 text-cyber">{domain.code}</span>
        <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-400">#{card.tag}</span>
      </div>
      <span className={statusCls}>{status}</span>
    </div>
  );
}
