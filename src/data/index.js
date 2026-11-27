import { flashcards } from './flashcards.js';
import { labs } from './labs.js';
import { questionsD1 } from './questions_d1.js';
import { questionsD2 } from './questions_d2.js';
import { questionsD3 } from './questions_d3.js';
import { questionsD4 } from './questions_d4.js';
import { questionsD5 } from './questions_d5.js';

export const DOMAINS = [
  { id: 1, code: 'D1', name: 'Incident Response & Digital Forensics', short: 'IR & Forensics' },
  { id: 2, code: 'D2', name: 'Recon, Scanning & Network Detection', short: 'Recon & Detection' },
  { id: 3, code: 'D3', name: 'Password & Cloud Credential Attacks', short: 'Creds & Cloud' },
  { id: 4, code: 'D4', name: 'Web & API Attacks', short: 'Web & API' },
  { id: 5, code: 'D5', name: 'Persistence, Pivoting & Evasion', short: 'Persistence & Evasion' },
];

export const DIFFICULTIES = ['Easy', 'Medium', 'Hard'];

export const RANKS = [
  { name: 'Tier 1 Triage', minXp: 0, color: '#9CA3AF' },
  { name: 'Tier 2 Responder', minXp: 1500, color: '#06B6D4' },
  { name: 'Tier 3 Threat Hunter', minXp: 4500, color: '#10B981' },
  { name: 'Incident Commander', minXp: 9000, color: '#F59E0B' },
];

export const XP_RULES = {
  flashcardMastered: 20,
  mcqCorrect: 50,
  mcqStreakBonus: 25,
  mcqStreakEvery: 5,
  labComplete: 250,
  hintCost: 25,
};

export function getRankIndex(xp) {
  let idx = 0;
  RANKS.forEach((rank, i) => {
    if (xp >= rank.minXp) idx = i;
  });
  return idx;
}

export function getDomain(id) {
  return DOMAINS.find((d) => d.id === Number(id)) || { id, code: `D${id}`, name: `Domain ${id}`, short: `Domain ${id}` };
}

export const baseQuestions = [...questionsD1, ...questionsD2, ...questionsD3, ...questionsD4, ...questionsD5];
export const baseFlashcards = flashcards;
export const baseLabs = labs;

function mergeById(base, extra) {
  const seen = new Set(base.map((item) => String(item.id)));
  const merged = [...base];
  (extra || []).forEach((item) => {
    const key = String(item.id);
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(item);
    }
  });
  return merged;
}

export function buildDataset(custom = {}) {
  return {
    questions: mergeById(baseQuestions, custom.questions),
    flashcards: mergeById(baseFlashcards, custom.flashcards),
    labs: mergeById(baseLabs, custom.labs),
  };
}
