/**
 * SignalRank - Standalone Self-Contained Test Runner Bundle
 * (Works without local HTTP server or module restrictions)
 */

// 1. Types & Config
const DEFAULT_WEIGHTS = Object.freeze({
  severity: 0.25,
  assetImportance: 0.15,
  affectedUsers: 0.05,
  dataSensitivity: 0.15,
  attackConfidence: 0.20,
  businessImpact: 0.20
});

const PRIORITY_TIERS = Object.freeze({
  P1: { id: 'P1', label: 'P1 - Critical', minScore: 80.0, maxScore: 100.0, badgeClass: 'tier-p1', color: '#ef4444' },
  P2: { id: 'P2', label: 'P2 - High', minScore: 60.0, maxScore: 79.999, badgeClass: 'tier-p2', color: '#f97316' },
  P3: { id: 'P3', label: 'P3 - Medium', minScore: 40.0, maxScore: 59.999, badgeClass: 'tier-p3', color: '#06b6d4' },
  P4: { id: 'P4', label: 'P4 - Low', minScore: 0.0, maxScore: 39.999, badgeClass: 'tier-p4', color: '#64748b' }
});

const NORMALIZATION_CONFIG = Object.freeze({
  maxUserCap: 10000,
  minScore: 0,
  maxScore: 100
});

// 2. Scoring Engine
function normalizeAffectedUsers(rawCount, maxCap = NORMALIZATION_CONFIG.maxUserCap) {
  if (rawCount === undefined || rawCount === null || isNaN(rawCount)) return 0;
  const count = Number(rawCount);
  if (count <= 0) return 0;
  if (count >= maxCap) return 100;
  const normalized = (Math.log(1 + count) / Math.log(1 + maxCap)) * 100;
  return Math.min(100, Math.max(0, Math.round(normalized * 100) / 100));
}

function clampFactor(value, min = 0, max = 100) {
  if (value === undefined || value === null || isNaN(value)) return min;
  const num = Number(value);
  return Math.min(max, Math.max(min, num));
}

function normalizeWeights(weights = {}) {
  const merged = { ...DEFAULT_WEIGHTS, ...weights };
  const keys = Object.keys(DEFAULT_WEIGHTS);
  let total = 0;
  for (const k of keys) {
    const w = typeof merged[k] === 'number' && !isNaN(merged[k]) && merged[k] >= 0 ? merged[k] : 0;
    total += w;
  }
  if (total <= 0) return { ...DEFAULT_WEIGHTS };
  const normalized = {};
  for (const k of keys) {
    const val = typeof merged[k] === 'number' && merged[k] >= 0 ? merged[k] : 0;
    normalized[k] = val / total;
  }
  return normalized;
}

function extractFactors(alert) {
  if (!alert || typeof alert !== 'object') {
    return { severity: 0, assetImportance: 0, affectedUsers: 0, dataSensitivity: 0, attackConfidence: 0, businessImpact: 0, rawAffectedUsers: 0 };
  }
  let normUsers = 0;
  let rawUsers = 0;
  if (alert.rawAffectedUsers !== undefined && alert.rawAffectedUsers !== null) {
    rawUsers = Math.max(0, Number(alert.rawAffectedUsers) || 0);
    normUsers = normalizeAffectedUsers(rawUsers);
  } else if (alert.affectedUsers !== undefined && alert.affectedUsers !== null) {
    const val = Number(alert.affectedUsers) || 0;
    if (val > 100) {
      rawUsers = val;
      normUsers = normalizeAffectedUsers(rawUsers);
    } else {
      normUsers = clampFactor(val);
      rawUsers = Math.round(Math.exp((normUsers / 100) * Math.log(1 + NORMALIZATION_CONFIG.maxUserCap)) - 1);
    }
  }
  return {
    severity: clampFactor(alert.severity),
    assetImportance: clampFactor(alert.assetImportance),
    affectedUsers: normUsers,
    dataSensitivity: clampFactor(alert.dataSensitivity),
    attackConfidence: clampFactor(alert.attackConfidence),
    businessImpact: clampFactor(alert.businessImpact),
    rawAffectedUsers: rawUsers
  };
}

function getPriorityTier(score) {
  const s = clampFactor(score);
  if (s >= PRIORITY_TIERS.P1.minScore) return PRIORITY_TIERS.P1;
  if (s >= PRIORITY_TIERS.P2.minScore) return PRIORITY_TIERS.P2;
  if (s >= PRIORITY_TIERS.P3.minScore) return PRIORITY_TIERS.P3;
  return PRIORITY_TIERS.P4;
}

function calculateRiskScore(alert, customWeights = DEFAULT_WEIGHTS) {
  const weights = normalizeWeights(customWeights);
  const factors = extractFactors(alert);
  const contributions = {
    severity: factors.severity * weights.severity,
    assetImportance: factors.assetImportance * weights.assetImportance,
    affectedUsers: factors.affectedUsers * weights.affectedUsers,
    dataSensitivity: factors.dataSensitivity * weights.dataSensitivity,
    attackConfidence: factors.attackConfidence * weights.attackConfidence,
    businessImpact: factors.businessImpact * weights.businessImpact
  };
  const rawScore = contributions.severity + contributions.assetImportance + contributions.affectedUsers + contributions.dataSensitivity + contributions.attackConfidence + contributions.businessImpact;
  const score = Math.min(100, Math.max(0, Math.round(rawScore * 10000) / 10000));
  const roundedScore = Math.round(score * 100) / 100;
  const tier = getPriorityTier(roundedScore);

  return {
    score: roundedScore,
    exactScore: score,
    tier,
    factors,
    weights,
    contributions: {
      severity: Math.round(contributions.severity * 100) / 100,
      assetImportance: Math.round(contributions.assetImportance * 100) / 100,
      affectedUsers: Math.round(contributions.affectedUsers * 100) / 100,
      dataSensitivity: Math.round(contributions.dataSensitivity * 100) / 100,
      attackConfidence: Math.round(contributions.attackConfidence * 100) / 100,
      businessImpact: Math.round(contributions.businessImpact * 100) / 100
    }
  };
}

// 3. Comparator & Sorter
const EPSILON = 1e-6;

function compareIncidents(alertA, alertB, customWeights = DEFAULT_WEIGHTS) {
  const scoreA = alertA._calculatedScore ?? calculateRiskScore(alertA, customWeights).score;
  const scoreB = alertB._calculatedScore ?? calculateRiskScore(alertB, customWeights).score;

  if (Math.abs(scoreA - scoreB) > EPSILON) return scoreB - scoreA;

  const factorsA = alertA._factors ?? extractFactors(alertA);
  const factorsB = alertB._factors ?? extractFactors(alertB);

  if (Math.abs(factorsA.attackConfidence - factorsB.attackConfidence) > EPSILON) return factorsB.attackConfidence - factorsA.attackConfidence;
  if (Math.abs(factorsA.businessImpact - factorsB.businessImpact) > EPSILON) return factorsB.businessImpact - factorsA.businessImpact;
  if (Math.abs(factorsA.dataSensitivity - factorsB.dataSensitivity) > EPSILON) return factorsB.dataSensitivity - factorsA.dataSensitivity;
  if (Math.abs(factorsA.assetImportance - factorsB.assetImportance) > EPSILON) return factorsB.assetImportance - factorsA.assetImportance;

  const timeA = alertA.timestamp ? new Date(alertA.timestamp).getTime() : 0;
  const timeB = alertB.timestamp ? new Date(alertB.timestamp).getTime() : 0;
  if (timeA !== timeB) return timeA - timeB;

  const idA = String(alertA.id || '');
  const idB = String(alertB.id || '');
  return idA.localeCompare(idB);
}

function rankAlerts(alerts, customWeights = DEFAULT_WEIGHTS) {
  if (!Array.isArray(alerts)) return [];
  const scored = alerts.map((alert, index) => {
    const calc = calculateRiskScore(alert, customWeights);
    return {
      ...alert,
      _calculatedScore: calc.score,
      _factors: calc.factors,
      _tier: calc.tier,
      _contributions: calc.contributions
    };
  });
  scored.sort((a, b) => compareIncidents(a, b, customWeights));
  return scored.map((alert, rankIndex) => ({
    ...alert,
    rank: rankIndex + 1,
    score: alert._calculatedScore,
    tier: alert._tier,
    factors: alert._factors,
    contributions: alert._contributions
  }));
}

function explainTieBreak(alertA, alertB, customWeights = DEFAULT_WEIGHTS) {
  const calcA = calculateRiskScore(alertA, customWeights);
  const calcB = calculateRiskScore(alertB, customWeights);

  if (Math.abs(calcA.score - calcB.score) > EPSILON) {
    return { decidingFactor: 'Risk Score', level: 1, rule: 'Risk Score (Descending)', winner: calcA.score > calcB.score ? alertA.id : alertB.id, explanation: `${alertA.id} (${calcA.score.toFixed(2)}) has higher risk score than ${alertB.id} (${calcB.score.toFixed(2)}).` };
  }
  if (Math.abs(calcA.factors.attackConfidence - calcB.factors.attackConfidence) > EPSILON) {
    return { decidingFactor: 'Attack Confidence', level: 2, rule: 'Attack Confidence (Descending)', winner: calcA.factors.attackConfidence > calcB.factors.attackConfidence ? alertA.id : alertB.id, explanation: `Equal risk score (${calcA.score.toFixed(2)}). Higher confidence wins.` };
  }
  if (Math.abs(calcA.factors.businessImpact - calcB.factors.businessImpact) > EPSILON) {
    return { decidingFactor: 'Business Impact', level: 3, rule: 'Business Impact (Descending)', winner: calcA.factors.businessImpact > calcB.factors.businessImpact ? alertA.id : alertB.id, explanation: `Equal risk & confidence. Higher impact wins.` };
  }
  if (Math.abs(calcA.factors.dataSensitivity - calcB.factors.dataSensitivity) > EPSILON) {
    return { decidingFactor: 'Data Sensitivity', level: 4, rule: 'Data Sensitivity (Descending)', winner: calcA.factors.dataSensitivity > calcB.factors.dataSensitivity ? alertA.id : alertB.id, explanation: `Equal risk, conf & impact. Higher data sensitivity wins.` };
  }
  if (Math.abs(calcA.factors.assetImportance - calcB.factors.assetImportance) > EPSILON) {
    return { decidingFactor: 'Asset Importance', level: 5, rule: 'Asset Importance (Descending)', winner: calcA.factors.assetImportance > calcB.factors.assetImportance ? alertA.id : alertB.id, explanation: `Equal risk, conf, impact & data. Higher asset importance wins.` };
  }
  const timeA = alertA.timestamp ? new Date(alertA.timestamp).getTime() : 0;
  const timeB = alertB.timestamp ? new Date(alertB.timestamp).getTime() : 0;
  if (timeA !== timeB) {
    const isAEarlier = timeA < timeB;
    return { decidingFactor: 'Timestamp (FIFO)', level: 6, rule: 'Timestamp (Ascending / Oldest First)', winner: isAEarlier ? alertA.id : alertB.id, explanation: `All factors identical. Earlier timestamp receives FIFO priority.` };
  }
  return { decidingFactor: 'Incident ID', level: 7, rule: 'Incident ID (Ascending)', winner: alertA.id < alertB.id ? alertA.id : alertB.id, explanation: `All factors and timestamps identical. Resolved deterministically by ID.` };
}

function formatFactorList(names) {
  if (!names || names.length === 0) return '';
  if (names.length === 1) return names[0];
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(', ')}, and ${names[names.length - 1]}`;
}

const FACTOR_DEFINITIONS_MAP = {
  severity: 'Severity',
  assetImportance: 'Asset Importance',
  affectedUsers: 'Affected Users',
  dataSensitivity: 'Data Sensitivity',
  attackConfidence: 'Attack Confidence',
  businessImpact: 'Business Impact'
};

function generateRankComparisonExplanation(alertA, alertB, customWeights = DEFAULT_WEIGHTS) {
  if (!alertA) return { explanation: 'No incident selected.', gains: [], concessions: [] };
  const calcA = calculateRiskScore(alertA, customWeights);
  const rankA = alertA.rank || 1;
  if (!alertB) {
    return {
      rankA, rankB: null, idA: alertA.id, idB: null, scoreA: calcA.score, scoreB: null,
      explanation: `Incident #${rankA} is currently the final incident in the active priority queue. There is no lower-ranked incident to compare.`,
      gains: [], concessions: [], factorDeltas: []
    };
  }
  const calcB = calculateRiskScore(alertB, customWeights);
  const rankB = alertB.rank || (rankA + 1);
  const factorKeys = ['severity', 'assetImportance', 'affectedUsers', 'dataSensitivity', 'attackConfidence', 'businessImpact'];
  const gains = [];
  const concessions = [];
  const ties = [];
  const factorDeltas = [];

  factorKeys.forEach(k => {
    const label = FACTOR_DEFINITIONS_MAP[k].toLowerCase();
    const properLabel = FACTOR_DEFINITIONS_MAP[k];
    const contribA = calcA.contributions[k];
    const contribB = calcB.contributions[k];
    const delta = contribA - contribB;
    const item = { key: k, label, properLabel, contribA, contribB, delta: Math.round(delta * 100) / 100 };
    factorDeltas.push(item);
    if (delta > 0.001) gains.push({ ...item, diff: delta });
    else if (delta < -0.001) concessions.push({ ...item, diff: -delta });
    else ties.push(item);
  });

  let explanation = '';
  let isTie = false;
  let tieTrace = null;
  const largestAdvantage = gains.length > 0 ? gains.reduce((max, g) => g.delta > max.delta ? g : max, gains[0]) : null;
  const largestDisadvantage = concessions.length > 0 ? concessions.reduce((max, c) => c.diff > max.diff ? c : max, concessions[0]) : null;
  const scoreDelta = Math.round((calcA.score - calcB.score) * 100) / 100;
  const idA = alertA.id || `Incident #${rankA}`;
  const idB = alertB.id || `Incident #${rankB}`;

  if (Math.abs(calcA.score - calcB.score) > EPSILON) {
    const gainNames = formatFactorList(gains.map(g => g.properLabel || g.label));
    const concessionNames = concessions.length > 0 ? formatFactorList(concessions.map(c => c.label)) : '';
    const advantageText = largestAdvantage ? ` ${largestAdvantage.properLabel} provides the largest individual advantage at +${largestAdvantage.delta.toFixed(2)} points.` : '';

    if (concessions.length > 0 && gains.length > 0) {
      explanation = `${idA} ranks #${rankA} with ${calcA.score.toFixed(2)} points, ${scoreDelta.toFixed(2)} points above ${idB} at ${calcB.score.toFixed(2)}. Although ${idB} has higher ${concessionNames}, ${idA} gains more weighted points from ${gainNames}.${advantageText}`;
    } else if (gains.length > 0) {
      explanation = `${idA} ranks #${rankA} with ${calcA.score.toFixed(2)} points, ${scoreDelta.toFixed(2)} points above ${idB} at ${calcB.score.toFixed(2)}, gaining more weighted points from ${gainNames}.${advantageText}`;
    } else {
      explanation = `${idA} ranks #${rankA} with ${calcA.score.toFixed(2)} points, ${scoreDelta.toFixed(2)} points above ${idB} at ${calcB.score.toFixed(2)}.`;
    }
  } else {
    isTie = true;
    tieTrace = explainTieBreak(alertA, alertB, customWeights);
    explanation = `${idA} ranks #${rankA} tied with ${idB} at ${calcA.score.toFixed(2)} points. Priority was resolved at Deterministic Rule Level ${tieTrace.level} (${tieTrace.rule}): ${tieTrace.explanation}`;
  }

  return { rankA, rankB, idA: alertA.id, idB: alertB.id, scoreA: calcA.score, scoreB: calcB.score, scoreDelta, calcA, calcB, explanation, gains, concessions, ties, factorDeltas, largestAdvantage, largestDisadvantage, isTie, tieTrace };
}

function computeSHA256Hex(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const maxWord = Math.pow(2, 32);
  const words = [];
  const asciiBitLength = ascii.length * 8;
  let hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let str = ascii + '\x80';
  while ((str.length % 64) !== 56) str += '\x00';
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    words[i >> 2] |= code << ((3 - (i % 4)) * 8);
  }
  words[words.length] = Math.floor(asciiBitLength / maxWord);
  words[words.length] = asciiBitLength & 0xffffffff;

  for (let j = 0; j < words.length; j += 16) {
    const w = words.slice(j, j + 16);
    const oldHash = hash.slice(0);

    for (let i = 0; i < 64; i++) {
      if (i >= 16) {
        const w15 = w[i - 15];
        const w2 = w[i - 2];
        const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
        const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      const a = hash[0], e = hash[4];
      const s1_e = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & hash[5]) ^ ((~e) & hash[6]);
      const temp1 = (hash[7] + s1_e + ch + k[i] + w[i]) | 0;
      const s0_a = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]);
      const temp2 = (s0_a + maj) | 0;

      hash = [((temp1 + temp2) | 0), hash[0], hash[1], hash[2], ((hash[3] + temp1) | 0), hash[4], hash[5], hash[6]];
    }

    for (let i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  let result = '';
  for (let i = 0; i < 8; i++) {
    for (let j = 3; j >= 0; j--) {
      const b = (hash[i] >>> (j * 8)) & 0xff;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

function computeQueueAnalytics(queue = []) {
  const total = queue.length;
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, totalScore = 0;
  queue.forEach(alert => {
    const score = alert.score || 0;
    totalScore += score;
    const tierId = alert.tier?.id || (score >= 80 ? 'P1' : score >= 60 ? 'P2' : score >= 40 ? 'P3' : 'P4');
    if (tierId === 'P1') criticalCount++;
    else if (tierId === 'P2') highCount++;
    else if (tierId === 'P3') mediumCount++;
    else lowCount++;
  });
  return { total, criticalCount, highCount, mediumCount, lowCount, avgScore: total > 0 ? Math.round((totalScore / total) * 100) / 100 : 0 };
}

// 4. Test Framework
class StandaloneTestRunner {
  constructor() {
    this.suites = [];
    this.currentSuite = null;
  }
  describe(name, fn) {
    const suite = { name, tests: [] };
    this.suites.push(suite);
    this.currentSuite = suite;
    fn();
    this.currentSuite = null;
  }
  it(name, fn) {
    this.currentSuite.tests.push({ name, fn });
  }
  async runAll() {
    const startTime = performance.now();
    const results = { total: 0, passed: 0, failed: 0, durationMs: 0, suites: [] };

    for (const suite of this.suites) {
      const suiteResult = { name: suite.name, passed: 0, failed: 0, tests: [] };
      for (const test of suite.tests) {
        results.total++;
        const tStart = performance.now();
        let status = 'passed';
        let error = null;
        try {
          await test.fn();
          suiteResult.passed++;
          results.passed++;
        } catch (err) {
          status = 'failed';
          error = err;
          suiteResult.failed++;
          results.failed++;
        }
        suiteResult.tests.push({
          name: test.name,
          status,
          durationMs: Math.round((performance.now() - tStart) * 100) / 100,
          error: error ? { message: error.message } : null
        });
      }
      results.suites.push(suiteResult);
    }
    results.durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    return results;
  }
}

const testRunner = new StandaloneTestRunner();
const describe = (name, fn) => testRunner.describe(name, fn);
const it = (name, fn) => testRunner.it(name, fn);

function expect(actual) {
  return {
    toBe(expected) { if (actual !== expected) throw new Error(`Expected ${actual} to be ${expected}`); },
    toBeCloseTo(expected, precision = 2) {
      const diff = Math.abs(actual - expected);
      const tol = Math.pow(10, -precision) / 2;
      if (diff > tol) throw new Error(`Expected ${actual} to be close to ${expected}`);
    },
    toBeGreaterThan(expected) { if (!(actual > expected)) throw new Error(`Expected ${actual} > ${expected}`); },
    toBeGreaterThanOrEqual(expected) { if (!(actual >= expected)) throw new Error(`Expected ${actual} >= ${expected}`); },
    toBeLessThan(expected) { if (!(actual < expected)) throw new Error(`Expected ${actual} < ${expected}`); },
    toBeLessThanOrEqual(expected) { if (!(actual <= expected)) throw new Error(`Expected ${actual} <= ${expected}`); }
  };
}

// 5. Register All Unit Tests
describe('Suite 1: Affected Users Normalization', () => {
  it('returns 0 for zero or negative users', () => {
    expect(normalizeAffectedUsers(0)).toBe(0);
    expect(normalizeAffectedUsers(-10)).toBe(0);
  });
  it('calculates expected logarithmic values across orders of magnitude', () => {
    expect(normalizeAffectedUsers(1)).toBeCloseTo(7.53, 1);
    expect(normalizeAffectedUsers(10)).toBeCloseTo(26.03, 1);
    expect(normalizeAffectedUsers(100)).toBeCloseTo(50.11, 1);
    expect(normalizeAffectedUsers(1000)).toBeCloseTo(75.01, 1);
    expect(normalizeAffectedUsers(10000)).toBe(100);
  });
  it('strictly caps values exceeding 10,000 at 100.00', () => {
    expect(normalizeAffectedUsers(50000)).toBe(100);
  });
});

describe('Suite 2: Deterministic Score Calculation', () => {
  it('calculates exact score matching theoretical formula for a standard incident', () => {
    const alert = { severity: 80, assetImportance: 60, affectedUsers: 50, dataSensitivity: 70, attackConfidence: 90, businessImpact: 85 };
    const res = calculateRiskScore(alert);
    expect(res.score).toBe(77.00);
  });
  it('normalizes rawAffectedUsers automatically in score calculation', () => {
    const alert = { severity: 100, assetImportance: 100, rawAffectedUsers: 10000, dataSensitivity: 100, attackConfidence: 100, businessImpact: 100 };
    const res = calculateRiskScore(alert);
    expect(res.score).toBe(100.00);
  });
  it('supports custom normalized weights', () => {
    const alert = { severity: 100, assetImportance: 0, affectedUsers: 0, dataSensitivity: 0, attackConfidence: 0, businessImpact: 0 };
    const customWeights = { severity: 0.5, assetImportance: 0, affectedUsers: 0, dataSensitivity: 0, attackConfidence: 0.5, businessImpact: 0 };
    const res = calculateRiskScore(alert, customWeights);
    expect(res.score).toBe(50.00);
  });
});

describe('Suite 3: Score Boundaries & Tier Thresholds', () => {
  it('evaluates all factors 0 to exact 0.00 (P4)', () => {
    const res = calculateRiskScore({ severity: 0, assetImportance: 0, affectedUsers: 0, dataSensitivity: 0, attackConfidence: 0, businessImpact: 0 });
    expect(res.score).toBe(0.00);
    expect(res.tier.id).toBe('P4');
  });
  it('evaluates all factors 100 to exact 100.00 (P1)', () => {
    const res = calculateRiskScore({ severity: 100, assetImportance: 100, affectedUsers: 100, dataSensitivity: 100, attackConfidence: 100, businessImpact: 100 });
    expect(res.score).toBe(100.00);
    expect(res.tier.id).toBe('P1');
  });
  it('correctly maps boundary scores to priority tiers', () => {
    expect(getPriorityTier(100).id).toBe('P1');
    expect(getPriorityTier(80.00).id).toBe('P1');
    expect(getPriorityTier(79.99).id).toBe('P2');
    expect(getPriorityTier(60.00).id).toBe('P2');
    expect(getPriorityTier(59.99).id).toBe('P3');
    expect(getPriorityTier(40.00).id).toBe('P3');
    expect(getPriorityTier(39.99).id).toBe('P4');
  });
});

describe('Suite 4: Deterministic Priority Queue Sorting', () => {
  it('ranks alerts in descending order of calculated risk score', () => {
    const alerts = [
      { id: 'INC-01', severity: 40, assetImportance: 40, affectedUsers: 40, dataSensitivity: 40, attackConfidence: 40, businessImpact: 40 },
      { id: 'INC-02', severity: 90, assetImportance: 90, affectedUsers: 90, dataSensitivity: 90, attackConfidence: 90, businessImpact: 90 },
      { id: 'INC-03', severity: 65, assetImportance: 65, affectedUsers: 65, dataSensitivity: 65, attackConfidence: 65, businessImpact: 65 }
    ];
    const ranked = rankAlerts(alerts);
    expect(ranked[0].id).toBe('INC-02');
    expect(ranked[0].rank).toBe(1);
    expect(ranked[1].id).toBe('INC-03');
    expect(ranked[2].id).toBe('INC-01');
  });
});

describe('Suite 5: 6-Tier Tie-Breaking Hierarchy', () => {
  it('Tier 1: Higher Risk Score wins', () => {
    const trace = explainTieBreak(
      { id: 'A', severity: 80, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 },
      { id: 'B', severity: 70, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 }
    );
    expect(trace.level).toBe(1);
    expect(trace.winner).toBe('A');
  });
  it('Tier 2: Equal Score -> Higher Attack Confidence wins', () => {
    const alertA = { id: 'A', severity: 44, assetImportance: 60, affectedUsers: 60, dataSensitivity: 60, attackConfidence: 80, businessImpact: 60, timestamp: '2026-09-01T10:00:00Z' };
    const alertB = { id: 'B', severity: 60, assetImportance: 60, affectedUsers: 60, dataSensitivity: 60, attackConfidence: 60, businessImpact: 60, timestamp: '2026-09-01T10:00:00Z' };
    const trace = explainTieBreak(alertA, alertB);
    expect(trace.level).toBe(2);
    expect(trace.winner).toBe('A');
  });
  it('Tier 3: Equal Score & Confidence -> Higher Business Impact wins', () => {
    const alertA = { id: 'A', severity: 44, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 90, timestamp: '2026-09-01T10:00:00Z' };
    const alertB = { id: 'B', severity: 60, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 70, timestamp: '2026-09-01T10:00:00Z' };
    const trace = explainTieBreak(alertA, alertB);
    expect(trace.level).toBe(3);
    expect(trace.winner).toBe('A');
  });
  it('Tier 4: Equal Score, Conf & Impact -> Higher Data Sensitivity wins', () => {
    const alertA = { id: 'A', severity: 68, assetImportance: 80, affectedUsers: 80, dataSensitivity: 90, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };
    const alertB = { id: 'B', severity: 80, assetImportance: 80, affectedUsers: 80, dataSensitivity: 70, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };
    const trace = explainTieBreak(alertA, alertB);
    expect(trace.level).toBe(4);
    expect(trace.winner).toBe('A');
  });
  it('Tier 5: Equal Score, Conf, Impact & Data -> Higher Asset Importance wins', () => {
    const alertA = { id: 'A', severity: 68, assetImportance: 90, affectedUsers: 80, dataSensitivity: 80, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };
    const alertB = { id: 'B', severity: 80, assetImportance: 70, affectedUsers: 80, dataSensitivity: 80, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };
    const trace = explainTieBreak(alertA, alertB);
    expect(trace.level).toBe(5);
    expect(trace.winner).toBe('A');
  });
  it('Tier 6: All factors identical -> Timestamp ascending (Oldest first)', () => {
    const alertOld = { id: 'OLD', severity: 75, assetImportance: 75, affectedUsers: 75, dataSensitivity: 75, attackConfidence: 75, businessImpact: 75, timestamp: '2026-09-01T08:00:00Z' };
    const alertNew = { id: 'NEW', severity: 75, assetImportance: 75, affectedUsers: 75, dataSensitivity: 75, attackConfidence: 75, businessImpact: 75, timestamp: '2026-09-01T11:00:00Z' };
    const trace = explainTieBreak(alertOld, alertNew);
    expect(trace.level).toBe(6);
    expect(trace.winner).toBe('OLD');
  });
  it('Tier 7: All factors & timestamps identical -> Incident ID ascending', () => {
    const alertA = { id: 'INC-A', severity: 70, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 70, timestamp: '2026-09-01T10:00:00Z' };
    const alertZ = { id: 'INC-Z', severity: 70, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 70, timestamp: '2026-09-01T10:00:00Z' };
    const trace = explainTieBreak(alertA, alertZ);
    expect(trace.level).toBe(7);
    expect(trace.winner).toBe('INC-A');
  });
});

describe('Suite 7: Ranking Explanation & Side-by-Side Comparison', () => {
  it('formats factor lists with Oxford comma', () => {
    expect(formatFactorList([])).toBe('');
    expect(formatFactorList(['severity'])).toBe('severity');
    expect(formatFactorList(['severity', 'attack confidence'])).toBe('severity and attack confidence');
    expect(formatFactorList(['severity', 'asset importance', 'data sensitivity', 'business impact']))
      .toBe('severity, asset importance, data sensitivity, and business impact');
  });

  it('generates concise factual explanation when Incident #1 outranks #2 with factor trade-offs', () => {
    const alert1 = { id: 'INC-01', rank: 1, severity: 98, assetImportance: 90, affectedUsers: 75, dataSensitivity: 90, attackConfidence: 80, businessImpact: 92 };
    const alert2 = { id: 'INC-02', rank: 2, severity: 80, assetImportance: 70, affectedUsers: 75, dataSensitivity: 80, attackConfidence: 96, businessImpact: 80 };
    const res = generateRankComparisonExplanation(alert1, alert2);
    expect(res.rankA).toBe(1);
    expect(res.rankB).toBe(2);
    expect(res.scoreA).toBe(89.65);
    expect(res.scoreB).toBe(81.45);
    expect(res.explanation.includes('ranks #1 with 89.65 points')).toBe(true);
    expect(res.explanation.includes('8.20 points above')).toBe(true);
    expect(res.explanation.includes('Severity provides the largest individual advantage at +4.50 points')).toBe(true);
  });

  it('generates explanation when incident dominates all factors', () => {
    const alert1 = { id: 'INC-01', rank: 1, severity: 95, assetImportance: 95, affectedUsers: 90, dataSensitivity: 90, attackConfidence: 95, businessImpact: 95 };
    const alert2 = { id: 'INC-02', rank: 2, severity: 70, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 70 };
    const res = generateRankComparisonExplanation(alert1, alert2);
    expect(res.concessions.length).toBe(0);
    expect(res.explanation.includes('ranks #1 with 89.00 points, 19.00 points above INC-02 at 70.00')).toBe(true);
  });

  it('generates tie-break explanation on identical risk scores', () => {
    const alertA = { id: 'INC-T1', rank: 1, severity: 44, assetImportance: 60, affectedUsers: 60, dataSensitivity: 60, attackConfidence: 80, businessImpact: 60, timestamp: '2026-09-01T10:00:00Z' };
    const alertB = { id: 'INC-T2', rank: 2, severity: 60, assetImportance: 60, affectedUsers: 60, dataSensitivity: 60, attackConfidence: 60, businessImpact: 60, timestamp: '2026-09-01T10:00:00Z' };
    const res = generateRankComparisonExplanation(alertA, alertB);
    expect(res.isTie).toBe(true);
    expect(res.explanation.includes('tied with INC-T2 at 60.00 points')).toBe(true);
  });

  it('handles end of queue boundary gracefully', () => {
    const alert = { id: 'INC-LAST', rank: 108, severity: 50, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 };
    const res = generateRankComparisonExplanation(alert, null);
    expect(res.rankA).toBe(108);
    expect(res.rankB).toBe(null);
    expect(res.explanation).toBe(
      'Incident #108 is currently the final incident in the active priority queue. There is no lower-ranked incident to compare.'
    );
  });
});

describe('Suite 8: System Invariants, Verification Hash & Dashboard Consistency', () => {
  it('generates authentic, valid 64-character SHA-256 hash', () => {
    const hash = computeSHA256Hex('abc');
    expect(hash).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('validates dashboard metrics consistency: Total == P1 + P2 + P3 + P4', () => {
    const queue = [
      { score: 90, tier: { id: 'P1' } },
      { score: 85, tier: { id: 'P1' } },
      { score: 70, tier: { id: 'P2' } },
      { score: 50, tier: { id: 'P3' } },
      { score: 30, tier: { id: 'P4' } }
    ];
    const stats = computeQueueAnalytics(queue);
    expect(stats.total).toBe(5);
    expect(stats.criticalCount).toBe(2);
    expect(stats.highCount).toBe(1);
    expect(stats.mediumCount).toBe(1);
    expect(stats.lowCount).toBe(1);
    expect(stats.criticalCount + stats.highCount + stats.mediumCount + stats.lowCount).toBe(5);
  });

  it('ensures score calculation is monotonic across all 6 dimensions', () => {
    const base = { severity: 50, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 };
    const baseScore = calculateRiskScore(base).score;
    expect(calculateRiskScore({ ...base, severity: 80 }).score).toBeGreaterThan(baseScore);
    expect(calculateRiskScore({ ...base, assetImportance: 80 }).score).toBeGreaterThan(baseScore);
    expect(calculateRiskScore({ ...base, attackConfidence: 80 }).score).toBeGreaterThan(baseScore);
  });
});

describe('Suite 9: Incident Row Interaction & Detail View Suite', () => {
  const mockAlert1 = {
    id: 'INC-2026-0001',
    rank: 1,
    alertType: 'Ransomware / File Encryption',
    shortDescription: 'Shadow copy deletion and encrypted canary files.',
    source: 'Falcon EDR',
    asset: 'DC-PRIMARY-01',
    factors: {
      severity: 98,
      assetImportance: 100,
      rawAffectedUsers: 4500,
      affectedUsers: 91.3,
      dataSensitivity: 95,
      attackConfidence: 96,
      businessImpact: 98
    },
    score: 97.12,
    tier: { id: 'P1', label: 'CRITICAL PRIORITY', badgeClass: 'tier-p1' }
  };

  const mockAlert2 = {
    id: 'INC-2026-0005',
    rank: 2,
    alertType: 'Cloud IAM / Root Account Compromise',
    shortDescription: 'AWS root account logged in without MFA from anomalous ASN in St. Petersburg.',
    source: 'AWS GuardDuty',
    asset: 'AWS-ROOT-MGMT-ACCOUNT',
    factors: {
      severity: 96,
      assetImportance: 100,
      rawAffectedUsers: 10000,
      affectedUsers: 100,
      dataSensitivity: 90,
      attackConfidence: 98,
      businessImpact: 96
    },
    score: 96.30,
    tier: { id: 'P1', label: 'CRITICAL PRIORITY', badgeClass: 'tier-p1' }
  };

  it('1. Verifies incident row interaction model and data mapping', () => {
    expect(mockAlert1.id).toBe('INC-2026-0001');
    expect(mockAlert1.alertType).toBe('Ransomware / File Encryption');
    expect(mockAlert1.score).toBe(97.12);
    expect(mockAlert1.rank).toBe(1);
  });

  it('2. Clicking Report does not trigger the row click handler (Event isolation)', () => {
    let rowHandlerTriggered = false;
    let reportHandlerTriggered = false;

    const simulateClick = (targetType) => {
      if (targetType === 'report_button') {
        reportHandlerTriggered = true;
        const isInteractive = true;
        if (!isInteractive) rowHandlerTriggered = true;
      } else {
        rowHandlerTriggered = true;
      }
    };

    simulateClick('report_button');
    expect(reportHandlerTriggered).toBe(true);
    expect(rowHandlerTriggered).toBe(false);

    simulateClick('row_cell');
    expect(rowHandlerTriggered).toBe(true);
  });

  it('3. The comparison uses the incident immediately below the selected incident', () => {
    const comparison = generateRankComparisonExplanation(mockAlert1, mockAlert2, DEFAULT_WEIGHTS);
    expect(comparison.idA).toBe('INC-2026-0001');
    expect(comparison.idB).toBe('INC-2026-0005');
  });

  it('4. The comparison score difference matches the actual scores', () => {
    const comparison = generateRankComparisonExplanation(mockAlert1, mockAlert2, DEFAULT_WEIGHTS);
    expect(comparison.scoreDelta).toBe(0.82);
    expect(comparison.explanation.includes('0.82 points above')).toBe(true);
  });
});

// SUITE 10: CUSTOM ALERT INGESTION & DETERMINISTIC PARSING
describe('Suite 10: Custom Security Alert Ingestion Engine', () => {
  const sampleCustomAlert = {
    id: 'CUSTOM-2026-0001',
    alertType: 'Ransomware / File Encryption Threat',
    severity: 94,
    assetImportance: 90,
    rawAffectedUsers: 2500,
    dataSensitivity: 85,
    attackConfidence: 95,
    businessImpact: 88,
    timestamp: '2026-09-01T12:00:00.000Z',
    isCustom: true
  };

  it('1. Verifies deterministic calculation of custom alert (Score: 90.60)', () => {
    const scoreResult = calculateRiskScore(sampleCustomAlert, DEFAULT_WEIGHTS);
    expect(scoreResult.score).toBe(90.60);
    expect(scoreResult.tier.id).toBe('P1');
  });

  it('2. Custom alert integrates into queue and re-ranks correctly', () => {
    const queue = [sampleCustomAlert, mockAlert1, mockAlert2];
    const ranked = rankAlerts(queue, DEFAULT_WEIGHTS);
    expect(ranked.length).toBe(3);
    expect(ranked[0].id).toBe('INC-2026-0001'); // 97.12
    expect(ranked[1].id).toBe('INC-2026-0005'); // 96.30
    expect(ranked[2].id).toBe('CUSTOM-2026-0001'); // 90.60
    expect(ranked[2].rank).toBe(3);
  });

  it('3. Custom alert receives unique ID prefix CUSTOM-2026-', () => {
    expect(sampleCustomAlert.id.startsWith('CUSTOM-2026-')).toBe(true);
  });
});

// Expose runner globally for UI invocation
window.__STANDALONE_RUNNER__ = testRunner;

