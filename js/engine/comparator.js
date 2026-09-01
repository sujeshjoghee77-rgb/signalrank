/**
 * SignalRank - Deterministic Incident Comparator & Priority Queue Sorter
 * 
 * Strict 6-level tie-breaking hierarchy:
 * 1. Risk score descending (highest risk first)
 * 2. Attack confidence descending (higher certainty first)
 * 3. Business impact descending (higher damage potential first)
 * 4. Data sensitivity descending (higher data classification first)
 * 5. Asset importance descending (more critical infrastructure first)
 * 6. Timestamp ascending (older alert first -> FIFO for identical risk)
 * 7. Incident ID ascending (strictly deterministic total order)
 */

import { calculateRiskScore, extractFactors } from './scoring.js';
import { DEFAULT_WEIGHTS, FACTOR_DEFINITIONS } from './types.js';

// Tolerance for floating point equality in risk score comparisons
const EPSILON = 1e-6;

/**
 * Compares two alerts deterministically based on the 6-level priority queue rules.
 * 
 * @param {Object} alertA - First alert (can be raw alert or scored alert)
 * @param {Object} alertB - Second alert (can be raw alert or scored alert)
 * @param {Object} [customWeights=DEFAULT_WEIGHTS] - Optional custom weights
 * @returns {number} Negative if A before B, Positive if B before A, 0 if strictly equal
 */
export function compareIncidents(alertA, alertB, customWeights = DEFAULT_WEIGHTS) {
  // Ensure scores are calculated
  const scoreA = alertA._calculatedScore ?? calculateRiskScore(alertA, customWeights).score;
  const scoreB = alertB._calculatedScore ?? calculateRiskScore(alertB, customWeights).score;

  // 1. Risk score descending
  if (Math.abs(scoreA - scoreB) > EPSILON) {
    return scoreB - scoreA;
  }

  const factorsA = alertA._factors ?? extractFactors(alertA);
  const factorsB = alertB._factors ?? extractFactors(alertB);

  // 2. Attack confidence descending
  if (Math.abs(factorsA.attackConfidence - factorsB.attackConfidence) > EPSILON) {
    return factorsB.attackConfidence - factorsA.attackConfidence;
  }

  // 3. Business impact descending
  if (Math.abs(factorsA.businessImpact - factorsB.businessImpact) > EPSILON) {
    return factorsB.businessImpact - factorsA.businessImpact;
  }

  // 4. Data sensitivity descending
  if (Math.abs(factorsA.dataSensitivity - factorsB.dataSensitivity) > EPSILON) {
    return factorsB.dataSensitivity - factorsA.dataSensitivity;
  }

  // 5. Asset importance descending
  if (Math.abs(factorsA.assetImportance - factorsB.assetImportance) > EPSILON) {
    return factorsB.assetImportance - factorsA.assetImportance;
  }

  // 6. Timestamp ascending (older alert investigated first)
  const timeA = alertA.timestamp ? new Date(alertA.timestamp).getTime() : 0;
  const timeB = alertB.timestamp ? new Date(alertB.timestamp).getTime() : 0;

  if (timeA !== timeB) {
    return timeA - timeB;
  }

  // 7. Incident ID ascending (deterministic fallback)
  const idA = String(alertA.id || '');
  const idB = String(alertB.id || '');
  return idA.localeCompare(idB);
}

/**
 * Ranks an array of alerts into a deterministic priority queue.
 * Attaches calculated score, factors, tier, and rank position.
 * 
 * @param {Array<Object>} alerts - Array of raw or scored alerts
 * @param {Object} [customWeights=DEFAULT_WEIGHTS] - Optional custom weights
 * @returns {Array<Object>} Deterministically ranked alert array with metadata
 */
export function rankAlerts(alerts, customWeights = DEFAULT_WEIGHTS) {
  if (!Array.isArray(alerts)) {
    return [];
  }

  // Precompute scores and factors for performance and consistent sorting
  const scoredAlerts = alerts.map((alert, index) => {
    const calculation = calculateRiskScore(alert, customWeights);
    return {
      ...alert,
      _calculatedScore: calculation.score,
      _exactScore: calculation.exactScore,
      _factors: calculation.factors,
      _contributions: calculation.contributions,
      _tier: calculation.tier,
      _originalIndex: index
    };
  });

  // Sort deterministically
  scoredAlerts.sort((a, b) => compareIncidents(a, b, customWeights));

  // Assign 1-indexed rank and delta rank metadata
  return scoredAlerts.map((alert, rankIndex) => ({
    ...alert,
    rank: rankIndex + 1,
    score: alert._calculatedScore,
    tier: alert._tier,
    factors: alert._factors,
    contributions: alert._contributions
  }));
}

/**
 * Returns a human-readable and technical trace explaining why Alert A was ranked ahead of Alert B.
 * 
 * @param {Object} alertA - Higher-ranked alert
 * @param {Object} alertB - Lower-ranked alert
 * @param {Object} [customWeights=DEFAULT_WEIGHTS] - Weights
 * @returns {Object} Detailed tie-break trace
 */
export function explainTieBreak(alertA, alertB, customWeights = DEFAULT_WEIGHTS) {
  const calcA = calculateRiskScore(alertA, customWeights);
  const calcB = calculateRiskScore(alertB, customWeights);

  if (Math.abs(calcA.score - calcB.score) > EPSILON) {
    return {
      decidingFactor: 'Risk Score',
      level: 1,
      rule: 'Risk Score (Descending)',
      winner: calcA.score > calcB.score ? alertA.id : alertB.id,
      explanation: `${alertA.id} (${calcA.score.toFixed(2)} pts) has higher risk score than ${alertB.id} (${calcB.score.toFixed(2)} pts).`
    };
  }

  if (Math.abs(calcA.factors.attackConfidence - calcB.factors.attackConfidence) > EPSILON) {
    return {
      decidingFactor: 'Attack Confidence',
      level: 2,
      rule: 'Attack Confidence (Descending)',
      winner: calcA.factors.attackConfidence > calcB.factors.attackConfidence ? alertA.id : alertB.id,
      explanation: `Equal risk score (${calcA.score.toFixed(2)} pts). ${alertA.id} has higher Attack Confidence (${calcA.factors.attackConfidence.toFixed(1)} vs ${calcB.factors.attackConfidence.toFixed(1)}).`
    };
  }

  if (Math.abs(calcA.factors.businessImpact - calcB.factors.businessImpact) > EPSILON) {
    return {
      decidingFactor: 'Business Impact',
      level: 3,
      rule: 'Business Impact (Descending)',
      winner: calcA.factors.businessImpact > calcB.factors.businessImpact ? alertA.id : alertB.id,
      explanation: `Equal risk & confidence. ${alertA.id} has higher Business Impact (${calcA.factors.businessImpact.toFixed(1)} vs ${calcB.factors.businessImpact.toFixed(1)}).`
    };
  }

  if (Math.abs(calcA.factors.dataSensitivity - calcB.factors.dataSensitivity) > EPSILON) {
    return {
      decidingFactor: 'Data Sensitivity',
      level: 4,
      rule: 'Data Sensitivity (Descending)',
      winner: calcA.factors.dataSensitivity > calcB.factors.dataSensitivity ? alertA.id : alertB.id,
      explanation: `Equal risk, confidence & impact. ${alertA.id} has higher Data Sensitivity (${calcA.factors.dataSensitivity.toFixed(1)} vs ${calcB.factors.dataSensitivity.toFixed(1)}).`
    };
  }

  if (Math.abs(calcA.factors.assetImportance - calcB.factors.assetImportance) > EPSILON) {
    return {
      decidingFactor: 'Asset Importance',
      level: 5,
      rule: 'Asset Importance (Descending)',
      winner: calcA.factors.assetImportance > calcB.factors.assetImportance ? alertA.id : alertB.id,
      explanation: `Equal risk, confidence, impact & data sensitivity. ${alertA.id} has higher Asset Importance (${calcA.factors.assetImportance.toFixed(1)} vs ${calcB.factors.assetImportance.toFixed(1)}).`
    };
  }

  const timeA = alertA.timestamp ? new Date(alertA.timestamp).getTime() : 0;
  const timeB = alertB.timestamp ? new Date(alertB.timestamp).getTime() : 0;

  if (timeA !== timeB) {
    const isAEarlier = timeA < timeB;
    return {
      decidingFactor: 'Timestamp (FIFO)',
      level: 6,
      rule: 'Timestamp (Ascending / Oldest First)',
      winner: isAEarlier ? alertA.id : alertB.id,
      explanation: `All 5 risk factors identical. ${isAEarlier ? alertA.id : alertB.id} occurred earlier (${new Date(Math.min(timeA, timeB)).toISOString()}) and receives FIFO priority.`
    };
  }

  return {
    decidingFactor: 'Incident ID',
    level: 7,
    rule: 'Incident ID (Ascending)',
    winner: alertA.id < alertB.id ? alertA.id : alertB.id,
    explanation: `All factors and timestamps identical. Resolved deterministically by Incident ID (${alertA.id < alertB.id ? alertA.id : alertB.id}).`
  };
}

/**
 * Formats an array of factor names into a natural-language list with Oxford comma.
 * E.g., ['severity', 'asset importance'] -> 'severity and asset importance'
 * E.g., ['severity', 'asset importance', 'data sensitivity', 'business impact'] 
 *    -> 'severity, asset importance, data sensitivity, and business impact'
 * 
 * @param {Array<string>} names - Array of factor names
 * @returns {string} Formatted natural-language string
 */
export function formatFactorList(names) {
  if (!names || names.length === 0) return '';
  if (names.length === 1) return names[0];
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(', ')}, and ${names[names.length - 1]}`;
}

/**
 * Deterministically explains why Incident A outranks Incident B in the sorted queue.
 * Strictly uses calculated mathematical values without any LLM or invented facts.
 * 
 * @param {Object} alertA - Selected higher-ranked incident
 * @param {Object} [alertB] - Next lower-ranked incident (optional if at end of queue)
 * @param {Object} [customWeights=DEFAULT_WEIGHTS] - Active scoring weights
 * @returns {Object} Comparison result and concise explanation
 */
export function generateRankComparisonExplanation(alertA, alertB, customWeights = DEFAULT_WEIGHTS) {
  if (!alertA) {
    return {
      explanation: 'No incident selected for comparison.',
      gains: [],
      concessions: [],
      factorDeltas: []
    };
  }

  const calcA = calculateRiskScore(alertA, customWeights);
  const rankA = alertA.rank || 1;

  if (!alertB) {
    return {
      rankA,
      rankB: null,
      idA: alertA.id,
      idB: null,
      scoreA: calcA.score,
      scoreB: null,
      calcA,
      calcB: null,
      explanation: `Incident #${rankA} is currently the final incident in the active priority queue. There is no lower-ranked incident to compare.`,
      gains: [],
      concessions: [],
      factorDeltas: []
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
    const def = FACTOR_DEFINITIONS[k];
    const label = def ? def.label.toLowerCase() : k;
    const properLabel = def ? def.label : k;
    const contribA = calcA.contributions[k];
    const contribB = calcB.contributions[k];
    const delta = contribA - contribB;

    const item = {
      key: k,
      label,
      properLabel,
      weight: calcA.weights[k],
      weightPercent: Math.round(calcA.weights[k] * 100),
      valA: calcA.factors[k],
      valB: calcB.factors[k],
      contribA,
      contribB,
      delta: Math.round(delta * 100) / 100
    };

    factorDeltas.push(item);

    if (delta > 0.001) {
      gains.push({ ...item, diff: delta });
    } else if (delta < -0.001) {
      concessions.push({ ...item, diff: -delta });
    } else {
      ties.push(item);
    }
  });

  let explanation = '';
  let isTie = false;
  let tieTrace = null;

  // Find largest positive advantage and largest negative disadvantage
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

  return {
    rankA,
    rankB,
    idA: alertA.id,
    idB: alertB.id,
    scoreA: calcA.score,
    scoreB: calcB.score,
    scoreDelta,
    calcA,
    calcB,
    explanation,
    gains,
    concessions,
    ties,
    factorDeltas,
    largestAdvantage,
    largestDisadvantage,
    isTie,
    tieTrace
  };
}

