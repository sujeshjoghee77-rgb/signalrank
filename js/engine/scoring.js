/**
 * SignalRank - Deterministic Scoring Engine
 * 
 * Mathematical Risk Score Calculation & Factor Normalization.
 * 
 * Formula:
 *   Risk Score = 0.25 * Severity +
 *                0.15 * Asset Importance +
 *                0.05 * Normalized Affected Users +
 *                0.15 * Data Sensitivity +
 *                0.20 * Attack Confidence +
 *                0.20 * Business Impact
 * 
 * Total output is strictly bounded within [0, 100].
 * NO LLMs are used for numerical computation.
 */

import { DEFAULT_WEIGHTS, FACTOR_DEFINITIONS, PRIORITY_TIERS, NORMALIZATION_CONFIG } from './types.js';

/**
 * Normalizes raw affected user count to a [0, 100] factor score using a capped logarithmic curve.
 * 
 * Formula: U(N) = min(100, (ln(1 + N) / ln(1 + N_max)) * 100)
 * 
 * @param {number} rawCount - The raw count of affected users/identities
 * @param {number} [maxCap=10000] - Cap where factor reaches 100
 * @returns {number} Normalized score between 0.00 and 100.00
 */
export function normalizeAffectedUsers(rawCount, maxCap = NORMALIZATION_CONFIG.maxUserCap) {
  if (rawCount === undefined || rawCount === null || isNaN(rawCount)) {
    return 0;
  }
  const count = Number(rawCount);
  if (count <= 0) {
    return 0;
  }
  if (count >= maxCap) {
    return 100;
  }
  const normalized = (Math.log(1 + count) / Math.log(1 + maxCap)) * 100;
  return Math.min(100, Math.max(0, Math.round(normalized * 100) / 100));
}

/**
 * Clamps any numeric factor safely to the [0, 100] range.
 * 
 * @param {number|any} value - The input value
 * @param {number} [min=0] - Minimum bound
 * @param {number} [max=100] - Maximum bound
 * @returns {number} Clamped float
 */
export function clampFactor(value, min = 0, max = 100) {
  if (value === undefined || value === null || isNaN(value)) {
    return min;
  }
  const num = Number(value);
  return Math.min(max, Math.max(min, num));
}

/**
 * Normalizes weight configuration so that sum(weights) === 1.0.
 * If total weight is 0 or invalid, falls back to DEFAULT_WEIGHTS.
 * 
 * @param {Object} [weights] - Custom weight overrides
 * @returns {Object} Normalized weights summing to 1.0
 */
export function normalizeWeights(weights = {}) {
  const merged = { ...DEFAULT_WEIGHTS, ...weights };
  const keys = Object.keys(DEFAULT_WEIGHTS);
  
  let total = 0;
  for (const k of keys) {
    const w = typeof merged[k] === 'number' && !isNaN(merged[k]) && merged[k] >= 0 ? merged[k] : 0;
    total += w;
  }

  if (total <= 0) {
    return { ...DEFAULT_WEIGHTS };
  }

  const normalized = {};
  for (const k of keys) {
    const val = typeof merged[k] === 'number' && merged[k] >= 0 ? merged[k] : 0;
    normalized[k] = val / total;
  }
  return normalized;
}

/**
 * Extracts and clamps the six normalized factors from an alert object.
 * Automatically converts rawAffectedUsers if affectedUsers is not already normalized.
 * 
 * @param {Object} alert - The security incident alert
 * @returns {Object} Clamped factors { severity, assetImportance, affectedUsers, dataSensitivity, attackConfidence, businessImpact }
 */
export function extractFactors(alert) {
  if (!alert || typeof alert !== 'object') {
    return {
      severity: 0,
      assetImportance: 0,
      affectedUsers: 0,
      dataSensitivity: 0,
      attackConfidence: 0,
      businessImpact: 0,
      rawAffectedUsers: 0
    };
  }

  // Handle affected users: normalize if raw count is provided or if affectedUsers > 100
  let normUsers = 0;
  let rawUsers = 0;

  if (alert.rawAffectedUsers !== undefined && alert.rawAffectedUsers !== null) {
    rawUsers = Math.max(0, Number(alert.rawAffectedUsers) || 0);
    normUsers = normalizeAffectedUsers(rawUsers);
  } else if (alert.affectedUsers !== undefined && alert.affectedUsers !== null) {
    const val = Number(alert.affectedUsers) || 0;
    if (val > 100) {
      // It was passed as a raw count
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

/**
 * Determines the Priority Tier (P1, P2, P3, P4) based on risk score.
 * 
 * @param {number} score - The computed risk score [0, 100]
 * @returns {Object} Priority tier metadata
 */
export function getPriorityTier(score) {
  const s = clampFactor(score);
  if (s >= PRIORITY_TIERS.P1.minScore) {
    return PRIORITY_TIERS.P1;
  }
  if (s >= PRIORITY_TIERS.P2.minScore) {
    return PRIORITY_TIERS.P2;
  }
  if (s >= PRIORITY_TIERS.P3.minScore) {
    return PRIORITY_TIERS.P3;
  }
  return PRIORITY_TIERS.P4;
}

/**
 * Calculates the exact deterministic risk score for a security alert.
 * 
 * @param {Object} alert - Security alert object
 * @param {Object} [customWeights] - Optional custom weights
 * @returns {Object} Scoring result with score, contributions, tier, and factors
 */
export function calculateRiskScore(alert, customWeights = DEFAULT_WEIGHTS) {
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

  const rawScore = 
    contributions.severity +
    contributions.assetImportance +
    contributions.affectedUsers +
    contributions.dataSensitivity +
    contributions.attackConfidence +
    contributions.businessImpact;

  // Clamp strictly between 0 and 100
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
    },
    exactContributions: contributions
  };
}

/**
 * Generates an in-depth mathematical explainability payload for SOC analysts.
 * 
 * @param {Object} alert - The incident alert
 * @param {Object} [customWeights] - Current weights used
 * @returns {Object} Explainability report
 */
export function generateScoreExplanation(alert, customWeights = DEFAULT_WEIGHTS) {
  const calculation = calculateRiskScore(alert, customWeights);
  const { factors, weights, contributions, score, tier } = calculation;

  // Find top contributing factor
  let maxContributionKey = 'severity';
  let maxContributionVal = -1;

  for (const [key, val] of Object.entries(contributions)) {
    if (val > maxContributionVal) {
      maxContributionVal = val;
      maxContributionKey = key;
    }
  }

  const factorBreakdowns = Object.keys(DEFAULT_WEIGHTS).map(key => {
    const def = FACTOR_DEFINITIONS[key];
    const factorVal = factors[key];
    const weight = weights[key];
    const contrib = contributions[key];
    const percentOfTotal = score > 0 ? Math.round((contrib / score) * 1000) / 10 : 0;

    return {
      key,
      label: def.label,
      shortLabel: def.shortLabel,
      color: def.color,
      factorValue: factorVal,
      weight: Math.round(weight * 100) / 100,
      weightPercent: Math.round(weight * 100),
      contribution: contrib,
      percentOfTotal,
      rawDisplay: key === 'affectedUsers' 
        ? `${factors.rawAffectedUsers.toLocaleString()} users (${factorVal.toFixed(1)} pts normalized)` 
        : `${factorVal.toFixed(1)} / 100`
    };
  });

  const formulaSteps = [
    `Severity: ${factors.severity.toFixed(1)} × ${(weights.severity).toFixed(2)} = ${contributions.severity.toFixed(2)} pts`,
    `Asset Importance: ${factors.assetImportance.toFixed(1)} × ${(weights.assetImportance).toFixed(2)} = ${contributions.assetImportance.toFixed(2)} pts`,
    `Affected Users: ${factors.affectedUsers.toFixed(1)} × ${(weights.affectedUsers).toFixed(2)} = ${contributions.affectedUsers.toFixed(2)} pts (Raw: ${factors.rawAffectedUsers.toLocaleString()})`,
    `Data Sensitivity: ${factors.dataSensitivity.toFixed(1)} × ${(weights.dataSensitivity).toFixed(2)} = ${contributions.dataSensitivity.toFixed(2)} pts`,
    `Attack Confidence: ${factors.attackConfidence.toFixed(1)} × ${(weights.attackConfidence).toFixed(2)} = ${contributions.attackConfidence.toFixed(2)} pts`,
    `Business Impact: ${factors.businessImpact.toFixed(1)} × ${(weights.businessImpact).toFixed(2)} = ${contributions.businessImpact.toFixed(2)} pts`
  ];

  const formulaString = `Risk Score = (${factors.severity.toFixed(1)} × ${weights.severity.toFixed(2)}) + ` +
    `(${factors.assetImportance.toFixed(1)} × ${weights.assetImportance.toFixed(2)}) + ` +
    `(${factors.affectedUsers.toFixed(1)} × ${weights.affectedUsers.toFixed(2)}) + ` +
    `(${factors.dataSensitivity.toFixed(1)} × ${weights.dataSensitivity.toFixed(2)}) + ` +
    `(${factors.attackConfidence.toFixed(1)} × ${weights.attackConfidence.toFixed(2)}) + ` +
    `(${factors.businessImpact.toFixed(1)} × ${weights.businessImpact.toFixed(2)}) = ${score.toFixed(2)}`;

  return {
    incidentId: alert.id || 'N/A',
    score,
    tier,
    factors,
    weights,
    contributions,
    factorBreakdowns,
    formulaSteps,
    formulaString,
    topDriver: {
      key: maxContributionKey,
      label: FACTOR_DEFINITIONS[maxContributionKey].label,
      contribution: maxContributionVal,
      description: FACTOR_DEFINITIONS[maxContributionKey].description
    }
  };
}
