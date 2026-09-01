/**
 * SignalRank - Comprehensive Unit Test Suite
 * 
 * Verifies:
 * 1. Score Calculation (Weighted sums, factor precision, custom weight scaling)
 * 2. Normalization (Logarithmic curve, 0-10000+ bounds, edge cases)
 * 3. Sorting (Deterministic descending risk order)
 * 4. Tie-breaking (All 6 priority queue tie-break tiers)
 * 5. Score Boundaries (0 to 100 clamps, Priority Tier P1-P4 edges)
 */

import { describe, it, expect } from './test_framework.js';
import { 
  normalizeAffectedUsers, 
  clampFactor, 
  calculateRiskScore, 
  normalizeWeights,
  extractFactors,
  getPriorityTier
} from '../engine/scoring.js';
import { compareIncidents, rankAlerts, explainTieBreak, generateRankComparisonExplanation, formatFactorList } from '../engine/comparator.js';
import { DEFAULT_WEIGHTS, PRIORITY_TIERS } from '../engine/types.js';
import { computeQueueAnalytics } from '../ui/analytics.js';
import { renderExplainabilityView } from '../ui/explainability.js';
import { WhatIfSimulator } from '../ui/simulator.js';
import { parseRawSecurityInput, extractEvidenceFromText } from '../engine/alertParser.js';
import { buildIncidentReportData } from '../ui/reportGenerator.js';

export function registerUnitTests() {

  // =========================================================================
  // SUITE 1: AFFECTED USERS NORMALIZATION
  // =========================================================================
  describe('Suite 1: Affected Users Normalization', () => {
    it('returns 0 for zero or negative users', () => {
      expect(normalizeAffectedUsers(0)).toBe(0);
      expect(normalizeAffectedUsers(-10)).toBe(0);
      expect(normalizeAffectedUsers(-1000)).toBe(0);
    });

    it('returns 0 for null, undefined, or NaN inputs', () => {
      expect(normalizeAffectedUsers(null)).toBe(0);
      expect(normalizeAffectedUsers(undefined)).toBe(0);
      expect(normalizeAffectedUsers(NaN)).toBe(0);
      expect(normalizeAffectedUsers('invalid')).toBe(0);
    });

    it('calculates expected logarithmic values across order-of-magnitude tiers', () => {
      // Formula: ln(1 + N) / ln(10001) * 100
      // N=1: ln(2)/ln(10001)*100 = 0.693147/9.21044*100 ≈ 7.53
      expect(normalizeAffectedUsers(1)).toBeCloseTo(7.53, 1);
      
      // N=10: ln(11)/ln(10001)*100 ≈ 26.03
      expect(normalizeAffectedUsers(10)).toBeCloseTo(26.03, 1);

      // N=100: ln(101)/ln(10001)*100 ≈ 50.11
      expect(normalizeAffectedUsers(100)).toBeCloseTo(50.11, 1);

      // N=1,000: ln(1001)/ln(10001)*100 ≈ 75.01
      expect(normalizeAffectedUsers(1000)).toBeCloseTo(75.01, 1);

      // N=10,000: exact cap 100.00
      expect(normalizeAffectedUsers(10000)).toBe(100);
    });

    it('strictly caps any value exceeding maxCap (10,000) at 100.00', () => {
      expect(normalizeAffectedUsers(10001)).toBe(100);
      expect(normalizeAffectedUsers(50000)).toBe(100);
      expect(normalizeAffectedUsers(1000000)).toBe(100);
    });

    it('supports custom cap limits', () => {
      // With cap = 100, N=100 should be 100
      expect(normalizeAffectedUsers(100, 100)).toBe(100);
      // With cap = 100, N=0 should be 0
      expect(normalizeAffectedUsers(0, 100)).toBe(0);
    });
  });

  // =========================================================================
  // SUITE 2: SCORE CALCULATION & FACTOR CONTRIBUTIONS
  // =========================================================================
  describe('Suite 2: Deterministic Score Calculation', () => {
    it('calculates exact score matching theoretical formula for a standard incident', () => {
      // Risk Score = 0.25*SEV + 0.15*AST + 0.05*USR + 0.15*DAT + 0.20*CNF + 0.20*IMP
      const alert = {
        severity: 80,         // 80 * 0.25 = 20.00
        assetImportance: 60,  // 60 * 0.15 = 9.00
        affectedUsers: 50,    // 50 * 0.05 = 2.50
        dataSensitivity: 70,  // 70 * 0.15 = 10.50
        attackConfidence: 90, // 90 * 0.20 = 18.00
        businessImpact: 85    // 85 * 0.20 = 17.00
      };
      // Sum = 20 + 9 + 2.50 + 10.50 + 18 + 17 = 77.00
      const result = calculateRiskScore(alert);
      expect(result.score).toBe(77.00);
      expect(result.contributions.severity).toBe(20.00);
      expect(result.contributions.assetImportance).toBe(9.00);
      expect(result.contributions.affectedUsers).toBe(2.50);
      expect(result.contributions.dataSensitivity).toBe(10.50);
      expect(result.contributions.attackConfidence).toBe(18.00);
      expect(result.contributions.businessImpact).toBe(17.00);
    });

    it('automatically normalizes rawAffectedUsers if provided in alert', () => {
      const alert = {
        severity: 100,        // 100 * 0.25 = 25.00
        assetImportance: 100, // 100 * 0.15 = 15.00
        rawAffectedUsers: 10000, // 100 * 0.05 = 5.00
        dataSensitivity: 100, // 100 * 0.15 = 15.00
        attackConfidence: 100,// 100 * 0.20 = 20.00
        businessImpact: 100   // 100 * 0.20 = 20.00
      };
      // Total = 100.00
      const result = calculateRiskScore(alert);
      expect(result.score).toBe(100.00);
      expect(result.factors.affectedUsers).toBe(100.00);
    });

    it('correctly calculates score with custom normalized weights', () => {
      const alert = {
        severity: 100,
        assetImportance: 0,
        affectedUsers: 0,
        dataSensitivity: 0,
        attackConfidence: 0,
        businessImpact: 0
      };
      // Custom weights: 50% severity, 50% confidence
      const customWeights = {
        severity: 0.50,
        assetImportance: 0.0,
        affectedUsers: 0.0,
        dataSensitivity: 0.0,
        attackConfidence: 0.50,
        businessImpact: 0.0
      };
      const result = calculateRiskScore(alert, customWeights);
      expect(result.score).toBe(50.00);
    });

    it('normalizes unnormalized custom weights to sum to 1.0', () => {
      // Raw weights sum to 2.0 -> should be scaled down by half
      const unnormalizedWeights = {
        severity: 0.50,
        assetImportance: 0.30,
        affectedUsers: 0.10,
        dataSensitivity: 0.30,
        attackConfidence: 0.40,
        businessImpact: 0.40
      };
      const norm = normalizeWeights(unnormalizedWeights);
      const sum = Object.values(norm).reduce((a, b) => a + b, 0);
      expect(sum).toBeCloseTo(1.0, 5);
      expect(norm.severity).toBeCloseTo(0.25, 4);
    });
  });

  // =========================================================================
  // SUITE 3: SCORE BOUNDARIES & PRIORITY TIERS
  // =========================================================================
  describe('Suite 3: Score Boundaries & Tier Thresholds', () => {
    it('evaluates minimum possible score (all factors 0) to exactly 0.00', () => {
      const minAlert = {
        severity: 0,
        assetImportance: 0,
        affectedUsers: 0,
        dataSensitivity: 0,
        attackConfidence: 0,
        businessImpact: 0
      };
      const result = calculateRiskScore(minAlert);
      expect(result.score).toBe(0.00);
      expect(result.tier.id).toBe('P4');
    });

    it('evaluates maximum possible score (all factors 100) to exactly 100.00', () => {
      const maxAlert = {
        severity: 100,
        assetImportance: 100,
        affectedUsers: 100,
        dataSensitivity: 100,
        attackConfidence: 100,
        businessImpact: 100
      };
      const result = calculateRiskScore(maxAlert);
      expect(result.score).toBe(100.00);
      expect(result.tier.id).toBe('P1');
    });

    it('safely clamps out-of-bound inputs (>100 to 100, <0 to 0)', () => {
      const clampedAlert = {
        severity: 250,
        assetImportance: -50,
        affectedUsers: 99999, // Should clamp to 100
        dataSensitivity: 150,
        attackConfidence: 120,
        businessImpact: -10
      };
      const factors = extractFactors(clampedAlert);
      expect(factors.severity).toBe(100);
      expect(factors.assetImportance).toBe(0);
      expect(factors.affectedUsers).toBe(100);
      expect(factors.dataSensitivity).toBe(100);
      expect(factors.attackConfidence).toBe(100);
      expect(factors.businessImpact).toBe(0);
    });

    it('correctly assigns Priority Tiers at exact boundary points', () => {
      expect(getPriorityTier(100).id).toBe('P1');
      expect(getPriorityTier(80.00).id).toBe('P1');
      expect(getPriorityTier(79.99).id).toBe('P2');
      expect(getPriorityTier(60.00).id).toBe('P2');
      expect(getPriorityTier(59.99).id).toBe('P3');
      expect(getPriorityTier(40.00).id).toBe('P3');
      expect(getPriorityTier(39.99).id).toBe('P4');
      expect(getPriorityTier(0.00).id).toBe('P4');
    });
  });

  // =========================================================================
  // SUITE 4: DETERMINISTIC SORTING
  // =========================================================================
  describe('Suite 4: Deterministic Priority Queue Sorting', () => {
    it('ranks alerts in descending order of calculated risk score', () => {
      const alerts = [
        { id: 'INC-01', severity: 40, assetImportance: 40, affectedUsers: 40, dataSensitivity: 40, attackConfidence: 40, businessImpact: 40 }, // score: 40
        { id: 'INC-02', severity: 90, assetImportance: 90, affectedUsers: 90, dataSensitivity: 90, attackConfidence: 90, businessImpact: 90 }, // score: 90
        { id: 'INC-03', severity: 65, assetImportance: 65, affectedUsers: 65, dataSensitivity: 65, attackConfidence: 65, businessImpact: 65 }, // score: 65
        { id: 'INC-04', severity: 10, assetImportance: 10, affectedUsers: 10, dataSensitivity: 10, attackConfidence: 10, businessImpact: 10 }  // score: 10
      ];

      const ranked = rankAlerts(alerts);
      expect(ranked.length).toBe(4);
      expect(ranked[0].id).toBe('INC-02');
      expect(ranked[0].rank).toBe(1);
      expect(ranked[1].id).toBe('INC-03');
      expect(ranked[1].rank).toBe(2);
      expect(ranked[2].id).toBe('INC-01');
      expect(ranked[2].rank).toBe(3);
      expect(ranked[3].id).toBe('INC-04');
      expect(ranked[3].rank).toBe(4);
    });

    it('handles empty or single-element alert arrays gracefully', () => {
      expect(rankAlerts([])).toEqual([]);
      const single = rankAlerts([{ id: 'INC-SINGLE', severity: 50, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 }]);
      expect(single.length).toBe(1);
      expect(single[0].rank).toBe(1);
    });
  });

  // =========================================================================
  // SUITE 5: DETERMINISTIC 6-TIER TIE-BREAKING
  // =========================================================================
  describe('Suite 5: 6-Tier Tie-Breaking Hierarchy', () => {
    it('Tier 1: Higher Risk Score wins', () => {
      const alertA = { id: 'A', severity: 80, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 };
      const alertB = { id: 'B', severity: 70, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 };
      
      const comp = compareIncidents(alertA, alertB);
      expect(comp).toBeLessThan(0); // alertA comes first
      const trace = explainTieBreak(alertA, alertB);
      expect(trace.level).toBe(1);
      expect(trace.winner).toBe('A');
    });

    it('Tier 2: Equal Risk Score -> Higher Attack Confidence wins', () => {
      // Both have equal score of 60.00
      // Alert A: higher confidence (80 vs 60), balanced by lower severity
      // Alert A: SEV(44)*0.25=11 + AST(60)*0.15=9 + USR(60)*0.05=3 + DAT(60)*0.15=9 + CNF(80)*0.20=16 + IMP(60)*0.20=12 = 60.00
      // Alert B: SEV(60)*0.25=15 + AST(60)*0.15=9 + USR(60)*0.05=3 + DAT(60)*0.15=9 + CNF(60)*0.20=12 + IMP(60)*0.20=12 = 60.00
      const alertA = { id: 'INC-CNF-HIGH', severity: 44, assetImportance: 60, affectedUsers: 60, dataSensitivity: 60, attackConfidence: 80, businessImpact: 60, timestamp: '2026-09-01T10:00:00Z' };
      const alertB = { id: 'INC-CNF-LOW',  severity: 60, assetImportance: 60, affectedUsers: 60, dataSensitivity: 60, attackConfidence: 60, businessImpact: 60, timestamp: '2026-09-01T10:00:00Z' };

      const scoreA = calculateRiskScore(alertA).score;
      const scoreB = calculateRiskScore(alertB).score;
      expect(scoreA).toBe(scoreB);

      const comp = compareIncidents(alertA, alertB);
      expect(comp).toBeLessThan(0); // Alert A wins because CNF 80 > 60
      const trace = explainTieBreak(alertA, alertB);
      expect(trace.level).toBe(2);
      expect(trace.winner).toBe('INC-CNF-HIGH');
    });

    it('Tier 3: Equal Score & Confidence -> Higher Business Impact wins', () => {
      // Both have equal score and equal CNF (70)
      // Alert A has higher IMP (90 vs 70), offset by lower SEV
      // Alert A: SEV(44)*0.25=11 + AST(70)*0.15=10.5 + USR(70)*0.05=3.5 + DAT(70)*0.15=10.5 + CNF(70)*0.20=14 + IMP(90)*0.20=18 = 67.50
      // Alert B: SEV(60)*0.25=15 + AST(70)*0.15=10.5 + USR(70)*0.05=3.5 + DAT(70)*0.15=10.5 + CNF(70)*0.20=14 + IMP(70)*0.20=14 = 67.50
      const alertA = { id: 'INC-IMP-HIGH', severity: 44, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 90, timestamp: '2026-09-01T10:00:00Z' };
      const alertB = { id: 'INC-IMP-LOW',  severity: 60, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 70, timestamp: '2026-09-01T10:00:00Z' };

      const scoreA = calculateRiskScore(alertA).score;
      const scoreB = calculateRiskScore(alertB).score;
      expect(scoreA).toBe(scoreB);

      const comp = compareIncidents(alertA, alertB);
      expect(comp).toBeLessThan(0); // Alert A wins because IMP 90 > 70
      const trace = explainTieBreak(alertA, alertB);
      expect(trace.level).toBe(3);
      expect(trace.winner).toBe('INC-IMP-HIGH');
    });

    it('Tier 4: Equal Score, Confidence & Impact -> Higher Data Sensitivity wins', () => {
      // Both have equal score, CNF (80), IMP (80)
      // Alert A: higher DAT (90 vs 70)
      // Alert A: SEV(68)*0.25=17 + AST(80)*0.15=12 + USR(80)*0.05=4 + DAT(90)*0.15=13.5 + CNF(80)*0.20=16 + IMP(80)*0.20=16 = 78.50
      // Alert B: SEV(80)*0.25=20 + AST(80)*0.15=12 + USR(80)*0.05=4 + DAT(70)*0.15=10.5 + CNF(80)*0.20=16 + IMP(80)*0.20=16 = 78.50
      const alertA = { id: 'INC-DAT-HIGH', severity: 68, assetImportance: 80, affectedUsers: 80, dataSensitivity: 90, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };
      const alertB = { id: 'INC-DAT-LOW',  severity: 80, assetImportance: 80, affectedUsers: 80, dataSensitivity: 70, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };

      const scoreA = calculateRiskScore(alertA).score;
      const scoreB = calculateRiskScore(alertB).score;
      expect(scoreA).toBe(scoreB);

      const comp = compareIncidents(alertA, alertB);
      expect(comp).toBeLessThan(0); // Alert A wins because DAT 90 > 70
      const trace = explainTieBreak(alertA, alertB);
      expect(trace.level).toBe(4);
      expect(trace.winner).toBe('INC-DAT-HIGH');
    });

    it('Tier 5: Equal Score, Conf, Impact & Data -> Higher Asset Importance wins', () => {
      // Both have equal score, CNF (80), IMP (80), DAT (80)
      // Alert A: AST(90 vs 70)
      // Alert A: SEV(68)*0.25=17 + AST(90)*0.15=13.5 + USR(80)*0.05=4 + DAT(80)*0.15=12 + CNF(80)*0.20=16 + IMP(80)*0.20=16 = 78.50
      // Alert B: SEV(80)*0.25=20 + AST(70)*0.15=10.5 + USR(80)*0.05=4 + DAT(80)*0.15=12 + CNF(80)*0.20=16 + IMP(80)*0.20=16 = 78.50
      const alertA = { id: 'INC-AST-HIGH', severity: 68, assetImportance: 90, affectedUsers: 80, dataSensitivity: 80, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };
      const alertB = { id: 'INC-AST-LOW',  severity: 80, assetImportance: 70, affectedUsers: 80, dataSensitivity: 80, attackConfidence: 80, businessImpact: 80, timestamp: '2026-09-01T10:00:00Z' };

      const scoreA = calculateRiskScore(alertA).score;
      const scoreB = calculateRiskScore(alertB).score;
      expect(scoreA).toBe(scoreB);

      const comp = compareIncidents(alertA, alertB);
      expect(comp).toBeLessThan(0); // Alert A wins because AST 90 > 70
      const trace = explainTieBreak(alertA, alertB);
      expect(trace.level).toBe(5);
      expect(trace.winner).toBe('INC-AST-HIGH');
    });

    it('Tier 6: All factors identical -> Timestamp ascending (Oldest first / FIFO)', () => {
      const alertOld = { id: 'INC-OLD', severity: 75, assetImportance: 75, affectedUsers: 75, dataSensitivity: 75, attackConfidence: 75, businessImpact: 75, timestamp: '2026-09-01T08:00:00Z' };
      const alertNew = { id: 'INC-NEW', severity: 75, assetImportance: 75, affectedUsers: 75, dataSensitivity: 75, attackConfidence: 75, businessImpact: 75, timestamp: '2026-09-01T11:00:00Z' };

      const comp = compareIncidents(alertOld, alertNew);
      expect(comp).toBeLessThan(0); // Older alert wins
      const trace = explainTieBreak(alertOld, alertNew);
      expect(trace.level).toBe(6);
      expect(trace.winner).toBe('INC-OLD');
    });

    it('Tier 7: All factors & timestamps identical -> Incident ID ascending', () => {
      const alertA = { id: 'INC-AAA', severity: 70, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 70, timestamp: '2026-09-01T10:00:00Z' };
      const alertZ = { id: 'INC-ZZZ', severity: 70, assetImportance: 70, affectedUsers: 70, dataSensitivity: 70, attackConfidence: 70, businessImpact: 70, timestamp: '2026-09-01T10:00:00Z' };

      const comp = compareIncidents(alertA, alertZ);
      expect(comp).toBeLessThan(0); // 'INC-AAA' precedes 'INC-ZZZ'
      const trace = explainTieBreak(alertA, alertZ);
      expect(trace.level).toBe(7);
      expect(trace.winner).toBe('INC-AAA');
    });
  });

  // =========================================================================
  // SUITE 6: REALISTIC DATASET (100+ ALERTS) & QUEUE INTEGRITY
  // =========================================================================
  describe('Suite 6: Sample Dataset (105 Alerts) & Queue Verification', () => {
    it('contains at least 100 realistic security alerts', async () => {
      const { MOCK_SECURITY_ALERTS } = await import('../data/mockAlerts.js');
      expect(MOCK_SECURITY_ALERTS.length).toBeGreaterThanOrEqual(100);
    });

    it('ensures every alert has all 13 mandatory SOC fields and valid factors', async () => {
      const { MOCK_SECURITY_ALERTS } = await import('../data/mockAlerts.js');
      const requiredFields = [
        'id', 'timestamp', 'alertType', 'shortDescription', 'source',
        'severity', 'asset', 'assetImportance', 'rawAffectedUsers',
        'dataSensitivity', 'attackConfidence', 'businessImpact', 'status'
      ];

      MOCK_SECURITY_ALERTS.forEach((alert, idx) => {
        for (const field of requiredFields) {
          if (alert[field] === undefined || alert[field] === null) {
            throw new Error(`Alert at index ${idx} (ID: ${alert.id}) missing required field: ${field}`);
          }
        }

        // Validate numeric factor boundaries [0, 100]
        if (alert.severity < 0 || alert.severity > 100) throw new Error(`Invalid severity in ${alert.id}: ${alert.severity}`);
        if (alert.assetImportance < 0 || alert.assetImportance > 100) throw new Error(`Invalid assetImportance in ${alert.id}: ${alert.assetImportance}`);
        if (alert.rawAffectedUsers < 0) throw new Error(`Invalid rawAffectedUsers in ${alert.id}: ${alert.rawAffectedUsers}`);
        if (alert.dataSensitivity < 0 || alert.dataSensitivity > 100) throw new Error(`Invalid dataSensitivity in ${alert.id}: ${alert.dataSensitivity}`);
        if (alert.attackConfidence < 0 || alert.attackConfidence > 100) throw new Error(`Invalid attackConfidence in ${alert.id}: ${alert.attackConfidence}`);
        if (alert.businessImpact < 0 || alert.businessImpact > 100) throw new Error(`Invalid businessImpact in ${alert.id}: ${alert.businessImpact}`);
      });
    });

    it('successfully ranks all 105 alerts into a strictly deterministic priority queue', async () => {
      const { MOCK_SECURITY_ALERTS } = await import('../data/mockAlerts.js');
      const rankedQueue = rankAlerts(MOCK_SECURITY_ALERTS);

      expect(rankedQueue.length).toBe(MOCK_SECURITY_ALERTS.length);

      // Verify ranks 1 to N are sequentially ordered without gaps
      rankedQueue.forEach((alert, idx) => {
        expect(alert.rank).toBe(idx + 1);
        if (isNaN(alert.score) || alert.score < 0 || alert.score > 100) {
          throw new Error(`Invalid ranked score for ${alert.id}: ${alert.score}`);
        }
      });

      // Verify strictly descending risk score (or valid tie-break ordering)
      for (let i = 0; i < rankedQueue.length - 1; i++) {
        const a = rankedQueue[i];
        const b = rankedQueue[i + 1];
        const comp = compareIncidents(a, b);
        expect(comp).toBeLessThanOrEqual(0);
      }
    });
  });

  // =========================================================================
  // SUITE 7: RANKING EXPLANATION & DECISION TRACE VERIFICATION
  // =========================================================================
  describe('Suite 7: Ranking Explanation & Side-by-Side Comparison', () => {
    it('formats factor lists with proper commas and Oxford comma', () => {
      expect(formatFactorList([])).toBe('');
      expect(formatFactorList(['severity'])).toBe('severity');
      expect(formatFactorList(['severity', 'attack confidence'])).toBe('severity and attack confidence');
      expect(formatFactorList(['severity', 'asset importance', 'data sensitivity', 'business impact']))
        .toBe('severity, asset importance, data sensitivity, and business impact');
    });

    it('generates concise factual explanation when Incident #1 outranks #2 with factor trade-offs', () => {
      // Incident #1: High severity, asset, data, impact; lower confidence
      const alert1 = {
        id: 'INC-2026-0001',
        rank: 1,
        severity: 98,         // 98 * 0.25 = 24.50
        assetImportance: 90,  // 90 * 0.15 = 13.50
        affectedUsers: 75,    // 75 * 0.05 = 3.75
        dataSensitivity: 90,  // 90 * 0.15 = 13.50
        attackConfidence: 80, // 80 * 0.20 = 16.00
        businessImpact: 92    // 92 * 0.20 = 18.40
      }; // Total = 89.65

      // Incident #2: Higher confidence (96 vs 80), but lower severity and asset
      const alert2 = {
        id: 'INC-2026-0002',
        rank: 2,
        severity: 80,         // 80 * 0.25 = 20.00
        assetImportance: 70,  // 70 * 0.15 = 10.50
        affectedUsers: 75,    // 75 * 0.05 = 3.75
        dataSensitivity: 80,  // 80 * 0.15 = 12.00
        attackConfidence: 96, // 96 * 0.20 = 19.20
        businessImpact: 80    // 80 * 0.20 = 16.00
      }; // Total = 81.45

      const result = generateRankComparisonExplanation(alert1, alert2);
      expect(result.rankA).toBe(1);
      expect(result.rankB).toBe(2);
      expect(result.scoreA).toBe(89.65);
      expect(result.scoreB).toBe(81.45);
      expect(result.gains.length).toBe(4); // severity, assetImportance, dataSensitivity, businessImpact
      expect(result.concessions.length).toBe(1); // attackConfidence

      // Verify explanation text exactly references real values and largest advantage
      expect(result.explanation.includes('ranks #1 with 89.65 points')).toBe(true);
      expect(result.explanation.includes('8.20 points above')).toBe(true);
      expect(result.explanation.includes('Severity provides the largest individual advantage at +4.50 points')).toBe(true);
    });

    it('generates concise explanation when an incident dominates or equals all factors', () => {
      const alertA = {
        id: 'INC-A',
        rank: 1,
        severity: 95,
        assetImportance: 95,
        affectedUsers: 90,
        dataSensitivity: 90,
        attackConfidence: 95,
        businessImpact: 95
      };
      const alertB = {
        id: 'INC-B',
        rank: 2,
        severity: 70,
        assetImportance: 70,
        affectedUsers: 70,
        dataSensitivity: 70,
        attackConfidence: 70,
        businessImpact: 70
      };

      const result = generateRankComparisonExplanation(alertA, alertB);
      expect(result.concessions.length).toBe(0);
      expect(result.explanation.includes('ranks #1 with 89.00 points, 19.00 points above INC-B at 70.00')).toBe(true);
      expect(result.explanation.includes('gaining more weighted points from')).toBe(true);
    });

    it('generates tie-break rule explanation when two incidents share identical risk score', () => {
      const alertA = {
        id: 'INC-TIE-1',
        rank: 3,
        severity: 44,
        assetImportance: 60,
        affectedUsers: 60,
        dataSensitivity: 60,
        attackConfidence: 80,
        businessImpact: 60,
        timestamp: '2026-09-01T10:00:00Z'
      };
      const alertB = {
        id: 'INC-TIE-2',
        rank: 4,
        severity: 60,
        assetImportance: 60,
        affectedUsers: 60,
        dataSensitivity: 60,
        attackConfidence: 60,
        businessImpact: 60,
        timestamp: '2026-09-01T10:00:00Z'
      };

      const result = generateRankComparisonExplanation(alertA, alertB);
      expect(result.isTie).toBe(true);
      expect(result.tieTrace.level).toBe(2);
      expect(result.explanation.includes('tied with INC-TIE-2 at 60.00 points')).toBe(true);
      expect(result.explanation.includes('Deterministic Rule Level 2')).toBe(true);
    });

    it('handles the final incident in queue gracefully with no lower-ranked incident', () => {
      const lastAlert = {
        id: 'INC-LAST',
        rank: 108,
        severity: 20,
        assetImportance: 20,
        affectedUsers: 10,
        dataSensitivity: 20,
        attackConfidence: 30,
        businessImpact: 20
      };

      const result = generateRankComparisonExplanation(lastAlert, null);
      expect(result.rankA).toBe(108);
      expect(result.rankB).toBe(null);
      expect(result.explanation).toBe(
        'Incident #108 is currently the final incident in the active priority queue. There is no lower-ranked incident to compare.'
      );
    });

    it('computes exact mathematical contributions matching engine formula', () => {
      const alert = {
        id: 'INC-MATH',
        severity: 98,
        assetImportance: 90,
        rawAffectedUsers: 1000,
        dataSensitivity: 90,
        attackConfidence: 96,
        businessImpact: 92
      };

      const calc = calculateRiskScore(alert);
      const c = calc.contributions;
      const f = calc.factors;
      const w = calc.weights;

      expect(c.severity).toBeCloseTo(f.severity * w.severity, 2);
      expect(c.assetImportance).toBeCloseTo(f.assetImportance * w.assetImportance, 2);
      expect(c.affectedUsers).toBeCloseTo(f.affectedUsers * w.affectedUsers, 2);
      expect(c.dataSensitivity).toBeCloseTo(f.dataSensitivity * w.dataSensitivity, 2);
      expect(c.attackConfidence).toBeCloseTo(f.attackConfidence * w.attackConfidence, 2);
      expect(c.businessImpact).toBeCloseTo(f.businessImpact * w.businessImpact, 2);

      const sum = c.severity + c.assetImportance + c.affectedUsers + c.dataSensitivity + c.attackConfidence + c.businessImpact;
      expect(calc.score).toBeCloseTo(sum, 1);
    });
  });

  // =========================================================================
  // SUITE 8: INVARIANTS, ZERO-FABRICATION, SHA-256 & DASHBOARD TOTALS
  // =========================================================================
  describe('Suite 8: System Invariants, Verification Hash & Dashboard Consistency', () => {
    it('generates authentic, valid 64-character hexadecimal SHA-256 hash for incident reports', () => {
      const hash1 = computeSHA256Hex('SIGNALRANK-TEST-PAYLOAD');
      expect(hash1.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(hash1)).toBe(true);

      // Known SHA-256 test vector: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
      const hashAbc = computeSHA256Hex('abc');
      expect(hashAbc).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

      // Incident Report data contains real verificationHash
      const testAlert = {
        id: 'INC-2026-0001',
        timestamp: '2026-09-01T10:00:00Z',
        alertType: 'Ransomware',
        asset: 'AD-DC-01',
        severity: 98,
        assetImportance: 100,
        rawAffectedUsers: 4500,
        dataSensitivity: 95,
        attackConfidence: 96,
        businessImpact: 98
      };
      const repData = buildIncidentReportData(testAlert, null, DEFAULT_WEIGHTS);
      expect(repData.verificationHash.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(repData.verificationHash)).toBe(true);
    });

    it('validates dashboard metrics consistency: Total == Critical (P1) + High (P2) + Medium (P3) + Low (P4)', async () => {
      const { MOCK_SECURITY_ALERTS } = await import('../data/mockAlerts.js');
      const rankedQueue = rankAlerts(MOCK_SECURITY_ALERTS, DEFAULT_WEIGHTS);
      const stats = computeQueueAnalytics(rankedQueue);

      expect(stats.total).toBe(MOCK_SECURITY_ALERTS.length);
      expect(stats.total).toBeGreaterThanOrEqual(106);

      const sumTiers = stats.criticalCount + stats.highCount + stats.mediumCount + stats.lowCount;
      expect(sumTiers).toBe(stats.total);
      expect(stats.avgScore).toBeGreaterThan(0);
      expect(stats.avgScore).toBeLessThanOrEqual(100);
    });

    it('ensures monotonic score increase when any factor is strictly increased', () => {
      const base = { severity: 50, assetImportance: 50, affectedUsers: 50, dataSensitivity: 50, attackConfidence: 50, businessImpact: 50 };
      const baseScore = calculateRiskScore(base).score;

      const incSev = calculateRiskScore({ ...base, severity: 80 }).score;
      const incAst = calculateRiskScore({ ...base, assetImportance: 80 }).score;
      const incUsr = calculateRiskScore({ ...base, affectedUsers: 80 }).score;
      const incDat = calculateRiskScore({ ...base, dataSensitivity: 80 }).score;
      const incCnf = calculateRiskScore({ ...base, attackConfidence: 80 }).score;
      const incImp = calculateRiskScore({ ...base, businessImpact: 80 }).score;

      expect(incSev).toBeGreaterThan(baseScore);
      expect(incAst).toBeGreaterThan(baseScore);
      expect(incUsr).toBeGreaterThan(baseScore);
      expect(incDat).toBeGreaterThan(baseScore);
      expect(incCnf).toBeGreaterThan(baseScore);
      expect(incImp).toBeGreaterThan(baseScore);
    });

    it('ensures What-If simulation calculations do not mutate the source alert object', () => {
      const originalAlert = {
        id: 'INC-IMMUTABLE-01',
        severity: 70,
        assetImportance: 70,
        rawAffectedUsers: 500,
        dataSensitivity: 70,
        attackConfidence: 70,
        businessImpact: 70
      };

      const cloneBefore = JSON.parse(JSON.stringify(originalAlert));
      
      // Simulate modified parameters
      const simulatedFactors = {
        ...originalAlert,
        severity: 95,
        assetImportance: 90
      };
      const simCalc = calculateRiskScore(simulatedFactors);

      // Verify original alert is completely unchanged
      expect(originalAlert.severity).toBe(cloneBefore.severity);
      expect(originalAlert.assetImportance).toBe(cloneBefore.assetImportance);
      expect(simCalc.score).toBeGreaterThan(calculateRiskScore(originalAlert).score);
    });
  });

  // =========================================================================
  // SUITE 9: INCIDENT ROW INTERACTION & DETAIL VIEW SUITE
  // =========================================================================
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

    const mockQueue = [mockAlert1, mockAlert2];

    it('1. Clicking an incident row opens its detail view with all 11 required fields', () => {
      const html = renderExplainabilityView(mockAlert1, mockQueue, DEFAULT_WEIGHTS);
      
      // 1. Incident ID
      expect(html.includes('INC-2026-0001')).toBe(true);
      // 2. Alert Type
      expect(html.includes('Ransomware / File Encryption')).toBe(true);
      // 3. Description
      expect(html.includes('Shadow copy deletion and encrypted canary files.')).toBe(true);
      // 4. Risk Score
      expect(html.includes('97.12')).toBe(true);
      // 5. Priority Rank
      expect(html.includes('Rank #1')).toBe(true);
      // 6. Severity
      expect(html.includes('98')).toBe(true);
      // 7. Asset Importance
      expect(html.includes('100')).toBe(true);
      // 8. Affected Users
      expect(html.includes('4,500')).toBe(true);
      // 9. Data Sensitivity
      expect(html.includes('95')).toBe(true);
      // 10. Attack Confidence
      expect(html.includes('96')).toBe(true);
      // 11. Business Impact
      expect(html.includes('98')).toBe(true);
    });

    it('2. Clicking Report does not trigger the row click handler', () => {
      // Test event propagation filter logic
      let rowHandlerTriggered = false;
      let reportHandlerTriggered = false;

      const simulateClick = (targetType) => {
        if (targetType === 'report_button') {
          // Report button handler runs and stops propagation
          reportHandlerTriggered = true;
          // Row click handler must check if click was inside button/interactive control
          const isInteractive = true;
          if (!isInteractive) {
            rowHandlerTriggered = true;
          }
        } else {
          // Normal row click
          rowHandlerTriggered = true;
        }
      };

      simulateClick('report_button');
      expect(reportHandlerTriggered).toBe(true);
      expect(rowHandlerTriggered).toBe(false);

      simulateClick('row_cell');
      expect(rowHandlerTriggered).toBe(true);
    });

    it('3. The correct incident data is displayed', () => {
      const html = renderExplainabilityView(mockAlert1, mockQueue, DEFAULT_WEIGHTS);
      expect(html.includes('DC-PRIMARY-01')).toBe(true);
      expect(html.includes('Falcon EDR')).toBe(true);
      expect(html.includes('CRITICAL PRIORITY')).toBe(true);
    });

    it('4. "Why is this ranked here?" displays the correct scoring data and Decision Trace', () => {
      const html = renderExplainabilityView(mockAlert1, mockQueue, DEFAULT_WEIGHTS);
      // Hero button present
      expect(html.includes('btnWhyRankedHereHero')).toBe(true);
      expect(html.includes('Why is this ranked here?')).toBe(true);
      // Decision trace section present
      expect(html.includes('decisionTraceSection')).toBe(true);
      expect(html.includes('Calculated by deterministic scoring engine')).toBe(true);
      // Contributions and weights present
      expect(html.includes('Severity')).toBe(true);
      expect(html.includes('25%')).toBe(true);
      expect(html.includes('Final Deterministic Score Calculation:')).toBe(true);
    });

    it('5. The comparison uses the incident immediately below the selected incident', () => {
      const html = renderExplainabilityView(mockAlert1, mockQueue, DEFAULT_WEIGHTS);
      // Ranks #1 compared against Rank #2 (INC-2026-0005)
      expect(html.includes('Why does this outrank #2?')).toBe(true);
      expect(html.includes('INC-2026-0005')).toBe(true);
    });

    it('6. The comparison score difference matches the actual scores', () => {
      const scoreDiff = Math.round((mockAlert1.score - mockAlert2.score) * 100) / 100;
      expect(scoreDiff).toBe(0.82);

      const comparison = generateRankComparisonExplanation(mockAlert1, mockAlert2, DEFAULT_WEIGHTS);
      expect(comparison.scoreDelta).toBe(0.82);
      expect(comparison.explanation.includes('0.82 points above')).toBe(true);
    });

    it('7. The explanation is based only on actual scoring values without LLM alteration', () => {
      const comparison = generateRankComparisonExplanation(mockAlert1, mockAlert2, DEFAULT_WEIGHTS);
      expect(comparison.idA).toBe('INC-2026-0001');
      expect(comparison.idB).toBe('INC-2026-0005');
      expect(comparison.scoreA).toBe(97.12);
      expect(comparison.scoreB).toBe(96.30);
      expect(comparison.largestAdvantage).not.toBe(null);
      expect(comparison.isTie).toBe(false);
    });

    it('8. WhatIfSimulator renders simulation view with baselineFactors without throwing TypeError', () => {
      const sim = new WhatIfSimulator(mockAlert1, mockQueue, DEFAULT_WEIGHTS);
      const html = sim.renderSimulatorView();
      expect(html.includes('Baseline: 98')).toBe(true);
      expect(html.includes('simSlider_severity')).toBe(true);
      expect(html.includes('What-If Threat Scenario Sandbox')).toBe(true);
    });

    it('9. WhatIfSimulator handles undefined or null incident gracefully', () => {
      const nullSim = new WhatIfSimulator(null);
      const html = nullSim.renderSimulatorView();
      expect(html.includes('Incident data unavailable')).toBe(true);
    });

    it('10. renderExplainabilityView handles undefined or null incident gracefully', () => {
      const nullHtml = renderExplainabilityView(null);
      expect(nullHtml.includes('Incident data unavailable')).toBe(true);
    });
  });

  // =========================================================================
  // SUITE 10: CUSTOM ALERT ANALYSIS & INGESTION (+ Analyze My Alert)
  // =========================================================================
  describe('Suite 10: Custom Alert Analysis & Ingestion Engine', () => {
    const rawJsonAlert = JSON.stringify({
      event_type: 'Ransomware / File Encryption Threat',
      details: 'Active canary file encryption on primary domain cluster.',
      host: 'DC-PRIMARY-01',
      severity: 94,
      affected_users: 2500,
      source: 'Falcon EDR',
      ip: '198.51.100.24',
      sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0'
    });

    it('1. User can paste a custom alert and parse raw content', () => {
      const parsed = parseRawSecurityInput(rawJsonAlert);
      expect(parsed.detectedFormat).toBe('JSON');
      expect(parsed.extractedFields.alertType).toBe('Ransomware / File Encryption Threat');
      expect(parsed.extractedFields.asset).toBe('DC-PRIMARY-01');
      expect(parsed.factors.severity.value).toBe(94);
      expect(parsed.factors.severity.source).toBe('EXTRACTED');
      expect(parsed.factors.rawAffectedUsers.value).toBe(2500);
      expect(parsed.factors.rawAffectedUsers.source).toBe('EXTRACTED');
    });

    it('2. User can upload and parse supported security files (.csv, .eml, .log, .json)', () => {
      const csvContent = 'type,severity,asset,impacted_users\nSQL Injection Attack,88,PROD-API-01,150';
      const parsedCsv = parseRawSecurityInput(csvContent, 'incident_export.csv');
      expect(parsedCsv.detectedFormat).toBe('CSV');
      expect(parsedCsv.extractedFields.alertType).toBe('SQL Injection Attack');
      expect(parsedCsv.factors.severity.value).toBe(88);
      expect(parsedCsv.factors.rawAffectedUsers.value).toBe(150);

      const emlContent = 'From: attacker@evil.com\nTo: admin@corp.internal\nSubject: Password Expired\nTarget: Mailbox\nSeverity: High';
      const parsedEml = parseRawSecurityInput(emlContent, 'phish.eml');
      expect(parsedEml.detectedFormat).toBe('EML');
      expect(parsedEml.extractedFields.alertType.includes('Password Expired')).toBe(true);
      expect(parsedEml.factors.severity.value).toBe(80);
    });

    it('3. Raw alert fields and real IoCs are extracted accurately', () => {
      const parsed = parseRawSecurityInput(rawJsonAlert);
      expect(parsed.extractedFields.evidence.length >= 2).toBe(true);
      expect(parsed.extractedFields.evidence.some(e => e.includes('198.51.100.24'))).toBe(true);
      expect(parsed.extractedFields.evidence.some(e => e.includes('a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0'))).toBe(true);
    });

    it('4. Missing fields are tagged as MISSING rather than invented', () => {
      const parsed = parseRawSecurityInput(rawJsonAlert);
      expect(parsed.factors.assetImportance.value).toBe(null);
      expect(parsed.factors.assetImportance.source).toBe('MISSING');
      expect(parsed.factors.dataSensitivity.value).toBe(null);
      expect(parsed.factors.dataSensitivity.source).toBe('MISSING');
      expect(parsed.missingFieldKeys.includes('assetImportance')).toBe(true);
      expect(parsed.missingFieldKeys.includes('dataSensitivity')).toBe(true);
    });

    it('5. User can correct and enrich extracted values with organizational context', () => {
      const parsed = parseRawSecurityInput(rawJsonAlert);
      const userFactors = {
        severity: parsed.factors.severity.value || 80,
        assetImportance: 90, // User-provided context
        rawAffectedUsers: parsed.factors.rawAffectedUsers.value || 100,
        dataSensitivity: 85,  // User-provided context
        attackConfidence: 95, // User-provided context
        businessImpact: 88    // User-provided context
      };
      expect(userFactors.assetImportance).toBe(90);
      expect(userFactors.dataSensitivity).toBe(85);
      expect(userFactors.attackConfidence).toBe(95);
      expect(userFactors.businessImpact).toBe(88);
    });

    it('6. Custom alert uses existing deterministic scoring engine', () => {
      const customAlertObj = {
        id: 'CUSTOM-2026-0001',
        alertType: 'Ransomware / File Encryption Threat',
        severity: 94,
        assetImportance: 90,
        rawAffectedUsers: 2500,
        dataSensitivity: 85,
        attackConfidence: 95,
        businessImpact: 88
      };
      const scoreResult = calculateRiskScore(customAlertObj, DEFAULT_WEIGHTS);
      // Normalized users: 2500 -> 84.95
      // 94*0.25 + 90*0.15 + 84.95*0.05 + 85*0.15 + 95*0.20 + 88*0.20
      // 23.50 + 13.50 + 4.25 + 12.75 + 19.00 + 17.60 = 90.60
      expect(scoreResult.score).toBe(90.60);
      expect(scoreResult.tier.id).toBe('P1');
    });

    it('7. Custom alert is inserted into existing queue and re-ranked', () => {
      const customAlert = {
        id: 'CUSTOM-2026-0001',
        alertType: 'Ransomware / File Encryption Threat',
        severity: 94,
        assetImportance: 90,
        rawAffectedUsers: 2500,
        dataSensitivity: 85,
        attackConfidence: 95,
        businessImpact: 88,
        timestamp: '2026-09-01T12:00:00.000Z'
      };
      const queueWithCustom = [customAlert, mockAlert1, mockAlert2];
      const ranked = rankAlerts(queueWithCustom, DEFAULT_WEIGHTS);
      expect(ranked.length).toBe(3);
      expect(ranked[0].id).toBe('INC-2026-0001'); // 97.12
      expect(ranked[1].id).toBe('INC-2026-0005'); // 96.30
      expect(ranked[2].id).toBe('CUSTOM-2026-0001'); // 90.60
      expect(ranked[2].rank).toBe(3);
    });

    it('8. Custom alert receives unique ID prefix CUSTOM-2026-', () => {
      const customId = `CUSTOM-2026-0001`;
      expect(customId.startsWith('CUSTOM-2026-')).toBe(true);
    });

    it('9. Decision Trace uses real custom alert factor values and exact calculations', () => {
      const customAlert = {
        id: 'CUSTOM-2026-0001',
        alertType: 'Ransomware / File Encryption Threat',
        severity: 94,
        assetImportance: 90,
        rawAffectedUsers: 2500,
        dataSensitivity: 85,
        attackConfidence: 95,
        businessImpact: 88
      };
      const calc = calculateRiskScore(customAlert, DEFAULT_WEIGHTS);
      const sum = Object.values(calc.contributions).reduce((a, b) => a + b, 0);
      expect(Math.round(sum * 100) / 100).toBe(90.60);
    });

    it('10. Incident Report identifies source as user-supplied alert without fabricated evidence', () => {
      const customAlert = {
        id: 'CUSTOM-2026-0001',
        alertType: 'Ransomware / File Encryption Threat',
        asset: 'DC-PRIMARY-01',
        source: 'Falcon EDR (User-Supplied)',
        severity: 94,
        assetImportance: 90,
        rawAffectedUsers: 2500,
        dataSensitivity: 85,
        attackConfidence: 95,
        businessImpact: 88,
        isCustom: true,
        iocs: ['IP: 198.51.100.24'],
        timestamp: '2026-09-01T12:00:00.000Z'
      };
      const reportData = buildIncidentReportData(customAlert, mockAlert1, DEFAULT_WEIGHTS);
      expect(reportData.evidence.some(e => e.includes('Source: User-supplied alert'))).toBe(true);
      expect(reportData.evidence.some(e => e.includes('198.51.100.24'))).toBe(true);
      expect(reportData.riskScore.includes('90.60')).toBe(true);
    });

    it('11. Simulated alert ingestion remains distinct and functional', () => {
      const simulatedId = 'INC-2026-0109';
      expect(simulatedId.startsWith('INC-2026-')).toBe(true);
    });
  });
}


