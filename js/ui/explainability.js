/**
 * SignalRank - Explainability Drawer & AI Explanation Layer
 * 
 * Generates exact formula breakdowns, mathematical factor contributions,
 * data-driven "Why is this ranked here?" explanations, interactive "What If?" simulation,
 * and AI-powered natural-language briefings with strict score separation.
 */

import { generateScoreExplanation, calculateRiskScore } from '../engine/scoring.js';
import { explainTieBreak, generateRankComparisonExplanation } from '../engine/comparator.js';
import { FACTOR_DEFINITIONS, PRIORITY_TIERS } from '../engine/types.js';
import { WhatIfSimulator } from './simulator.js';
import { aiService } from '../ai/aiService.js';

/**
 * Generates the data-driven "Why is this ranked here?" analytical text.
 */
export function generateWhyRankedAnalysis(alert, nextAlert, explanation, queue = []) {
  const factors = explanation.factors;
  const contributions = explanation.contributions;

  const highestFactor = explanation.topDriver;
  let dangerText = `Observed telemetry flags ${alert.alertType} associated with ${alert.asset || 'target asset'}. `;
  if (factors.severity >= 85 && factors.assetImportance >= 85) {
    dangerText += `Priority is elevated due to a high technical Severity score (${factors.severity.toFixed(1)}/100) on a critical infrastructure asset (${alert.asset}, Asset Importance: ${factors.assetImportance.toFixed(1)}/100).`;
  } else if (factors.dataSensitivity >= 85) {
    dangerText += `Elevated data sensitivity score (${factors.dataSensitivity.toFixed(0)}/100) associated with the targeted asset/service.`;
  } else if (factors.rawAffectedUsers >= 1000) {
    dangerText += `Elevated scope with an affected footprint of ${factors.rawAffectedUsers.toLocaleString()} recorded user accounts/identities.`;
  } else if (factors.attackConfidence >= 90) {
    dangerText += `High-fidelity detection telemetry from ${alert.source} with an Attack Confidence assessment of ${factors.attackConfidence.toFixed(0)}%.`;
  } else {
    dangerText += `Driven primarily by ${highestFactor.label} (+${highestFactor.contribution.toFixed(2)} pts).`;
  }

  const increasedFactors = [];
  Object.keys(FACTOR_DEFINITIONS).forEach(k => {
    const val = factors[k];
    const contrib = contributions[k];
    const def = FACTOR_DEFINITIONS[k];
    if (val >= 70) {
      increasedFactors.push({
        label: def.label,
        val: val.toFixed(1),
        contrib: contrib.toFixed(2),
        reason: val >= 90 ? 'Critically elevated' : 'High priority driver'
      });
    }
  });

  const reducedFactors = [];
  Object.keys(FACTOR_DEFINITIONS).forEach(k => {
    const val = factors[k];
    const contrib = contributions[k];
    const def = FACTOR_DEFINITIONS[k];
    if (val < 50) {
      reducedFactors.push({
        label: def.label,
        val: val.toFixed(1),
        contrib: contrib.toFixed(2),
        reason: val === 0 ? 'Zero recorded exposure' : 'Below baseline risk threshold'
      });
    }
  });

  let rankedAboveNextExplanation = '';
  let tieTrace = null;

  if (nextAlert) {
    tieTrace = explainTieBreak(alert, nextAlert);
    const scoreDiff = (alert.score || explanation.score) - (nextAlert.score || 0);
    const currentContribs = explanation.contributions || alert.contributions || {};
    const nextContribs = nextAlert.contributions || (calculateRiskScore(nextAlert).contributions) || {};

    if (Math.abs(scoreDiff) > 0.001) {
      let maxDeltaKey = 'severity';
      let maxDeltaVal = -999;
      Object.keys(FACTOR_DEFINITIONS).forEach(k => {
        const delta = (currentContribs[k] || 0) - (nextContribs[k] || 0);
        if (delta > maxDeltaVal) {
          maxDeltaVal = delta;
          maxDeltaKey = k;
        }
      });

      rankedAboveNextExplanation = `Ranked #${alert.rank || 1} (${(alert.score || explanation.score).toFixed(2)} pts) above #${nextAlert.rank || 2} ${nextAlert.id} (${(nextAlert.score || 0).toFixed(2)} pts) with a +${scoreDiff.toFixed(2)} pt margin. The largest advantage is ${FACTOR_DEFINITIONS[maxDeltaKey].label} (contributing +${maxDeltaVal.toFixed(2)} more points).`;
    } else {
      rankedAboveNextExplanation = `Tied in risk score with #${nextAlert.rank || 2} ${nextAlert.id} (${(alert.score || explanation.score).toFixed(2)} pts). Decided at Deterministic Rule Level ${tieTrace.level} (${tieTrace.rule}): ${tieTrace.explanation}`;
    }
  } else {
    rankedAboveNextExplanation = `This is currently the final incident in the active priority queue.`;
  }

  return {
    dangerText,
    increasedFactors,
    reducedFactors,
    rankedAboveNextExplanation,
    tieTrace
  };
}

/**
 * Renders the full explainability drawer for the selected alert.
 */
export function renderExplainabilityView(alert, queue = [], currentWeights) {
  if (!alert) {
    return `
      <div class="drawer-header">
        <div class="drawer-title-group">
          <h2 class="drawer-alert-title">Incident Data Unavailable</h2>
          <p class="drawer-alert-desc">No active incident selected.</p>
        </div>
        <div class="drawer-header-actions-col">
          <button class="drawer-close-btn" id="closeDrawerBtn" aria-label="Close Inspector">&times;</button>
        </div>
      </div>
      <div class="drawer-content tab-panel active">
        <div class="sandbox-disclaimer-banner">
          <div class="sandbox-icon">⚠️</div>
          <div class="sandbox-text">
            <strong>Incident data unavailable:</strong> Unable to load incident details.
          </div>
        </div>
      </div>
    `;
  }

  const explanation = generateScoreExplanation(alert, currentWeights);
  const currentRank = alert.rank || (queue.findIndex(a => a.id === alert.id) + 1);

  const alertIndex = queue.findIndex(a => a.id === alert.id);
  const nextAlert = (alertIndex >= 0 && alertIndex < queue.length - 1) ? queue[alertIndex + 1] : null;
  const nextRank = nextAlert ? (nextAlert.rank || (currentRank + 1)) : (currentRank + 1);

  const comparison = generateRankComparisonExplanation(alert, nextAlert, currentWeights);
  const analysis = generateWhyRankedAnalysis(alert, nextAlert, explanation, queue);

  const c = explanation.contributions;
  const exactSumEquation = `${c.severity.toFixed(2)} + ${c.assetImportance.toFixed(2)} + ${c.affectedUsers.toFixed(2)} + ${c.dataSensitivity.toFixed(2)} + ${c.attackConfidence.toFixed(2)} + ${c.businessImpact.toFixed(2)} = ${explanation.score.toFixed(2)}`;

  // Instantiate simulator for the "What If?" tab
  const simulator = new WhatIfSimulator(alert, queue, currentWeights);
  const simHtml = simulator.renderSimulatorView();

  const outrankSectionTitle = nextAlert ? `Why does this outrank #${nextRank}?` : `Queue Position Context`;

  return `
    <div class="drawer-header">
      <div class="drawer-title-group">
        <div class="drawer-badge-row">
          <span class="rank-pill">Rank #${currentRank}</span>
          <span class="tier-pill ${explanation.tier.badgeClass}">${explanation.tier.label}</span>
          <span class="incident-id-pill font-mono">${alert.id}</span>
        </div>
        <h2 class="drawer-alert-title">${alert.alertType}</h2>
        <p class="drawer-alert-desc">${alert.shortDescription}</p>
      </div>
      <div class="drawer-header-actions-col">
        <button class="drawer-close-btn" id="closeDrawerBtn" aria-label="Close Inspector">&times;</button>
        <button class="btn-generate-report-header" id="drawerGenerateReportBtn" data-alert-id="${alert.id}" title="Generate formal SOC Incident Report">
          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          Generate Report
        </button>
      </div>
    </div>

    <!-- Drawer Navigation Tabs (3 Tabs) -->
    <div class="drawer-tabs-bar">
      <button class="drawer-tab-btn active" id="tabBtn_breakdown" data-tab="breakdown">
        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
        </svg>
        Priority & Math
      </button>

      <button class="drawer-tab-btn tab-ai-glow" id="tabBtn_ai" data-tab="ai">
        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
        </svg>
        🤖 AI Explanation
      </button>

      <button class="drawer-tab-btn" id="tabBtn_whatif" data-tab="whatif">
        <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>
        </svg>
        🧪 "What If?" Sandbox
      </button>
    </div>

    <!-- TAB 1: Priority & Math Breakdown (Calculated by SignalRank) -->
    <div class="drawer-content tab-panel active" id="panel_breakdown">
      <!-- Attribution Badge -->
      <div class="attribution-banner engine-attr">
        <span class="attr-icon">🛡️</span>
        <span class="attr-text"><strong>Calculated by SignalRank Deterministic Core:</strong> Mathematical ground-truth priority scoring.</span>
      </div>

      <!-- Section 1: RISK SCORE Header Banner -->
      <div class="score-banner-card">
        <div class="score-dial-large">
          <div class="score-title-label">RISK SCORE</div>
          <div class="score-val-big">${explanation.score.toFixed(2)}</div>
          <div class="score-max-label">/ 100.00</div>
        </div>
        <div class="score-meta-col">
          <div class="meta-row">
            <span class="meta-label">Priority Tier:</span>
            <span class="meta-val tier-badge ${explanation.tier.badgeClass}">${explanation.tier.label}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">Target Asset:</span>
            <span class="meta-val font-mono">${alert.asset}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">Telemetry Source:</span>
            <span class="meta-val">${alert.source}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">MITRE ATT&CK:</span>
            <span class="meta-val badge-mitre">${alert.mitreTechnique || 'N/A'}</span>
          </div>
        </div>
      </div>

      <!-- Quick 6-Factor Telemetry Badges Grid -->
      <div class="drawer-factor-grid" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; margin-bottom: 1rem;">
        <div class="factor-summary-pill" style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 4px; padding: 0.4rem 0.6rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Severity</div>
          <div class="font-mono" style="font-weight: 700; color: #ef4444;">${explanation.factors.severity.toFixed(0)} <span style="font-size: 0.75rem; font-weight: normal; color: var(--text-muted);">/100</span></div>
        </div>
        <div class="factor-summary-pill" style="background: rgba(249, 115, 22, 0.08); border: 1px solid rgba(249, 115, 22, 0.3); border-radius: 4px; padding: 0.4rem 0.6rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Asset Importance</div>
          <div class="font-mono" style="font-weight: 700; color: #f97316;">${explanation.factors.assetImportance.toFixed(0)} <span style="font-size: 0.75rem; font-weight: normal; color: var(--text-muted);">/100</span></div>
        </div>
        <div class="factor-summary-pill" style="background: rgba(234, 179, 8, 0.08); border: 1px solid rgba(234, 179, 8, 0.3); border-radius: 4px; padding: 0.4rem 0.6rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Affected Users</div>
          <div class="font-mono" style="font-weight: 700; color: #eab308;">${explanation.factors.rawAffectedUsers.toLocaleString()} <span style="font-size: 0.75rem; font-weight: normal; color: var(--text-muted);">(${explanation.factors.affectedUsers.toFixed(0)} norm)</span></div>
        </div>
        <div class="factor-summary-pill" style="background: rgba(6, 182, 212, 0.08); border: 1px solid rgba(6, 182, 212, 0.3); border-radius: 4px; padding: 0.4rem 0.6rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Data Sensitivity</div>
          <div class="font-mono" style="font-weight: 700; color: #06b6d4;">${explanation.factors.dataSensitivity.toFixed(0)} <span style="font-size: 0.75rem; font-weight: normal; color: var(--text-muted);">/100</span></div>
        </div>
        <div class="factor-summary-pill" style="background: rgba(139, 92, 246, 0.08); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: 4px; padding: 0.4rem 0.6rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Attack Confidence</div>
          <div class="font-mono" style="font-weight: 700; color: #8b5cf6;">${explanation.factors.attackConfidence.toFixed(0)}%</div>
        </div>
        <div class="factor-summary-pill" style="background: rgba(236, 72, 153, 0.08); border: 1px solid rgba(236, 72, 153, 0.3); border-radius: 4px; padding: 0.4rem 0.6rem;">
          <div style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Business Impact</div>
          <div class="font-mono" style="font-weight: 700; color: #ec4899;">${explanation.factors.businessImpact.toFixed(0)} <span style="font-size: 0.75rem; font-weight: normal; color: var(--text-muted);">/100</span></div>
        </div>
      </div>

      <!-- Prominent "Why is this ranked here?" Action Banner Button -->
      <div class="why-ranked-banner-wrapper">
        <button class="btn-why-ranked-hero" id="btnWhyRankedHereHero" title="Inspect full deterministic scoring trace & comparison">
          <div class="btn-why-hero-left">
            <span class="btn-why-hero-radar">⚡</span>
            <div class="btn-why-hero-text">
              <span class="btn-why-hero-title">Why is this ranked here?</span>
              <span class="btn-why-hero-sub">Inspect exact deterministic formula & side-by-side comparison with #${nextAlert ? (nextAlert.rank || currentRank + 1) : 2}</span>
            </div>
          </div>
          <span class="btn-why-hero-badge">Decision Trace &darr;</span>
        </button>
      </div>

      <!-- Section 2: DECISION TRACE Section -->
      <div class="section-card decision-trace-card" id="decisionTraceSection">
        <div class="decision-trace-header-row">
          <h3 class="section-title">
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 7h6m0 10v-3m-3 3h.01M9 17h.01M9 14h.01M12 14h.01M15 11h.01M12 11h.01M9 11h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>
            </svg>
            Decision Trace
          </h3>
          <span class="deterministic-engine-badge">
            <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            Calculated by deterministic scoring engine
          </span>
        </div>

        <!-- 1. Current incident risk score -->
        <div class="decision-trace-score-summary">
          <div class="trace-score-item">
            <span class="trace-score-label">Current Incident Risk Score:</span>
            <span class="trace-score-value font-mono text-cyan">${explanation.score.toFixed(2)} / 100.00</span>
            <span class="tier-badge ${explanation.tier.badgeClass}">${explanation.tier.label}</span>
          </div>
          <div class="trace-rank-item">
            <span class="trace-rank-label">Queue Position:</span>
            <span class="trace-rank-value font-mono text-accent">Rank #${currentRank}</span>
          </div>
        </div>

        <!-- 2, 3, 4, 5. The six scoring factors (Normalized, Configured Weight, Mathematical Contribution) -->
        <div class="trace-factors-subtitle">Six Scoring Factors & Exact Contribution Calculations:</div>
        <div class="factor-multipliers-list">
          <div class="multiplier-row" style="border-left: 3px solid #ef4444;">
            <div class="multiplier-left">
              <span class="multiplier-name">Severity</span>
              <span class="factor-val-hint font-mono text-muted">(${explanation.factors.severity.toFixed(1)}/100)</span>
              <span class="multiplier-formula font-mono">${explanation.factors.severity.toFixed(1)} × ${(explanation.weights.severity * 100).toFixed(0)}%</span>
            </div>
            <div class="multiplier-result font-mono text-green">+${c.severity.toFixed(2)} pts</div>
          </div>

          <div class="multiplier-row" style="border-left: 3px solid #f97316;">
            <div class="multiplier-left">
              <span class="multiplier-name">Asset Importance</span>
              <span class="factor-val-hint font-mono text-muted">(${explanation.factors.assetImportance.toFixed(1)}/100)</span>
              <span class="multiplier-formula font-mono">${explanation.factors.assetImportance.toFixed(1)} × ${(explanation.weights.assetImportance * 100).toFixed(0)}%</span>
            </div>
            <div class="multiplier-result font-mono text-green">+${c.assetImportance.toFixed(2)} pts</div>
          </div>

          <div class="multiplier-row" style="border-left: 3px solid #eab308;">
            <div class="multiplier-left">
              <span class="multiplier-name">Affected Users <small class="text-muted">(Raw: ${explanation.factors.rawAffectedUsers.toLocaleString()})</small></span>
              <span class="factor-val-hint font-mono text-muted">(${explanation.factors.affectedUsers.toFixed(1)}/100)</span>
              <span class="multiplier-formula font-mono">${explanation.factors.affectedUsers.toFixed(1)} × ${(explanation.weights.affectedUsers * 100).toFixed(0)}%</span>
            </div>
            <div class="multiplier-result font-mono text-green">+${c.affectedUsers.toFixed(2)} pts</div>
          </div>

          <div class="multiplier-row" style="border-left: 3px solid #06b6d4;">
            <div class="multiplier-left">
              <span class="multiplier-name">Data Sensitivity</span>
              <span class="factor-val-hint font-mono text-muted">(${explanation.factors.dataSensitivity.toFixed(1)}/100)</span>
              <span class="multiplier-formula font-mono">${explanation.factors.dataSensitivity.toFixed(1)} × ${(explanation.weights.dataSensitivity * 100).toFixed(0)}%</span>
            </div>
            <div class="multiplier-result font-mono text-green">+${c.dataSensitivity.toFixed(2)} pts</div>
          </div>

          <div class="multiplier-row" style="border-left: 3px solid #8b5cf6;">
            <div class="multiplier-left">
              <span class="multiplier-name">Attack Confidence</span>
              <span class="factor-val-hint font-mono text-muted">(${explanation.factors.attackConfidence.toFixed(1)}/100)</span>
              <span class="multiplier-formula font-mono">${explanation.factors.attackConfidence.toFixed(1)} × ${(explanation.weights.attackConfidence * 100).toFixed(0)}%</span>
            </div>
            <div class="multiplier-result font-mono text-green">+${c.attackConfidence.toFixed(2)} pts</div>
          </div>

          <div class="multiplier-row" style="border-left: 3px solid #ec4899;">
            <div class="multiplier-left">
              <span class="multiplier-name">Business Impact</span>
              <span class="factor-val-hint font-mono text-muted">(${explanation.factors.businessImpact.toFixed(1)}/100)</span>
              <span class="multiplier-formula font-mono">${explanation.factors.businessImpact.toFixed(1)} × ${(explanation.weights.businessImpact * 100).toFixed(0)}%</span>
            </div>
            <div class="multiplier-result font-mono text-green">+${c.businessImpact.toFixed(2)} pts</div>
          </div>
        </div>

        <!-- 6. Final score calculation -->
        <div class="calculation-sum-box">
          <div class="sum-box-label">Final Deterministic Score Calculation:</div>
          <div class="sum-box-equation font-mono">
            ${exactSumEquation}
          </div>
        </div>

        <!-- Sub-section: "Why does this outrank #<nextRank>?" -->
        <div class="outrank-comparison-section">
          <div class="outrank-header-row">
            <h4 class="outrank-section-title">
              <span class="outrank-icon">⚡</span>
              ${outrankSectionTitle}
            </h4>
            <span class="deterministic-engine-badge">
              <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              Calculated by deterministic scoring engine
            </span>
          </div>

          <!-- Concise generated explanation strictly from actual scoring values -->
          <div class="outrank-explanation-callout">
            <p class="outrank-explanation-text">${comparison.explanation}</p>
          </div>

          ${nextAlert ? `
            <!-- Side-by-side factor comparison table -->
            <div class="side-by-side-table-wrapper">
              <table class="side-by-side-table">
                <thead>
                  <tr>
                    <th>Metric / Factor</th>
                    <th>#${currentRank} (${alert.id})</th>
                    <th>#${nextRank} (${nextAlert.id})</th>
                    <th>Score Contribution Impact</th>
                  </tr>
                </thead>
                <tbody>
                  <tr class="row-highlight font-mono">
                    <td class="col-metric font-sans"><strong>Risk Score</strong></td>
                    <td><strong class="text-cyan">${alert.score.toFixed(2)}</strong> <span class="tier-badge ${alert.tier?.badgeClass}">${alert.tier?.id}</span></td>
                    <td><strong class="text-secondary">${nextAlert.score.toFixed(2)}</strong> <span class="tier-badge ${nextAlert.tier?.badgeClass}">${nextAlert.tier?.id}</span></td>
                    <td><strong class="${alert.score >= nextAlert.score ? 'diff-pos' : 'diff-neg'}">+${(alert.score - nextAlert.score).toFixed(2)} net margin</strong></td>
                  </tr>
                  ${comparison.factorDeltas.map(f => {
                    let diffHtml = '';
                    if (f.delta > 0) {
                      diffHtml = `<span class="diff-pos font-mono">+${f.delta.toFixed(2)} pts for #${currentRank}</span>`;
                    } else if (f.delta < 0) {
                      diffHtml = `<span class="diff-neg font-mono">${f.delta.toFixed(2)} pts for #${nextRank}</span>`;
                    } else {
                      diffHtml = `<span class="diff-neutral font-mono">= 0.00 pts</span>`;
                    }
                    const rawA = f.key === 'affectedUsers' ? `<div class="raw-hint font-mono">${alert.factors.rawAffectedUsers.toLocaleString()} raw</div>` : '';
                    const rawB = f.key === 'affectedUsers' ? `<div class="raw-hint font-mono">${nextAlert.factors.rawAffectedUsers.toLocaleString()} raw</div>` : '';
                    return `
                      <tr>
                        <td class="col-metric">
                          <strong>${f.properLabel}</strong>
                          <span class="text-muted font-mono">(${f.weightPercent}%)</span>
                        </td>
                        <td class="font-mono">
                          <span>${f.valA.toFixed(1)}</span> <small class="text-muted">(+${f.contribA.toFixed(2)} pts)</small>
                          ${rawA}
                        </td>
                        <td class="font-mono">
                          <span>${f.valB.toFixed(1)}</span> <small class="text-muted">(+${f.contribB.toFixed(2)} pts)</small>
                          ${rawB}
                        </td>
                        <td>${diffHtml}</td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>

            <div class="compare-action-row">
              <button class="compare-next-btn" id="compareNextIncidentBtn" data-current-id="${alert.id}" data-next-id="${nextAlert.id}">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/>
                </svg>
                Open Full Modal Comparison (${alert.id} vs ${nextAlert.id})
              </button>
            </div>
          ` : `
            <div class="end-of-queue-box">
              <p class="text-muted">This incident is at the end of the active queue (Rank #${currentRank}). There is no lower-ranked incident to compare.</p>
            </div>
          `}
        </div>
      </div>

      <!-- Section 3: Driver Analysis -->
      <div class="section-card why-ranked-card">
        <h3 class="section-title">
          <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          Analytical Drivers & Risk Context
        </h3>

        <div class="analysis-block">
          <div class="analysis-block-title text-red">What makes it dangerous:</div>
          <p class="analysis-block-text">${analysis.dangerText}</p>
        </div>

        <div class="analysis-block">
          <div class="analysis-block-title text-orange">Factors that increased priority:</div>
          ${analysis.increasedFactors.length > 0 ? `
            <ul class="analysis-factor-list">
              ${analysis.increasedFactors.map(f => `
                <li><strong>${f.label}</strong>: Scored ${f.val}/100 (+${f.contrib} pts) &bull; <em>${f.reason}</em></li>
              `).join('')}
            </ul>
          ` : `<p class="analysis-block-text text-muted">No factors significantly above baseline thresholds.</p>`}
        </div>

        <div class="analysis-block">
          <div class="analysis-block-title text-cyan">Factors that reduced priority:</div>
          ${analysis.reducedFactors.length > 0 ? `
            <ul class="analysis-factor-list">
              ${analysis.reducedFactors.map(f => `
                <li><strong>${f.label}</strong>: Low score ${f.val}/100 (+${f.contrib} pts) &bull; <em>${f.reason}</em></li>
              `).join('')}
            </ul>
          ` : `<p class="analysis-block-text text-muted">All factors are elevated with no significant mitigating factors.</p>`}
        </div>
      </div>

      <!-- Quick AI Briefing Callout Banner -->
      <div class="quick-sim-banner ai-quick-banner" id="triggerAiTabBtn">
        <div class="quick-sim-left">
          <span class="sim-icon-glow">🤖</span>
          <div>
            <div class="quick-sim-title">Synthesize AI Security Briefing</div>
            <div class="quick-sim-sub">Generate natural-language executive summary & investigation actions.</div>
          </div>
        </div>
        <button class="quick-sim-action-btn ai-btn">Generate AI Report &rarr;</button>
      </div>

      <!-- Triage Lifecycle Actions -->
      <div class="section-card">
        <h3 class="section-title">SOC Triage Status</h3>
        <div class="status-btn-group" data-alert-id="${alert.id}">
          <button class="status-btn ${alert.status === 'New' ? 'active' : ''}" data-status="New">New</button>
          <button class="status-btn ${alert.status === 'Investigating' ? 'active' : ''}" data-status="Investigating">Investigating</button>
          <button class="status-btn ${alert.status === 'Contained' ? 'active' : ''}" data-status="Contained">Contained</button>
          <button class="status-btn ${alert.status === 'Resolved' ? 'active' : ''}" data-status="Resolved">Resolved</button>
          <button class="status-btn ${alert.status === 'Suppressed' ? 'active' : ''}" data-status="Suppressed">Suppressed</button>
        </div>
      </div>
    </div>

    <!-- TAB 2: AI Explanation Layer (Natural Language Synthesis) -->
    <div class="drawer-content tab-panel" id="panel_ai" style="display: none;">
      <!-- Attribution Badge -->
      <div class="attribution-banner ai-attr">
        <span class="attr-icon">🤖</span>
        <span class="attr-text"><strong>AI Explanation Layer (Natural-Language Synthesis):</strong> Synthesized strictly from structured scoring evidence. <em>AI never calculates or alters numerical risk scores.</em></span>
      </div>

      <div id="aiContentContainer">
        <!-- AI content, loading spinner, or error state rendered dynamically -->
      </div>
    </div>

    <!-- TAB 3: "What If?" Simulator Content -->
    <div class="drawer-content tab-panel" id="panel_whatif" style="display: none;">
      ${simHtml}
    </div>
  `;
}

/**
 * Renders the AI Explanation report into the AI container.
 */
export function renderAIReportHTML(report, alert) {
  return `
    <div class="ai-report-wrapper">
      <!-- AI Action Bar -->
      <div class="ai-action-bar">
        <div class="ai-status-pill">
          <span class="ai-status-dot"></span>
          ${report.isLiveApi ? 'Live Gemini 1.5 Synthesis' : 'SignalRank Grounded Analyst Engine'}
        </div>
        <div class="ai-btn-group">
          <button class="btn-ai-action" id="copyAiReportBtn" title="Copy report as Markdown">
            <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
            </svg>
            Copy Markdown
          </button>
          <button class="btn-ai-action" id="regenerateAiBtn" title="Regenerate explanation">
            <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
            Regenerate
          </button>
        </div>
      </div>

      <!-- 1. Executive Summary -->
      <div class="ai-section-card">
        <div class="ai-section-header text-purple">
          <span class="ai-num">1</span>
          Executive Summary
        </div>
        <p class="ai-text">${report.executiveSummary}</p>
      </div>

      <!-- 2. Priority Tier Justification -->
      <div class="ai-section-card">
        <div class="ai-section-header text-red">
          <span class="ai-num">2</span>
          Priority Tier Justification (${alert.tier?.label || 'Priority Tier'})
        </div>
        <p class="ai-text">${report.priorityJustification}</p>
      </div>

      <!-- 3. Most Important Contributing Factors -->
      <div class="ai-section-card">
        <div class="ai-section-header text-orange">
          <span class="ai-num">3</span>
          Most Important Contributing Factors
        </div>
        <div class="ai-text-formatted font-mono">${report.contributingFactorsAnalysis.replace(/\n/g, '<br>')}</div>
      </div>

      <!-- 4. Why it Outranks the Next Incident -->
      <div class="ai-section-card">
        <div class="ai-section-header text-cyan">
          <span class="ai-num">4</span>
          Why it Outranks the Next Incident
        </div>
        <p class="ai-text">${report.outranksNextExplanation}</p>
      </div>

      <!-- 5. Recommended Investigation Actions -->
      <div class="ai-section-card">
        <div class="ai-section-header text-green">
          <span class="ai-num">5</span>
          Recommended Investigation & Containment Actions
        </div>
        <ul class="ai-action-list">
          ${report.recommendedActions.map(action => `
            <li>${action}</li>
          `).join('')}
        </ul>
      </div>
    </div>
  `;
}

/**
 * Renders the AI loading state.
 */
export function renderAILoadingHTML() {
  return `
    <div class="ai-loading-container">
      <div class="ai-radar-spinner">
        <div class="radar-sweep"></div>
        <div class="radar-ping"></div>
      </div>
      <div class="ai-loading-title">Synthesizing AI Security Briefing...</div>
      <div class="ai-loading-sub">Analyzing structured scoring factors, MITRE techniques, and queue context.</div>
    </div>
  `;
}

/**
 * Renders the AI error state.
 */
export function renderAIErrorHTML(errMsg) {
  return `
    <div class="ai-error-container">
      <div class="ai-error-icon">⚠️</div>
      <div class="ai-error-title">AI Explanation Failed</div>
      <div class="ai-error-msg">${errMsg || 'Unable to generate explanation from structured telemetry.'}</div>
      <button class="btn-cyber primary" id="retryAiBtn">Retry Explanation</button>
    </div>
  `;
}

/**
 * Renders the Side-by-Side Incident Comparison Modal.
 */
export function renderComparisonModal(alertA, alertB, weights) {
  const calcA = calculateRiskScore(alertA, weights);
  const calcB = calculateRiskScore(alertB, weights);
  const tieTrace = explainTieBreak(alertA, alertB, weights);

  const factorKeys = ['severity', 'assetImportance', 'affectedUsers', 'dataSensitivity', 'attackConfidence', 'businessImpact'];

  const comparisons = factorKeys.map(k => {
    const def = FACTOR_DEFINITIONS[k];
    const valA = calcA.factors[k];
    const valB = calcB.factors[k];
    const contribA = calcA.contributions[k];
    const contribB = calcB.contributions[k];
    const contribDiff = contribA - contribB;

    let diffDisplay = '';
    if (Math.abs(contribDiff) < 0.01) {
      diffDisplay = `<span class="diff-neutral">= 0.00 pts</span>`;
    } else if (contribDiff > 0) {
      diffDisplay = `<span class="diff-pos font-mono">+${contribDiff.toFixed(2)} pts for ${alertA.id}</span>`;
    } else {
      diffDisplay = `<span class="diff-neg font-mono">${contribDiff.toFixed(2)} pts for ${alertB.id}</span>`;
    }

    return {
      key: k,
      label: def.label,
      weightPercent: Math.round(weights[k] * 100),
      valA: valA.toFixed(1),
      valB: valB.toFixed(1),
      rawA: k === 'affectedUsers' ? `${calcA.factors.rawAffectedUsers.toLocaleString()} users` : null,
      rawB: k === 'affectedUsers' ? `${calcB.factors.rawAffectedUsers.toLocaleString()} users` : null,
      contribA: contribA.toFixed(2),
      contribB: contribB.toFixed(2),
      diffDisplay,
      contribDiff
    };
  });

  comparisons.sort((a, b) => Math.abs(b.contribDiff) - Math.abs(a.contribDiff));
  const topDecidingFactor = comparisons[0];

  return `
    <div class="comparison-backdrop" id="comparisonBackdrop">
      <div class="comparison-modal">
        <div class="comparison-modal-header">
          <div class="comparison-header-col">
            <h2 class="comparison-modal-title">Side-by-Side Incident Comparison</h2>
            <p class="comparison-modal-subtitle">Direct mathematical delta analysis between adjacent queue positions.</p>
          </div>
          <button class="modal-close-btn" id="closeComparisonModalBtn">&times;</button>
        </div>

        <div class="comparison-modal-body">
          <div class="compare-hero-grid">
            <div class="compare-hero-card card-a">
              <div class="compare-rank-badge">Rank #${alertA.rank}</div>
              <div class="compare-id font-mono">${alertA.id}</div>
              <div class="compare-type">${alertA.alertType}</div>
              <div class="compare-asset font-mono">${alertA.asset}</div>
              <div class="compare-score-box">
                <span class="compare-score-label">Risk Score:</span>
                <span class="compare-score-num font-mono">${calcA.score.toFixed(2)}</span>
                <span class="tier-badge ${calcA.tier.badgeClass}">${calcA.tier.id}</span>
              </div>
            </div>

            <div class="compare-vs-badge">VS</div>

            <div class="compare-hero-card card-b">
              <div class="compare-rank-badge">Rank #${alertB.rank}</div>
              <div class="compare-id font-mono">${alertB.id}</div>
              <div class="compare-type">${alertB.alertType}</div>
              <div class="compare-asset font-mono">${alertB.asset}</div>
              <div class="compare-score-box">
                <span class="compare-score-label">Risk Score:</span>
                <span class="compare-score-num font-mono">${calcB.score.toFixed(2)}</span>
                <span class="tier-badge ${calcB.tier.badgeClass}">${calcB.tier.id}</span>
              </div>
            </div>
          </div>

          <div class="deciding-factor-banner">
            <div class="deciding-icon">⚡</div>
            <div class="deciding-content">
              <div class="deciding-title">Primary Ranking Differentiator:</div>
              <div class="deciding-text">
                ${Math.abs(calcA.score - calcB.score) > 0.001 
                  ? `<strong>${topDecidingFactor.label}</strong> is the largest factor separating these incidents, creating a <strong>+${topDecidingFactor.contribDiff.toFixed(2)} point difference</strong> in favor of ${alertA.id}.`
                  : `Both incidents share an identical score of ${calcA.score.toFixed(2)} pts. Tie broken at <strong>Rule Level ${tieTrace.level} (${tieTrace.rule})</strong>: ${tieTrace.explanation}`}
              </div>
            </div>
          </div>

          <div class="compare-table-wrapper">
            <table class="compare-table">
              <thead>
                <tr>
                  <th>Factor (Weight)</th>
                  <th>${alertA.id} (Rank #${alertA.rank})</th>
                  <th>${alertB.id} (Rank #${alertB.rank})</th>
                  <th>Point Contribution Impact</th>
                </tr>
              </thead>
              <tbody>
                ${comparisons.map(item => `
                  <tr>
                    <td class="compare-col-factor">
                      <strong>${item.label}</strong> <span class="text-muted font-mono">(${item.weightPercent}%)</span>
                    </td>
                    <td class="compare-col-val font-mono">
                      ${item.valA} <small class="text-muted">(${item.contribA} pts)</small>
                      ${item.rawA ? `<div class="raw-user-hint">${item.rawA}</div>` : ''}
                    </td>
                    <td class="compare-col-val font-mono">
                      ${item.valB} <small class="text-muted">(${item.contribB} pts)</small>
                      ${item.rawB ? `<div class="raw-user-hint">${item.rawB}</div>` : ''}
                    </td>
                    <td class="compare-col-diff">
                      ${item.diffDisplay}
                    </td>
                  </tr>
                `).join('')}
                <tr class="compare-total-row font-mono">
                  <td><strong>TOTAL RISK SCORE</strong></td>
                  <td><strong>${calcA.score.toFixed(2)}</strong></td>
                  <td><strong>${calcB.score.toFixed(2)}</strong></td>
                  <td><strong class="${calcA.score >= calcB.score ? 'diff-pos' : 'diff-neg'}">+${(calcA.score - calcB.score).toFixed(2)} net margin</strong></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="comparison-modal-footer">
          <button class="btn-cyber primary" id="closeComparisonModalBtn2">Close Comparison</button>
        </div>
      </div>
    </div>
  `;
}
