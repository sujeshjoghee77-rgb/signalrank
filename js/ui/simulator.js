/**
 * SignalRank - Interactive "What If?" Incident Simulation Engine
 * 
 * Non-destructive simulation allowing analysts to modify factors with sliders,
 * observe real-time score shifts, hypothetical priority queue re-ranking,
 * and automated factor sensitivity explanations.
 */

import { calculateRiskScore, normalizeAffectedUsers } from '../engine/scoring.js';
import { compareIncidents } from '../engine/comparator.js';
import { FACTOR_DEFINITIONS, DEFAULT_WEIGHTS } from '../engine/types.js';

export class WhatIfSimulator {
  constructor(alert, queue = [], weights = DEFAULT_WEIGHTS, onSimulationChanged = null) {
    this.originalAlert = alert || null;
    this.queue = queue || [];
    this.weights = weights || DEFAULT_WEIGHTS;
    this.onSimulationChanged = onSimulationChanged;

    const f = alert ? (alert.factors || alert) : {};
    const rawUsers = Number(f.rawAffectedUsers !== undefined ? f.rawAffectedUsers : (alert?.rawAffectedUsers !== undefined ? alert.rawAffectedUsers : 0));
    const normUsers = Number(f.affectedUsers !== undefined ? f.affectedUsers : (alert?.factors?.affectedUsers !== undefined ? alert.factors.affectedUsers : normalizeAffectedUsers(rawUsers)));

    this.baselineFactors = {
      severity: Number(f.severity !== undefined ? f.severity : (alert?.severity || 0)),
      assetImportance: Number(f.assetImportance !== undefined ? f.assetImportance : (alert?.assetImportance || 0)),
      rawAffectedUsers: rawUsers,
      affectedUsers: normUsers,
      dataSensitivity: Number(f.dataSensitivity !== undefined ? f.dataSensitivity : (alert?.dataSensitivity || 0)),
      attackConfidence: Number(f.attackConfidence !== undefined ? f.attackConfidence : (alert?.attackConfidence || 0)),
      businessImpact: Number(f.businessImpact !== undefined ? f.businessImpact : (alert?.businessImpact || 0))
    };

    this.baselineScore = alert?.score !== undefined ? Number(alert.score) : 0;
    this.baselineRank = alert?.rank !== undefined ? Number(alert.rank) : 1;

    // Simulated working state (cloned from baseline)
    this.simulatedFactors = { ...this.baselineFactors };
  }

  setFactor(factorKey, value) {
    if (factorKey === 'rawAffectedUsers') {
      const raw = Math.max(0, Number(value) || 0);
      this.simulatedFactors.rawAffectedUsers = raw;
      this.simulatedFactors.affectedUsers = normalizeAffectedUsers(raw);
    } else {
      this.simulatedFactors[factorKey] = Math.min(100, Math.max(0, Number(value) || 0));
    }

    const simResults = this.computeSimulation();
    if (typeof this.onSimulationChanged === 'function') {
      this.onSimulationChanged(simResults);
    }
    return simResults;
  }

  reset() {
    this.simulatedFactors = { ...this.baselineFactors };
    const simResults = this.computeSimulation();
    if (typeof this.onSimulationChanged === 'function') {
      this.onSimulationChanged(simResults);
    }
    return simResults;
  }

  computeSimulation() {
    if (!this.originalAlert) {
      return {
        baselineFactors: { ...this.baselineFactors },
        baselineScore: 0,
        simulatedScore: 0,
        scoreDelta: 0,
        baselineRank: 1,
        simulatedRank: 1,
        rankDelta: 0,
        simulatedTier: { id: 'P1', label: 'CRITICAL', badgeClass: 'tier-p1' },
        simulatedFactors: { ...this.simulatedFactors },
        factorDeltas: [],
        explanation: 'Incident data unavailable.',
        hasChanged: false
      };
    }

    // Construct hypothetical alert object
    const hypotheticalAlert = {
      ...this.originalAlert,
      severity: this.simulatedFactors.severity,
      assetImportance: this.simulatedFactors.assetImportance,
      rawAffectedUsers: this.simulatedFactors.rawAffectedUsers,
      affectedUsers: this.simulatedFactors.affectedUsers,
      dataSensitivity: this.simulatedFactors.dataSensitivity,
      attackConfidence: this.simulatedFactors.attackConfidence,
      businessImpact: this.simulatedFactors.businessImpact
    };

    // Calculate new risk score using the SAME deterministic scoring engine
    const simCalc = calculateRiskScore(hypotheticalAlert, this.weights);
    const simScore = simCalc.score;
    const simTier = simCalc.tier;

    // Calculate hypothetical position in the priority queue
    // Exclude the current alert and find where hypotheticalAlert ranks among all others
    const otherAlerts = this.queue.filter(a => a.id !== this.originalAlert.id);
    let hypotheticalRank = 1;

    for (const other of otherAlerts) {
      // compareIncidents returns negative if hypothetical precedes other
      const comp = compareIncidents(hypotheticalAlert, other, this.weights);
      if (comp > 0) {
        // Other is ranked higher than hypothetical
        hypotheticalRank++;
      }
    }

    // Compute factor point contributions & deltas
    const factorDeltas = [];
    const baselineCalc = calculateRiskScore(this.originalAlert, this.weights);

    const keys = ['severity', 'assetImportance', 'affectedUsers', 'dataSensitivity', 'attackConfidence', 'businessImpact'];
    keys.forEach(k => {
      const def = FACTOR_DEFINITIONS[k];
      const baseVal = this.baselineFactors[k];
      const simVal = this.simulatedFactors[k];
      const valDelta = simVal - baseVal;
      const baseContrib = baselineCalc.contributions[k];
      const simContrib = simCalc.contributions[k];
      const contribDelta = simContrib - baseContrib;

      factorDeltas.push({
        key: k,
        label: def.label,
        weightPercent: Math.round(this.weights[k] * 100),
        baseVal,
        simVal,
        valDelta,
        baseContrib,
        simContrib,
        contribDelta,
        absContribDelta: Math.abs(contribDelta)
      });
    });

    // Generate analytical explanation of the largest change
    const explanation = this.generateDeltaExplanation(
      factorDeltas,
      this.baselineScore,
      simScore,
      this.baselineRank,
      hypotheticalRank
    );

    const scoreDelta = Math.round((simScore - this.baselineScore) * 100) / 100;
    const rankDelta = this.baselineRank - hypotheticalRank; // positive = promoted to higher rank

    return {
      baselineFactors: { ...this.baselineFactors },
      baselineScore: this.baselineScore,
      simulatedScore: simScore,
      scoreDelta,
      baselineRank: this.baselineRank,
      simulatedRank: hypotheticalRank,
      rankDelta,
      simulatedTier: simTier,
      simulatedFactors: { ...this.simulatedFactors },
      factorDeltas,
      explanation,
      hasChanged: Math.abs(scoreDelta) > 0.001 || rankDelta !== 0
    };
  }

  generateDeltaExplanation(factorDeltas, baseScore, simScore, baseRank, simRank) {
    const changedFactors = factorDeltas.filter(f => Math.abs(f.valDelta) > 0.01);

    if (changedFactors.length === 0) {
      return "No factor changes simulated. Incident remains at original baseline values.";
    }

    // Sort by largest contribution change
    changedFactors.sort((a, b) => b.absContribDelta - a.absContribDelta);
    const topFactor = changedFactors[0];

    const scoreDiff = (simScore - baseScore).toFixed(2);
    const sign = (simScore >= baseScore) ? '+' : '';
    const verb = topFactor.valDelta > 0 ? 'Increasing' : 'Decreasing';
    const direction = simScore >= baseScore ? 'increased' : 'reduced';

    let rankPhrase = '';
    if (simRank < baseRank) {
      rankPhrase = `promoted this incident from #${baseRank} to #${simRank}`;
    } else if (simRank > baseRank) {
      rankPhrase = `dropped this incident from #${baseRank} to #${simRank}`;
    } else {
      rankPhrase = `kept its priority rank unchanged at #${baseRank}`;
    }

    if (changedFactors.length === 1) {
      return `${verb} ${topFactor.label} from ${topFactor.baseVal.toFixed(0)} to ${topFactor.simVal.toFixed(0)} ${direction} the score by ${sign}${scoreDiff} points and ${rankPhrase}.`;
    }

    // Multiple factors changed
    const topContribStr = `${topFactor.contribDelta >= 0 ? '+' : ''}${topFactor.contribDelta.toFixed(2)} pts`;
    return `${verb} ${topFactor.label} from ${topFactor.baseVal.toFixed(0)} to ${topFactor.simVal.toFixed(0)} (${topContribStr}) had the largest impact, changing the overall risk score by ${sign}${scoreDiff} points (from ${baseScore.toFixed(2)} to ${simScore.toFixed(2)}) and ${rankPhrase}.`;
  }

  renderSimulatorView() {
    if (!this.originalAlert) {
      return `
        <div class="simulation-panel-container">
          <div class="sandbox-disclaimer-banner">
            <div class="sandbox-icon">⚠️</div>
            <div class="sandbox-text">
              <strong>Incident data unavailable:</strong> No active incident selected for simulation.
            </div>
          </div>
        </div>
      `;
    }

    const sim = this.computeSimulation();
    const base = sim.baselineFactors || this.baselineFactors;
    const simF = sim.simulatedFactors || this.simulatedFactors;

    return `
      <div class="simulation-panel-container">
        <!-- Sandbox Banner -->
        <div class="sandbox-disclaimer-banner">
          <div class="sandbox-icon">🧪</div>
          <div class="sandbox-text">
            <strong>What-If Threat Scenario Sandbox:</strong> Sliders simulate hypothetical threat shifts in real time. Production incident records are <strong>not modified</strong>.
          </div>
        </div>

        <!-- Before / After Score & Rank Comparison Card -->
        <div class="simulation-comparison-grid">
          <!-- Current Baseline Card -->
          <div class="sim-card baseline-card">
            <div class="sim-card-header">
              <span class="sim-state-label">CURRENT (ORIGINAL)</span>
              <span class="rank-pill font-mono">Rank #${sim.baselineRank}</span>
            </div>
            <div class="sim-card-body">
              <div class="sim-score-row">
                <span class="sim-score-val font-mono">${sim.baselineScore.toFixed(2)}</span>
                <span class="sim-score-max font-mono">/ 100</span>
              </div>
              <div class="sim-tier-tag tier-p${this.originalAlert.tier?.id ? this.originalAlert.tier.id.slice(1) : '1'}">
                ${this.originalAlert.tier?.label || 'Baseline Tier'}
              </div>
            </div>
          </div>

          <!-- Arrow Divider -->
          <div class="sim-arrow-col">
            <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/>
            </svg>
          </div>

          <!-- Simulated What-If Card -->
          <div class="sim-card simulated-card ${sim.hasChanged ? 'active-change' : ''}">
            <div class="sim-card-header">
              <span class="sim-state-label">SIMULATION (WHAT-IF)</span>
              <span class="rank-pill font-mono ${sim.simulatedRank < sim.baselineRank ? 'rank-up' : sim.simulatedRank > sim.baselineRank ? 'rank-down' : ''}" id="simRankBadge">
                Rank #${sim.simulatedRank}
              </span>
            </div>
            <div class="sim-card-body">
              <div class="sim-score-row">
                <span class="sim-score-val font-mono text-cyan" id="simScoreVal">${sim.simulatedScore.toFixed(2)}</span>
                <span class="sim-score-max font-mono">/ 100</span>
              </div>
              <div class="sim-tier-tag ${sim.simulatedTier.badgeClass}" id="simTierTag">
                ${sim.simulatedTier.label}
              </div>
            </div>
          </div>
        </div>

        <!-- Delta Shifts Badge Row -->
        <div class="sim-deltas-row">
          <div class="delta-badge ${sim.scoreDelta > 0 ? 'delta-pos' : sim.scoreDelta < 0 ? 'delta-neg' : 'delta-zero'}" id="simScoreDeltaBadge">
            Score Delta: ${sim.scoreDelta >= 0 ? '+' : ''}${sim.scoreDelta.toFixed(2)} pts
          </div>
          <div class="delta-badge ${sim.rankDelta > 0 ? 'delta-pos' : sim.rankDelta < 0 ? 'delta-neg' : 'delta-zero'}" id="simRankDeltaBadge">
            Queue Position: ${sim.rankDelta > 0 ? `&uarr; Promoted +${sim.rankDelta} ranks` : sim.rankDelta < 0 ? `&darr; Dropped ${Math.abs(sim.rankDelta)} ranks` : 'No Rank Shift'}
          </div>
        </div>

        <!-- Dynamic Natural Language Driver Explanation Box -->
        <div class="sim-explanation-box">
          <div class="sim-explanation-title">
            <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/></svg>
            Impact Explanation:
          </div>
          <p class="sim-explanation-text" id="simExplanationText">${sim.explanation}</p>
        </div>

        <!-- Six Factor Simulation Sliders -->
        <div class="sim-sliders-section">
          <div class="sim-sliders-header">
            <span class="sim-sliders-title">Adjust Scoring Factors (Sliders):</span>
            <button class="btn-reset-sim" id="resetSimulationBtn">
              <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
              </svg>
              Reset Simulation
            </button>
          </div>

          <div class="sim-sliders-list">
            <!-- 1. Severity Slider -->
            <div class="sim-slider-card">
              <div class="sim-slider-meta">
                <div class="sim-slider-name-col">
                  <span class="factor-dot" style="background:#ef4444;"></span>
                  <strong>Severity</strong>
                  <span class="text-muted font-mono">(25% weight)</span>
                </div>
                <div class="sim-slider-val-box font-mono" id="simVal_severity">
                  ${simF.severity.toFixed(0)} <small>/ 100</small>
                </div>
              </div>
              <input type="range" class="sim-range-input" id="simSlider_severity" data-factor="severity" min="0" max="100" step="1" value="${simF.severity}" />
              <div class="sim-slider-footer">
                <span class="text-muted">Baseline: ${base.severity.toFixed(0)}</span>
                <span class="sim-contrib-preview font-mono text-green" id="simContrib_severity">+${(simF.severity * 0.25).toFixed(2)} pts</span>
              </div>
            </div>

            <!-- 2. Asset Importance Slider -->
            <div class="sim-slider-card">
              <div class="sim-slider-meta">
                <div class="sim-slider-name-col">
                  <span class="factor-dot" style="background:#f97316;"></span>
                  <strong>Asset Importance</strong>
                  <span class="text-muted font-mono">(15% weight)</span>
                </div>
                <div class="sim-slider-val-box font-mono" id="simVal_assetImportance">
                  ${simF.assetImportance.toFixed(0)} <small>/ 100</small>
                </div>
              </div>
              <input type="range" class="sim-range-input" id="simSlider_assetImportance" data-factor="assetImportance" min="0" max="100" step="1" value="${simF.assetImportance}" />
              <div class="sim-slider-footer">
                <span class="text-muted">Baseline: ${base.assetImportance.toFixed(0)}</span>
                <span class="sim-contrib-preview font-mono text-green" id="simContrib_assetImportance">+${(simF.assetImportance * 0.15).toFixed(2)} pts</span>
              </div>
            </div>

            <!-- 3. Affected Users Slider -->
            <div class="sim-slider-card">
              <div class="sim-slider-meta">
                <div class="sim-slider-name-col">
                  <span class="factor-dot" style="background:#eab308;"></span>
                  <strong>Affected Users</strong>
                  <span class="text-muted font-mono">(5% weight)</span>
                </div>
                <div class="sim-slider-val-box font-mono" id="simVal_rawAffectedUsers">
                  ${simF.rawAffectedUsers.toLocaleString()} users <small class="text-muted">(${simF.affectedUsers.toFixed(1)} pts)</small>
                </div>
              </div>
              <input type="range" class="sim-range-input" id="simSlider_rawAffectedUsers" data-factor="rawAffectedUsers" min="0" max="10000" step="50" value="${simF.rawAffectedUsers}" />
              <div class="sim-slider-footer">
                <span class="text-muted">Baseline: ${base.rawAffectedUsers.toLocaleString()} users</span>
                <span class="sim-contrib-preview font-mono text-green" id="simContrib_rawAffectedUsers">+${(simF.affectedUsers * 0.05).toFixed(2)} pts</span>
              </div>
            </div>

            <!-- 4. Data Sensitivity Slider -->
            <div class="sim-slider-card">
              <div class="sim-slider-meta">
                <div class="sim-slider-name-col">
                  <span class="factor-dot" style="background:#06b6d4;"></span>
                  <strong>Data Sensitivity</strong>
                  <span class="text-muted font-mono">(15% weight)</span>
                </div>
                <div class="sim-slider-val-box font-mono" id="simVal_dataSensitivity">
                  ${simF.dataSensitivity.toFixed(0)} <small>/ 100</small>
                </div>
              </div>
              <input type="range" class="sim-range-input" id="simSlider_dataSensitivity" data-factor="dataSensitivity" min="0" max="100" step="1" value="${simF.dataSensitivity}" />
              <div class="sim-slider-footer">
                <span class="text-muted">Baseline: ${base.dataSensitivity.toFixed(0)}</span>
                <span class="sim-contrib-preview font-mono text-green" id="simContrib_dataSensitivity">+${(simF.dataSensitivity * 0.15).toFixed(2)} pts</span>
              </div>
            </div>

            <!-- 5. Attack Confidence Slider -->
            <div class="sim-slider-card">
              <div class="sim-slider-meta">
                <div class="sim-slider-name-col">
                  <span class="factor-dot" style="background:#8b5cf6;"></span>
                  <strong>Attack Confidence</strong>
                  <span class="text-muted font-mono">(20% weight)</span>
                </div>
                <div class="sim-slider-val-box font-mono" id="simVal_attackConfidence">
                  ${simF.attackConfidence.toFixed(0)} <small>/ 100</small>
                </div>
              </div>
              <input type="range" class="sim-range-input" id="simSlider_attackConfidence" data-factor="attackConfidence" min="0" max="100" step="1" value="${simF.attackConfidence}" />
              <div class="sim-slider-footer">
                <span class="text-muted">Baseline: ${base.attackConfidence.toFixed(0)}</span>
                <span class="sim-contrib-preview font-mono text-green" id="simContrib_attackConfidence">+${(simF.attackConfidence * 0.20).toFixed(2)} pts</span>
              </div>
            </div>

            <!-- 6. Business Impact Slider -->
            <div class="sim-slider-card">
              <div class="sim-slider-meta">
                <div class="sim-slider-name-col">
                  <span class="factor-dot" style="background:#ec4899;"></span>
                  <strong>Business Impact</strong>
                  <span class="text-muted font-mono">(20% weight)</span>
                </div>
                <div class="sim-slider-val-box font-mono" id="simVal_businessImpact">
                  ${simF.businessImpact.toFixed(0)} <small>/ 100</small>
                </div>
              </div>
              <input type="range" class="sim-range-input" id="simSlider_businessImpact" data-factor="businessImpact" min="0" max="100" step="1" value="${simF.businessImpact}" />
              <div class="sim-slider-footer">
                <span class="text-muted">Baseline: ${base.businessImpact.toFixed(0)}</span>
                <span class="sim-contrib-preview font-mono text-green" id="simContrib_businessImpact">+${(simF.businessImpact * 0.20).toFixed(2)} pts</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  attachListeners(container) {
    const sliders = container.querySelectorAll('.sim-range-input');
    sliders.forEach(slider => {
      slider.addEventListener('input', (e) => {
        const factorKey = e.target.dataset.factor;
        const val = Number(e.target.value);
        const sim = this.setFactor(factorKey, val);
        this.updateSimulatedDOM(container, sim, factorKey);
      });
    });

    const resetBtn = container.querySelector('#resetSimulationBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        const sim = this.reset();
        sliders.forEach(s => {
          const k = s.dataset.factor;
          s.value = this.simulatedFactors[k];
        });
        this.updateSimulatedDOM(container, sim, 'all');
      });
    }
  }

  updateSimulatedDOM(container, sim, changedKey) {
    // 1. Update Score and Rank values
    const scoreVal = container.querySelector('#simScoreVal');
    if (scoreVal) scoreVal.textContent = sim.simulatedScore.toFixed(2);

    const rankBadge = container.querySelector('#simRankBadge');
    if (rankBadge) {
      rankBadge.textContent = `Rank #${sim.simulatedRank}`;
      rankBadge.className = `rank-pill font-mono ${sim.simulatedRank < sim.baselineRank ? 'rank-up' : sim.simulatedRank > sim.baselineRank ? 'rank-down' : ''}`;
    }

    const tierTag = container.querySelector('#simTierTag');
    if (tierTag) {
      tierTag.textContent = sim.simulatedTier.label;
      tierTag.className = `sim-tier-tag ${sim.simulatedTier.badgeClass}`;
    }

    // 2. Update Delta Badges
    const scoreDeltaBadge = container.querySelector('#simScoreDeltaBadge');
    if (scoreDeltaBadge) {
      scoreDeltaBadge.innerHTML = `Score Delta: ${sim.scoreDelta >= 0 ? '+' : ''}${sim.scoreDelta.toFixed(2)} pts`;
      scoreDeltaBadge.className = `delta-badge ${sim.scoreDelta > 0 ? 'delta-pos' : sim.scoreDelta < 0 ? 'delta-neg' : 'delta-zero'}`;
    }

    const rankDeltaBadge = container.querySelector('#simRankDeltaBadge');
    if (rankDeltaBadge) {
      rankDeltaBadge.innerHTML = `Queue Position: ${sim.rankDelta > 0 ? `&uarr; Promoted +${sim.rankDelta} ranks` : sim.rankDelta < 0 ? `&darr; Dropped ${Math.abs(sim.rankDelta)} ranks` : 'No Rank Shift'}`;
      rankDeltaBadge.className = `delta-badge ${sim.rankDelta > 0 ? 'delta-pos' : sim.rankDelta < 0 ? 'delta-neg' : 'delta-zero'}`;
    }

    // 3. Update Impact Explanation Text
    const expText = container.querySelector('#simExplanationText');
    if (expText) expText.textContent = sim.explanation;

    // 4. Update specific factor slider displays
    const keys = ['severity', 'assetImportance', 'rawAffectedUsers', 'dataSensitivity', 'attackConfidence', 'businessImpact'];
    keys.forEach(k => {
      const valBox = container.querySelector(`#simVal_${k}`);
      const contribBox = container.querySelector(`#simContrib_${k}`);
      
      if (k === 'rawAffectedUsers') {
        if (valBox) valBox.innerHTML = `${sim.simulatedFactors.rawAffectedUsers.toLocaleString()} users <small class="text-muted">(${sim.simulatedFactors.affectedUsers.toFixed(1)} pts)</small>`;
        if (contribBox) contribBox.textContent = `+${(sim.simulatedFactors.affectedUsers * 0.05).toFixed(2)} pts`;
      } else {
        if (valBox) valBox.innerHTML = `${sim.simulatedFactors[k].toFixed(0)} <small>/ 100</small>`;
        const weight = this.weights[k] || 0.2;
        if (contribBox) contribBox.textContent = `+${(sim.simulatedFactors[k] * weight).toFixed(2)} pts`;
      }
    });
  }
}
