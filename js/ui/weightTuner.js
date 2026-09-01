/**
 * SignalRank - Interactive Dynamic Weight Tuner & Preset Sensitivity Profiles
 * 
 * Allows SOC leads and security engineers to adjust factor weights in real time,
 * choose presets (Standard, Ransomware Surge, Data Breach/DLP, Zero-Trust High-Fidelity),
 * and observe immediate queue re-ranking with delta animations.
 */

import { DEFAULT_WEIGHTS, FACTOR_DEFINITIONS, PRESET_WEIGHT_PROFILES } from '../engine/types.js';
import { normalizeWeights } from '../engine/scoring.js';

export class WeightTuner {
  constructor(initialWeights = { ...DEFAULT_WEIGHTS }, onWeightsChanged = null) {
    this.currentWeights = { ...initialWeights };
    this.onWeightsChanged = onWeightsChanged;
    this.selectedProfileId = 'default';
  }

  getCurrentWeights() {
    return { ...this.currentWeights };
  }

  setWeights(newWeights) {
    this.currentWeights = normalizeWeights(newWeights);
    if (typeof this.onWeightsChanged === 'function') {
      this.onWeightsChanged(this.currentWeights);
    }
  }

  applyPreset(presetId) {
    const preset = PRESET_WEIGHT_PROFILES[presetId];
    if (preset) {
      this.selectedProfileId = presetId;
      this.setWeights(preset.weights);
    }
  }

  resetToDefault() {
    this.applyPreset('default');
  }

  renderTunerModal() {
    const keys = Object.keys(DEFAULT_WEIGHTS);
    const sum = Object.values(this.currentWeights).reduce((a, b) => a + b, 0);

    return `
      <div class="tuner-backdrop" id="tunerBackdrop">
        <div class="tuner-modal">
          <div class="tuner-header">
            <div class="tuner-title-col">
              <h2 class="tuner-title">Dynamic Scoring Weight Configuration</h2>
              <p class="tuner-desc">Customize factor influence or select industry threat profiles. Weights are deterministically normalized to sum to 100%.</p>
            </div>
            <button class="tuner-close-btn" id="closeTunerBtn">&times;</button>
          </div>

          <!-- Preset Profiles Selector -->
          <div class="presets-section">
            <label class="presets-label">Operational Threat Scenarios / Presets:</label>
            <div class="presets-grid">
              ${Object.values(PRESET_WEIGHT_PROFILES).map(p => `
                <div class="preset-card ${this.selectedProfileId === p.id ? 'active' : ''}" data-preset-id="${p.id}">
                  <div class="preset-name">${p.name}</div>
                  <div class="preset-desc">${p.description}</div>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- Interactive Factor Sliders -->
          <div class="sliders-section">
            <div class="sliders-header">
              <span class="sliders-title">Factor Weights Sensitivity:</span>
              <span class="weight-sum-indicator font-mono ${Math.abs(sum - 1.0) < 0.01 ? 'sum-ok' : 'sum-warn'}">
                Total Weight: ${(sum * 100).toFixed(0)}%
              </span>
            </div>

            <div class="sliders-list">
              ${keys.map(k => {
                const def = FACTOR_DEFINITIONS[k];
                const weightPercent = Math.round(this.currentWeights[k] * 100);
                return `
                  <div class="slider-group" data-factor-key="${k}">
                    <div class="slider-meta">
                      <div class="slider-label-row">
                        <span class="slider-color-dot" style="background-color: ${def.color};"></span>
                        <span class="slider-name">${def.label}</span>
                        <span class="slider-short font-mono">(${def.shortLabel})</span>
                      </div>
                      <div class="slider-val-box font-mono" id="weightVal_${k}">
                        ${weightPercent}%
                      </div>
                    </div>
                    <div class="slider-input-row">
                      <input 
                        type="range" 
                        class="weight-range-slider" 
                        id="slider_${k}" 
                        min="0" 
                        max="100" 
                        step="5" 
                        value="${weightPercent}"
                        data-factor="${k}"
                      />
                    </div>
                    <div class="slider-hint">${def.description}</div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>

          <div class="tuner-footer">
            <button class="tuner-btn secondary" id="resetWeightsBtn">Reset to Default Baseline</button>
            <button class="tuner-btn primary" id="applyWeightsBtn">Apply & Re-Rank Priority Queue</button>
          </div>
        </div>
      </div>
    `;
  }

  attachListeners(container, onUpdateCallback) {
    // Preset selection
    const presetCards = container.querySelectorAll('.preset-card');
    presetCards.forEach(card => {
      card.addEventListener('click', () => {
        const presetId = card.dataset.presetId;
        this.applyPreset(presetId);
        presetCards.forEach(c => c.classList.remove('active'));
        card.classList.add('active');

        // Update slider values in DOM
        Object.keys(this.currentWeights).forEach(k => {
          const slider = container.querySelector(`#slider_${k}`);
          const valBox = container.querySelector(`#weightVal_${k}`);
          const val = Math.round(this.currentWeights[k] * 100);
          if (slider) slider.value = val;
          if (valBox) valBox.textContent = `${val}%`;
        });

        if (onUpdateCallback) onUpdateCallback(this.currentWeights);
      });
    });

    // Slider inputs
    const sliders = container.querySelectorAll('.weight-range-slider');
    sliders.forEach(slider => {
      slider.addEventListener('input', (e) => {
        const factorKey = e.target.dataset.factor;
        const val = parseInt(e.target.value, 10);
        const valBox = container.querySelector(`#weightVal_${factorKey}`);
        if (valBox) valBox.textContent = `${val}%`;

        // Gather all slider values
        const rawWeights = {};
        sliders.forEach(s => {
          rawWeights[s.dataset.factor] = parseInt(s.value, 10) / 100;
        });

        this.selectedProfileId = 'custom';
        presetCards.forEach(c => c.classList.remove('active'));

        this.currentWeights = normalizeWeights(rawWeights);
        if (onUpdateCallback) onUpdateCallback(this.currentWeights);
      });
    });

    // Reset button
    const resetBtn = container.querySelector('#resetWeightsBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        this.resetToDefault();
        presetCards.forEach(c => {
          if (c.dataset.presetId === 'default') c.classList.add('active');
          else c.classList.remove('active');
        });
        Object.keys(this.currentWeights).forEach(k => {
          const slider = container.querySelector(`#slider_${k}`);
          const valBox = container.querySelector(`#weightVal_${k}`);
          const val = Math.round(this.currentWeights[k] * 100);
          if (slider) slider.value = val;
          if (valBox) valBox.textContent = `${val}%`;
        });
        if (onUpdateCallback) onUpdateCallback(this.currentWeights);
      });
    }
  }
}
