/**
 * SignalRank - SOC Priority Queue Application Controller
 * 
 * Orchestrates deterministic scoring, 10-column queue table rendering,
 * explainability inspector, side-by-side incident comparison,
 * dynamic weight tuner, and SOC operations.
 */

import { MOCK_SECURITY_ALERTS } from '../data/mockAlerts.js';
import { DEFAULT_WEIGHTS, FACTOR_DEFINITIONS, PRIORITY_TIERS } from '../engine/types.js';
import { rankAlerts, compareIncidents } from '../engine/comparator.js';
import { normalizeAffectedUsers, calculateRiskScore } from '../engine/scoring.js';
import { renderExplainabilityView, renderComparisonModal } from './explainability.js';
import { WeightTuner } from './weightTuner.js';
import { computeQueueAnalytics, renderAnalyticsSummaryBar } from './analytics.js';
import { CustomAlertModal } from './customAlertModal.js';

export class SignalRankApp {
  constructor() {
    this.rawAlerts = JSON.parse(JSON.stringify(MOCK_SECURITY_ALERTS));
    this.currentWeights = { ...DEFAULT_WEIGHTS };
    this.rankedQueue = [];
    this.previousRankMap = new Map();
    this.selectedAlert = null;
    this.customAlertCount = 0;
    this.filters = {
      search: '',
      tier: 'ALL',
      type: 'ALL',
      status: 'ALL',
      minSeverity: 0
    };

    this.weightTuner = new WeightTuner(this.currentWeights, (updatedWeights) => {
      this.handleWeightsUpdated(updatedWeights);
    });

    this.customAlertModal = new CustomAlertModal(this);

    this.init();
  }

  init() {
    this.recomputeQueue();
    this.bindEvents();
    this.render();
  }

  recomputeQueue() {
    // Record previous ranks for delta indicators
    this.previousRankMap.clear();
    this.rankedQueue.forEach(a => {
      this.previousRankMap.set(a.id, a.rank);
    });

    // Deterministically rank alerts
    this.rankedQueue = rankAlerts(this.rawAlerts, this.currentWeights);

    // If an alert is currently selected in the explainability drawer, update its reference
    if (this.selectedAlert) {
      this.selectedAlert = this.rankedQueue.find(a => a.id === this.selectedAlert.id) || null;
    }
  }

  handleWeightsUpdated(newWeights) {
    this.currentWeights = { ...newWeights };
    this.recomputeQueue();
    this.render();

    // If drawer is open, re-render drawer with updated weights
    if (this.selectedAlert) {
      this.openExplainabilityDrawer(this.selectedAlert.id);
    }
  }

  getFilteredQueue() {
    return this.rankedQueue.filter(alert => {
      // Search filter
      if (this.filters.search) {
        const q = this.filters.search.toLowerCase();
        const matchesSearch = 
          alert.id.toLowerCase().includes(q) ||
          alert.alertType.toLowerCase().includes(q) ||
          alert.asset.toLowerCase().includes(q) ||
          alert.source.toLowerCase().includes(q) ||
          alert.shortDescription.toLowerCase().includes(q) ||
          (alert.mitreTechnique && alert.mitreTechnique.toLowerCase().includes(q));
        if (!matchesSearch) return false;
      }

      // Tier filter
      if (this.filters.tier !== 'ALL') {
        if (alert.tier?.id !== this.filters.tier) return false;
      }

      // Type filter
      if (this.filters.type !== 'ALL') {
        if (alert.alertType !== this.filters.type) return false;
      }

      // Status filter
      if (this.filters.status !== 'ALL') {
        if (alert.status !== this.filters.status) return false;
      }

      // Min Severity
      if (this.filters.minSeverity > 0) {
        if (alert.factors.severity < this.filters.minSeverity) return false;
      }

      return true;
    });
  }

  updateAlertStatus(alertId, newStatus) {
    const target = this.rawAlerts.find(a => a.id === alertId);
    if (target) {
      target.status = newStatus;
      this.recomputeQueue();
      this.render();
      if (this.selectedAlert && this.selectedAlert.id === alertId) {
        this.openExplainabilityDrawer(alertId);
      }
    }
  }

  simulateLiveAlertIngestion() {
    const nextIndex = this.rawAlerts.length + 1;
    const alertId = `INC-2026-${String(nextIndex).padStart(4, '0')}`;
    
    const simulatedTypes = [
      {
        type: 'Ransomware / File Encryption',
        desc: 'Shadow copy deletion and encrypted canary files detected on cluster volume.',
        source: 'CrowdStrike Falcon EDR',
        asset: 'STORAGE-SAN-PROD-01',
        sev: 96, ast: 95, rawUsers: 3400, dat: 92, cnf: 95, imp: 96,
        mitre: 'T1486 - Data Encrypted for Impact'
      },
      {
        type: 'Zero-Day Exploit / RCE',
        desc: 'Unauthenticated RCE attempted against public customer API ingress gateway.',
        source: 'Cloudflare WAF & Snort',
        asset: 'API-INGRESS-GATEWAY-02',
        sev: 94, ast: 92, rawUsers: 5000, dat: 88, cnf: 90, imp: 90,
        mitre: 'T1190 - Exploit Public-Facing Application'
      },
      {
        type: 'Data Exfiltration / Cloud Sync',
        desc: 'Spike in outbound encrypted traffic (45 GB) to anonymous mega transfer service.',
        source: 'Palo Alto NGFW',
        asset: 'DB-BILLING-RECORDS-01',
        sev: 90, ast: 90, rawUsers: 7800, dat: 98, cnf: 92, imp: 92,
        mitre: 'T1048.003 - Exfiltration Over Web Service'
      }
    ];

    const pick = simulatedTypes[Math.floor(Math.random() * simulatedTypes.length)];
    const newAlert = {
      id: alertId,
      timestamp: new Date().toISOString(),
      alertType: pick.type,
      shortDescription: pick.desc,
      source: pick.source,
      severity: pick.sev,
      asset: pick.asset,
      assetImportance: pick.ast,
      rawAffectedUsers: pick.rawUsers,
      dataSensitivity: pick.dat,
      attackConfidence: pick.cnf,
      businessImpact: pick.imp,
      status: 'New',
      mitreTechnique: pick.mitre,
      isSimulatedNew: true,
      iocs: [`IP: ${Math.floor(Math.random()*200+20)}.${Math.floor(Math.random()*250)}.${Math.floor(Math.random()*250)}.42`, `Target: ${pick.asset}`]
    };

    this.rawAlerts.unshift(newAlert);
    this.recomputeQueue();
    this.render();

    this.showToast(`🚨 New High-Priority Alert Ingested: ${newAlert.id} ranked at #${this.rankedQueue.find(a => a.id === alertId)?.rank || 1}!`);
  }

  openCustomAlertModal() {
    this.customAlertModal.open();
  }

  ingestCustomAlert(customData) {
    this.customAlertCount++;
    const customId = `CUSTOM-2026-${String(this.customAlertCount).padStart(4, '0')}`;
    
    const newCustomAlert = {
      id: customId,
      timestamp: customData.timestamp || new Date().toISOString(),
      alertType: customData.alertType || 'Custom Security Alert',
      shortDescription: customData.shortDescription || 'User-supplied custom security telemetry.',
      source: customData.source || 'User-Supplied Security Alert',
      severity: customData.severity,
      asset: customData.asset || 'Asset Unspecified',
      assetImportance: customData.assetImportance,
      rawAffectedUsers: customData.rawAffectedUsers,
      dataSensitivity: customData.dataSensitivity,
      attackConfidence: customData.attackConfidence,
      businessImpact: customData.businessImpact,
      status: 'New',
      mitreTechnique: customData.mitreTechnique || null,
      iocs: customData.iocs || [],
      rawContent: customData.rawContent || '',
      isCustom: true,
      fieldSources: customData.fieldSources || null
    };

    // Add to current incident dataset
    this.rawAlerts.unshift(newCustomAlert);

    // Re-rank entire queue through existing deterministic engine
    this.recomputeQueue();
    this.render();

    const rankedCustom = this.rankedQueue.find(a => a.id === customId);
    this.showToast(`✓ Custom Alert Analyzed: ${customId} prioritized at Rank #${rankedCustom ? rankedCustom.rank : 1} (Risk Score: ${rankedCustom ? rankedCustom.score.toFixed(2) : 'N/A'})`);

    // Highlight newly added row in table
    setTimeout(() => {
      const row = document.querySelector(`.queue-row[data-alert-id="${customId}"]`);
      if (row) {
        row.classList.add('row-new-highlight');
        setTimeout(() => row.classList.remove('row-new-highlight'), 4500);
      }
    }, 100);

    return rankedCustom || newCustomAlert;
  }

  showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'soc-toast';
    toast.innerHTML = `
      <div class="toast-content">
        <span class="toast-icon">⚡</span>
        <span class="toast-msg">${message}</span>
      </div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 400);
    }, 4000);
  }

  exportQueue(format = 'csv') {
    if (format === 'json') {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(this.rankedQueue, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `SignalRank_Queue_${new Date().toISOString().slice(0, 10)}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } else {
      const headers = ['Rank', 'Incident ID', 'Alert Type', 'Short Description', 'Risk Score', 'Severity', 'Asset', 'Confidence', 'Raw Affected Users', 'Normalized Users', 'Priority Tier', 'Status', 'Timestamp', 'Source'];
      const rows = this.rankedQueue.map(a => [
        a.rank,
        a.id,
        `"${a.alertType.replace(/"/g, '""')}"`,
        `"${a.shortDescription.replace(/"/g, '""')}"`,
        a.score.toFixed(2),
        a.factors.severity,
        `"${a.asset}"`,
        a.factors.attackConfidence,
        a.factors.rawAffectedUsers,
        a.factors.affectedUsers.toFixed(2),
        a.tier.id,
        a.status,
        a.timestamp,
        `"${a.source}"`
      ]);

      const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement('a');
      link.setAttribute('href', encodedUri);
      link.setAttribute('download', `SignalRank_PriorityQueue_${new Date().toISOString().slice(0, 10)}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    }
  }

  openExplainabilityDrawer(alertId) {
    console.log(`[SignalRank] openExplainabilityDrawer called for: ${alertId}`);
    const alert = this.rankedQueue.find(a => a.id === alertId);
    if (!alert) {
      console.warn(`[SignalRank] Alert not found: ${alertId}`);
      return;
    }

    this.selectedAlert = alert;
    const drawerContainer = document.getElementById('explainabilityDrawer');
    if (!drawerContainer) {
      console.error(`[SignalRank] #explainabilityDrawer element not found in DOM`);
      return;
    }

    try {
      drawerContainer.innerHTML = renderExplainabilityView(alert, this.rankedQueue, this.currentWeights);
      drawerContainer.classList.add('open');
      console.log(`[SignalRank] Detail view opened for ${alert.id} (Rank #${alert.rank}, Score: ${alert.score.toFixed(2)})`);

      // Bind close button
      const closeBtn = drawerContainer.querySelector('#closeDrawerBtn');
      if (closeBtn) {
        closeBtn.addEventListener('click', () => {
          drawerContainer.classList.remove('open');
          this.selectedAlert = null;
        });
      }

      // Bind status buttons in drawer
      const statusBtns = drawerContainer.querySelectorAll('.status-btn');
      statusBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          const newStatus = btn.dataset.status;
          this.updateAlertStatus(alertId, newStatus);
        });
      });

      // Bind Drawer Tabs
      const tabBreakdown = drawerContainer.querySelector('#tabBtn_breakdown');
      const tabAi = drawerContainer.querySelector('#tabBtn_ai');
      const tabWhatIf = drawerContainer.querySelector('#tabBtn_whatif');
      const panelBreakdown = drawerContainer.querySelector('#panel_breakdown');
      const panelAi = drawerContainer.querySelector('#panel_ai');
      const panelWhatIf = drawerContainer.querySelector('#panel_whatif');
      const quickSimBtn = drawerContainer.querySelector('#triggerWhatIfTabBtn');
      const quickAiBtn = drawerContainer.querySelector('#triggerAiTabBtn');

      const nextAlert = (this.rankedQueue.findIndex(a => a.id === alert.id) < this.rankedQueue.length - 1) 
        ? this.rankedQueue[this.rankedQueue.findIndex(a => a.id === alert.id) + 1] 
        : null;

      const loadAIReport = async (forceRegenerate = false) => {
        const aiContainer = drawerContainer.querySelector('#aiContentContainer');
        if (!aiContainer) return;

        const { renderAILoadingHTML, renderAIReportHTML, renderAIErrorHTML } = await import('./explainability.js');
        const { aiService } = await import('../ai/aiService.js');
        const { calculateRiskScore } = await import('../engine/scoring.js');

        if (forceRegenerate) {
          const cacheKey = `${alert.id}_${alert.score}_${nextAlert ? nextAlert.id : 'none'}`;
          aiService.cachedExplanations.delete(cacheKey);
        }

        aiContainer.innerHTML = renderAILoadingHTML();

        try {
          const calc = calculateRiskScore(alert, this.currentWeights);
          const report = await aiService.generateExplanation(alert, nextAlert, calc, this.rankedQueue);
          aiContainer.innerHTML = renderAIReportHTML(report, alert);

          // Bind Copy Markdown button
          const copyBtn = aiContainer.querySelector('#copyAiReportBtn');
          if (copyBtn) {
            copyBtn.addEventListener('click', () => {
              const mdText = `# SignalRank AI Security Briefing: ${alert.id} (${alert.alertType})\n\n` +
                `**Target Asset:** ${alert.asset}\n` +
                `**Risk Score (Deterministic Engine):** ${alert.score.toFixed(2)}/100 (${alert.tier?.label})\n` +
                `**Queue Rank:** #${alert.rank}\n\n` +
                `## 1. Executive Summary\n${report.executiveSummary}\n\n` +
                `## 2. Priority Tier Justification\n${report.priorityJustification}\n\n` +
                `## 3. Most Important Contributing Factors\n${report.contributingFactorsAnalysis}\n\n` +
                `## 4. Why it Outranks Next Incident\n${report.outranksNextExplanation}\n\n` +
                `## 5. Recommended Investigation Actions\n${report.recommendedActions.join('\n')}\n\n` +
                `---\n*Report generated by SignalRank AI Layer. Numerical risk scores are strictly computed by SignalRank Deterministic Core.*`;

              navigator.clipboard.writeText(mdText).then(() => {
                copyBtn.innerHTML = `✓ Copied!`;
                setTimeout(() => {
                  copyBtn.innerHTML = `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg> Copy Markdown`;
                }, 2000);
              });
            });
          }

          // Bind Regenerate button
          const regenBtn = aiContainer.querySelector('#regenerateAiBtn');
          if (regenBtn) {
            regenBtn.addEventListener('click', () => loadAIReport(true));
          }

        } catch (err) {
          aiContainer.innerHTML = renderAIErrorHTML(err.message);
          const retryBtn = aiContainer.querySelector('#retryAiBtn');
          if (retryBtn) {
            retryBtn.addEventListener('click', () => loadAIReport(true));
          }
        }
      };

      const switchTab = (tabName) => {
        [tabBreakdown, tabAi, tabWhatIf].forEach(t => t?.classList.remove('active'));
        [panelBreakdown, panelAi, panelWhatIf].forEach(p => { if (p) p.style.display = 'none'; });

        if (tabName === 'whatif') {
          tabWhatIf?.classList.add('active');
          if (panelWhatIf) panelWhatIf.style.display = 'flex';
        } else if (tabName === 'ai') {
          tabAi?.classList.add('active');
          if (panelAi) panelAi.style.display = 'flex';
          loadAIReport();
        } else {
          tabBreakdown?.classList.add('active');
          if (panelBreakdown) panelBreakdown.style.display = 'flex';
        }
      };

      if (tabBreakdown) tabBreakdown.addEventListener('click', () => switchTab('breakdown'));
      if (tabAi) tabAi.addEventListener('click', () => switchTab('ai'));
      if (tabWhatIf) tabWhatIf.addEventListener('click', () => switchTab('whatif'));
      if (quickSimBtn) quickSimBtn.addEventListener('click', () => switchTab('whatif'));
      if (quickAiBtn) quickAiBtn.addEventListener('click', () => switchTab('ai'));

      // Bind "Why is this ranked here?" hero button
      const whyBtnHero = drawerContainer.querySelector('#btnWhyRankedHereHero');
      if (whyBtnHero) {
        whyBtnHero.addEventListener('click', () => {
          switchTab('breakdown');
          const section = drawerContainer.querySelector('#decisionTraceSection');
          if (section) {
            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            section.classList.remove('decision-trace-active');
            void section.offsetWidth; // trigger reflow
            section.classList.add('decision-trace-active');
            setTimeout(() => section.classList.remove('decision-trace-active'), 2500);
          }
        });
      }

      // Bind Compare with Next Incident button
      const compareBtn = drawerContainer.querySelector('#compareNextIncidentBtn');
      if (compareBtn) {
        compareBtn.addEventListener('click', () => {
          const currentId = compareBtn.dataset.currentId;
          const nextId = compareBtn.dataset.nextId;
          this.openComparisonModal(currentId, nextId);
        });
      }

      // Bind Drawer Report button
      const drawerReportBtn = drawerContainer.querySelector('#drawerGenerateReportBtn');
      if (drawerReportBtn) {
        drawerReportBtn.addEventListener('click', () => {
          this.openIncidentReportModal(alertId);
        });
      }
    } catch (err) {
      console.error('Error rendering explainability drawer:', err);
    }
  }

  async openIncidentReportModal(alertId) {
    const alert = this.rankedQueue.find(a => a.id === alertId);
    if (!alert) return;

    const alertIndex = this.rankedQueue.findIndex(a => a.id === alertId);
    const nextAlert = (alertIndex >= 0 && alertIndex < this.rankedQueue.length - 1) 
      ? this.rankedQueue[alertIndex + 1] 
      : null;

    const modalContainer = document.getElementById('reportModalContainer');
    if (modalContainer) {
      const { 
        renderReportModalHTML, 
        copyReportToClipboard, 
        downloadMarkdownReport, 
        printPDFReport 
      } = await import('./reportGenerator.js');

      modalContainer.innerHTML = renderReportModalHTML(alert, nextAlert, this.currentWeights);
      modalContainer.style.display = 'block';

      const closeBtn = modalContainer.querySelector('#closeReportModalBtn');
      const backdrop = modalContainer.querySelector('#reportBackdrop');
      const copyBtn = modalContainer.querySelector('#modalCopyReportBtn');
      const downloadMdBtn = modalContainer.querySelector('#modalDownloadMdBtn');
      const downloadPdfBtn = modalContainer.querySelector('#modalDownloadPdfBtn');

      const closeModal = () => {
        modalContainer.style.display = 'none';
        modalContainer.innerHTML = '';
      };

      if (closeBtn) closeBtn.addEventListener('click', closeModal);
      if (backdrop) {
        backdrop.addEventListener('click', (e) => {
          if (e.target === backdrop) closeModal();
        });
      }

      if (copyBtn) {
        copyBtn.addEventListener('click', async () => {
          await copyReportToClipboard(alert, nextAlert, this.currentWeights);
          copyBtn.innerHTML = `✓ Copied!`;
          setTimeout(() => {
            copyBtn.innerHTML = `
              <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
              </svg>
              Copy Report
            `;
          }, 2000);
        });
      }

      if (downloadMdBtn) {
        downloadMdBtn.addEventListener('click', () => {
          downloadMarkdownReport(alert, nextAlert, this.currentWeights);
        });
      }

      if (downloadPdfBtn) {
        downloadPdfBtn.addEventListener('click', () => {
          printPDFReport();
        });
      }
    }
  }

  openComparisonModal(alertIdA, alertIdB) {
    const alertA = this.rankedQueue.find(a => a.id === alertIdA);
    const alertB = this.rankedQueue.find(a => a.id === alertIdB);
    if (!alertA || !alertB) return;

    const modalContainer = document.getElementById('comparisonModalContainer');
    if (modalContainer) {
      modalContainer.innerHTML = renderComparisonModal(alertA, alertB, this.currentWeights);
      modalContainer.style.display = 'block';

      const closeBtn1 = modalContainer.querySelector('#closeComparisonModalBtn');
      const closeBtn2 = modalContainer.querySelector('#closeComparisonModalBtn2');
      const backdrop = modalContainer.querySelector('#comparisonBackdrop');

      const closeModal = () => {
        modalContainer.style.display = 'none';
        modalContainer.innerHTML = '';
      };

      if (closeBtn1) closeBtn1.addEventListener('click', closeModal);
      if (closeBtn2) closeBtn2.addEventListener('click', closeModal);
      if (backdrop) {
        backdrop.addEventListener('click', (e) => {
          if (e.target === backdrop) closeModal();
        });
      }
    }
  }

  bindEvents() {
    // Search input
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.filters.search = e.target.value.trim();
        this.renderQueueTable();
      });
    }

    // Tier filters
    const tierPills = document.querySelectorAll('.tier-filter-pill');
    tierPills.forEach(pill => {
      pill.addEventListener('click', () => {
        tierPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        this.filters.tier = pill.dataset.tier;
        this.renderQueueTable();
      });
    });

    // Alert type selector
    const typeSelect = document.getElementById('typeFilterSelect');
    if (typeSelect) {
      typeSelect.addEventListener('change', (e) => {
        this.filters.type = e.target.value;
        this.renderQueueTable();
      });
    }

    // Status selector
    const statusSelect = document.getElementById('statusFilterSelect');
    if (statusSelect) {
      statusSelect.addEventListener('change', (e) => {
        this.filters.status = e.target.value;
        this.renderQueueTable();
      });
    }

    // Analyze My Custom Alert button
    const analyzeMyAlertBtn = document.getElementById('analyzeMyAlertBtn');
    if (analyzeMyAlertBtn) {
      analyzeMyAlertBtn.addEventListener('click', () => {
        this.openCustomAlertModal();
      });
    }

    // Weight Tuner modal button
    const openTunerBtn = document.getElementById('openWeightTunerBtn');
    if (openTunerBtn) {
      openTunerBtn.addEventListener('click', () => {
        this.openWeightTuner();
      });
    }

    // Scoring Method button
    const openScoringMethodBtn = document.getElementById('openScoringMethodBtn');
    if (openScoringMethodBtn) {
      openScoringMethodBtn.addEventListener('click', () => {
        this.openScoringMethodModal();
      });
    }

    // Live ingestion simulator button
    const simulateAlertBtn = document.getElementById('simulateAlertBtn');
    if (simulateAlertBtn) {
      simulateAlertBtn.addEventListener('click', () => {
        this.simulateLiveAlertIngestion();
      });
    }

    // Export buttons
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
      exportCsvBtn.addEventListener('click', () => this.exportQueue('csv'));
    }
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    if (exportJsonBtn) {
      exportJsonBtn.addEventListener('click', () => this.exportQueue('json'));
    }

    // Delegated click handler on Queue Table Body
    const queueTableBody = document.getElementById('queueTableBody');
    if (queueTableBody) {
      queueTableBody.addEventListener('click', (e) => {
        const reportBtn = e.target.closest('.btn-row-report');
        if (reportBtn) {
          e.stopPropagation();
          const alertId = reportBtn.dataset.alertId;
          if (alertId) {
            this.openIncidentReportModal(alertId);
          }
          return;
        }

        if (e.target.closest('button, a, input, select, textarea')) {
          return;
        }

        const row = e.target.closest('.queue-row');
        if (row && row.dataset.alertId) {
          this.openExplainabilityDrawer(row.dataset.alertId);
        }
      });
    }
  }

  openScoringMethodModal() {
    const modalContainer = document.getElementById('scoringMethodModalContainer');
    if (!modalContainer) return;

    modalContainer.innerHTML = `
      <div class="report-backdrop" id="scoringMethodBackdrop">
        <div class="report-modal scoring-method-modal" style="max-width: 820px;">
          <div class="report-action-header screen-only">
            <div class="report-header-left">
              <span class="report-badge-pill font-mono">MATHEMATICAL ARCHITECTURE</span>
              <span class="report-id-text font-mono">SIGNALRANK SCORING MODEL</span>
            </div>
            <div class="report-header-actions">
              <button class="report-close-btn" id="closeScoringMethodBtn">&times;</button>
            </div>
          </div>

          <div class="report-document-body" style="padding: 1.5rem 2rem;">
            <div class="doc-header-block" style="border-bottom: 2px solid var(--accent-cyan); padding-bottom: 0.75rem; margin-bottom: 1.25rem;">
              <div class="doc-logo-title" style="font-size: 1.3rem;">
                <span class="doc-logo-bracket">[</span>SIGNALRANK DETERMINISTIC SCORING MODEL<span class="doc-logo-bracket">]</span>
              </div>
              <div class="doc-confidential-stamp">THE ALGORITHM DECIDES. AI EXPLAINS.</div>
            </div>

            <!-- Core Formula -->
            <div class="doc-section">
              <h3 class="doc-section-heading">1. DETERMINISTIC RISK FORMULA & CONFIGURED WEIGHTS</h3>
              <p class="doc-paragraph">
                The numerical score is calculated entirely by a deterministic scoring engine. AI/LLM never determines, modifies, or overrides the numerical score or ranking.
              </p>
              <div class="doc-table-wrapper" style="margin: 0.75rem 0;">
                <table class="doc-table">
                  <thead>
                    <tr>
                      <th>Factor</th>
                      <th>Configured Weight</th>
                      <th>Input Domain</th>
                      <th>Normalization Method</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><strong>Severity</strong></td>
                      <td class="font-mono text-cyan"><strong>25%</strong> (0.25)</td>
                      <td class="font-mono">0 – 100</td>
                      <td>Linear clamp [0, 100]</td>
                    </tr>
                    <tr>
                      <td><strong>Asset Importance</strong></td>
                      <td class="font-mono text-cyan"><strong>15%</strong> (0.15)</td>
                      <td class="font-mono">0 – 100</td>
                      <td>Linear clamp [0, 100] based on asset criticality</td>
                    </tr>
                    <tr>
                      <td><strong>Affected Users</strong></td>
                      <td class="font-mono text-cyan"><strong>5%</strong> (0.05)</td>
                      <td class="font-mono">0 – 50,000+</td>
                      <td>Logarithmic diminishing returns: <code>log10(N+1)/log10(10001)*100</code>, capped at 100 (Max +5.00 pts)</td>
                    </tr>
                    <tr>
                      <td><strong>Data Sensitivity</strong></td>
                      <td class="font-mono text-cyan"><strong>15%</strong> (0.15)</td>
                      <td class="font-mono">0 – 100</td>
                      <td>Linear clamp [0, 100] based on data classification</td>
                    </tr>
                    <tr>
                      <td><strong>Attack Confidence</strong></td>
                      <td class="font-mono text-cyan"><strong>20%</strong> (0.20)</td>
                      <td class="font-mono">0 – 100</td>
                      <td>Linear telemetry confidence [0, 100]</td>
                    </tr>
                    <tr>
                      <td><strong>Business Impact</strong></td>
                      <td class="font-mono text-cyan"><strong>20%</strong> (0.20)</td>
                      <td class="font-mono">0 – 100</td>
                      <td>Linear estimated business disruption [0, 100]</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div class="doc-calc-sum font-mono" style="background: rgba(14, 165, 233, 0.08); border-left: 3px solid #38bdf8; padding: 0.75rem 1rem;">
                <strong>Formula:</strong> <code>Risk Score = (0.25 × Severity) + (0.15 × Asset Importance) + (0.05 × Affected Users) + (0.15 × Data Sensitivity) + (0.20 × Attack Confidence) + (0.20 × Business Impact)</code>
              </div>
            </div>

            <!-- Normalization & Diminishing Returns -->
            <div class="doc-section">
              <h3 class="doc-section-heading">2. NORMALIZATION & DIMINISHING RETURNS</h3>
              <p class="doc-paragraph">
                All 6 factors are normalized to a consistent <strong>0 – 100 scale</strong> before weighting. The final risk score is strictly bounded within <strong>0.00 – 100.00</strong>.
              </p>
              <p class="doc-paragraph">
                The <strong>Affected Users</strong> factor uses a logarithmic curve so that large user counts do not overwhelm the core indicators of technical severity, exploit confidence, or asset criticality.
              </p>
            </div>

            <!-- Deterministic 6-Level Tie-Breaking -->
            <div class="doc-section">
              <h3 class="doc-section-heading">3. STRICT 6-LEVEL DETERMINISTIC TIE-BREAKING HIERARCHY</h3>
              <p class="doc-paragraph">
                When two incidents share equal composite risk scores, the queue applies a strict, deterministic tie-breaking hierarchy with zero randomness or AI intervention:
              </p>
              <ol class="doc-list" style="padding-left: 1.25rem;">
                <li><strong>Level 1 — Risk Score (Descending):</strong> Highest composite risk score investigated first.</li>
                <li><strong>Level 2 — Attack Confidence (Descending):</strong> Higher technical certainty and multi-sensor validation takes priority.</li>
                <li><strong>Level 3 — Business Impact (Descending):</strong> Higher potential organizational damage takes priority.</li>
                <li><strong>Level 4 — Data Sensitivity (Descending):</strong> Higher data classification (e.g. customer PII, keys) takes priority.</li>
                <li><strong>Level 5 — Asset Importance (Descending):</strong> Mission-critical infrastructure takes priority.</li>
                <li><strong>Level 6 — Timestamp (Ascending / FIFO):</strong> Older uninvestigated alerts receive FIFO priority.</li>
                <li><strong>Fallback — Incident ID (Ascending):</strong> Strictly reproducible total ordering.</li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    `;
    modalContainer.style.display = 'block';

    const closeBtn = modalContainer.querySelector('#closeScoringMethodBtn');
    const backdrop = modalContainer.querySelector('#scoringMethodBackdrop');
    const closeModal = () => {
      modalContainer.style.display = 'none';
      modalContainer.innerHTML = '';
    };

    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (backdrop) {
      backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) closeModal();
      });
    }
  }

  openWeightTuner() {
    const modalContainer = document.getElementById('tunerModalContainer');
    if (modalContainer) {
      modalContainer.innerHTML = this.weightTuner.renderTunerModal();
      modalContainer.style.display = 'block';

      this.weightTuner.attachListeners(modalContainer, (newWeights) => {
        this.handleWeightsUpdated(newWeights);
      });

      const closeBtn = modalContainer.querySelector('#closeTunerBtn');
      const backdrop = modalContainer.querySelector('#tunerBackdrop');
      const applyBtn = modalContainer.querySelector('#applyWeightsBtn');

      const closeModal = () => {
        modalContainer.style.display = 'none';
        modalContainer.innerHTML = '';
      };

      if (closeBtn) closeBtn.addEventListener('click', closeModal);
      if (applyBtn) applyBtn.addEventListener('click', closeModal);
      if (backdrop) {
        backdrop.addEventListener('click', (e) => {
          if (e.target === backdrop) closeModal();
        });
      }
    }
  }

  render() {
    this.renderAnalyticsBar();
    this.populateTypeFilterOptions();
    this.renderQueueTable();
  }

  renderAnalyticsBar() {
    const bar = document.getElementById('analyticsBarContainer');
    if (bar) {
      const analytics = computeQueueAnalytics(this.rankedQueue);
      bar.innerHTML = renderAnalyticsSummaryBar(analytics);
    }
  }

  populateTypeFilterOptions() {
    const select = document.getElementById('typeFilterSelect');
    if (select && select.options.length <= 1) {
      const types = Array.from(new Set(this.rawAlerts.map(a => a.alertType))).sort();
      types.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        select.appendChild(opt);
      });
    }
  }

  renderQueueTable() {
    const container = document.getElementById('queueTableBody');
    const countBadge = document.getElementById('filteredCountBadge');
    if (!container) return;

    const filtered = this.getFilteredQueue();
    if (countBadge) {
      countBadge.textContent = `Showing ${filtered.length} of ${this.rankedQueue.length} incidents`;
    }

    if (filtered.length === 0) {
      container.innerHTML = `
        <tr>
          <td colspan="10" class="empty-state-cell">
            <div class="empty-state">
              <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
              <p>No incidents match the active filters or search query.</p>
              <button class="reset-filter-btn" id="resetFiltersBtn">Reset All Filters</button>
            </div>
          </td>
        </tr>
      `;
      const resetBtn = container.querySelector('#resetFiltersBtn');
      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          this.filters = { search: '', tier: 'ALL', type: 'ALL', status: 'ALL', minSeverity: 0 };
          const searchInput = document.getElementById('searchInput');
          if (searchInput) searchInput.value = '';
          const tierPills = document.querySelectorAll('.tier-filter-pill');
          tierPills.forEach(p => p.classList.toggle('active', p.dataset.tier === 'ALL'));
          const typeSelect = document.getElementById('typeFilterSelect');
          if (typeSelect) typeSelect.value = 'ALL';
          const statusSelect = document.getElementById('statusFilterSelect');
          if (statusSelect) statusSelect.value = 'ALL';
          this.renderQueueTable();
        });
      }
      return;
    }

    // Render the exact 10 columns:
    // 1. Rank, 2. Incident ID, 3. Alert Type, 4. Short Description, 5. Risk Score,
    // 6. Severity, 7. Asset, 8. Confidence, 9. Affected Users, 10. Priority
    container.innerHTML = filtered.map(alert => {
      const prevRank = this.previousRankMap.get(alert.id);
      let rankDeltaHtml = '';
      if (prevRank && prevRank !== alert.rank) {
        const delta = prevRank - alert.rank;
        if (delta > 0) {
          rankDeltaHtml = `<span class="rank-delta up">&uarr;+${delta}</span>`;
        } else {
          rankDeltaHtml = `<span class="rank-delta down">&darr;${delta}</span>`;
        }
      }

      const factors = alert.factors;
      const tier = alert.tier;

      // Visual Severity Indicator (Badge + numerical meter)
      const sevVal = factors.severity;
      const sevTier = sevVal >= 80 ? 'CRITICAL' : sevVal >= 60 ? 'HIGH' : sevVal >= 40 ? 'MEDIUM' : 'LOW';
      const sevClass = sevVal >= 80 ? 'sev-crit' : sevVal >= 60 ? 'sev-high' : sevVal >= 40 ? 'sev-med' : 'sev-low';

      // Confidence indicator
      const cnfVal = factors.attackConfidence;
      const cnfClass = cnfVal >= 80 ? 'cnf-high' : cnfVal >= 50 ? 'cnf-med' : 'cnf-low';

      return `
        <tr class="queue-row tier-${tier.id.toLowerCase()} ${alert.isSimulatedNew ? 'row-new-highlight' : ''}" data-alert-id="${alert.id}">
          <!-- 1. Rank -->
          <td class="col-rank">
            <div class="rank-display">
              <span class="rank-num ${alert.rank <= 3 ? 'top-rank' : ''}">#${alert.rank}</span>
              ${rankDeltaHtml}
            </div>
          </td>

          <!-- 2. Incident ID -->
          <td class="col-id">
            <div class="id-cell-group">
              <div class="id-row-header">
                <span class="incident-id font-mono">${alert.id}</span>
                <button class="btn-row-report" data-alert-id="${alert.id}" title="Generate Incident Report">
                  <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                  </svg>
                  Report
                </button>
              </div>
              <span class="incident-time" title="${alert.timestamp}">${this.formatRelativeTime(alert.timestamp)}</span>
            </div>
          </td>

          <!-- 3. Alert Type -->
          <td class="col-type">
            <span class="alert-type-title">${alert.alertType}</span>
          </td>

          <!-- 4. Short Description -->
          <td class="col-desc">
            <div class="desc-cell-group">
              <div class="alert-short-desc">${alert.shortDescription}</div>
              ${alert.mitreTechnique ? `<span class="mitre-tag">${alert.mitreTechnique}</span>` : ''}
            </div>
          </td>

          <!-- 5. Risk Score -->
          <td class="col-score">
            <div class="score-display-cell">
              <span class="score-digit font-mono">${alert.score.toFixed(2)}</span>
              <div class="score-micro-bar">
                <div class="score-micro-fill ${tier.badgeClass}" style="width: ${alert.score}%;"></div>
              </div>
            </div>
          </td>

          <!-- 6. Severity -->
          <td class="col-sev">
            <div class="sev-cell-box ${sevClass}">
              <span class="sev-tag font-mono">${sevVal.toFixed(0)}</span>
              <span class="sev-label">${sevTier}</span>
            </div>
          </td>

          <!-- 7. Asset -->
          <td class="col-asset">
            <div class="asset-cell-group">
              <span class="asset-name font-mono">${alert.asset}</span>
              <span class="source-telemetry">${alert.source}</span>
            </div>
          </td>

          <!-- 8. Confidence -->
          <td class="col-cnf">
            <div class="cnf-cell-box ${cnfClass} font-mono">
              ${cnfVal.toFixed(0)}%
            </div>
          </td>

          <!-- 9. Affected Users -->
          <td class="col-users">
            <div class="users-cell-group">
              <span class="users-raw font-mono">${factors.rawAffectedUsers.toLocaleString()}</span>
              <span class="users-norm font-mono text-muted">${factors.affectedUsers.toFixed(1)} pts</span>
            </div>
          </td>

          <!-- 10. Priority -->
          <td class="col-priority">
            <div class="priority-cell">
              <span class="tier-badge ${tier.badgeClass}">
                <span class="tier-dot"></span>
                ${tier.label}
              </span>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach click listeners to rows
    const rows = container.querySelectorAll('.queue-row');
    rows.forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.closest('button, a, input, select, textarea')) {
          return;
        }
        const alertId = row.dataset.alertId;
        if (alertId) {
          this.openExplainabilityDrawer(alertId);
        }
      });
    });

    // Attach click listeners to row report buttons
    const reportBtns = container.querySelectorAll('.btn-row-report');
    reportBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        const alertId = btn.dataset.alertId;
        if (alertId) {
          this.openIncidentReportModal(alertId);
        }
      });
    });
  }

  formatRelativeTime(isoString) {
    if (!isoString) return 'just now';
    const date = new Date(isoString);
    const now = new Date();
    const diffSec = Math.floor((now - date) / 1000);

    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  }
}
