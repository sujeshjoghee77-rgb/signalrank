/**
 * SignalRank - Custom Security Alert Ingestion Modal Controller
 * 
 * Manages user workflow for:
 * 1. Pasting or uploading custom raw alerts (JSON, CSV, Log, Syslog, EML, Text).
 * 2. Parsing and displaying extracted metadata vs missing context.
 * 3. User verification and context enrichment for all 6 scoring factors.
 * 4. Deterministic scoring, queue integration, and adjacent rank visualization.
 */

import { parseRawSecurityInput } from '../engine/alertParser.js';
import { normalizeAffectedUsers } from '../engine/scoring.js';

export const SAMPLE_CUSTOM_ALERTS = [
  {
    name: 'CrowdStrike EDR Ransomware Detection (JSON)',
    content: JSON.stringify({
      event_type: 'Ransomware / Canary File Encryption',
      details: 'Cobalt Strike beacon executed vssadmin delete shadows on primary database server, encrypted 420 customer record files.',
      host: 'DB-PROD-FINANCE-01',
      severity: 92,
      confidence: 96,
      affected_users: 1200,
      source: 'Falcon EDR',
      command: 'cmd.exe /c vssadmin.exe delete shadows /all /quiet',
      ip: '185.220.101.5',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    }, null, 2)
  },
  {
    name: 'Splunk SIEM SQL Injection Alert (CEF Syslog)',
    content: 'CEF:0|Cloudflare|WAF|1.0|1001|SQL Injection Attack|9|src=194.26.29.112 dst=10.0.4.50 dhost=PAY-GATEWAY-PROD-API msg=Stacked SQL injection attempt exploiting public authentication endpoint cat=Exploit suser=service_auth user_count=3500'
  },
  {
    name: 'Suspicious Phishing Email (.EML format)',
    content: `From: "IT Support Helpdesk" <no-reply@security-verification-portal.com>
To: ceo-exec-office@corp.internal
Subject: URGENT: Executive SSO Password Expiration Verification Required
Date: Tue, 01 Sep 2026 12:45:00 UTC

Dear Executive,
Your corporate Microsoft 365 security session has expired. Click below to verify your corporate credentials immediately:
http://login-microsoft365-verify.auth-portal-secure.ru/token=89fbc4
Target: Executive Mailbox
Severity: High`
  },
  {
    name: 'Palo Alto Firewall Data Exfiltration (CSV)',
    content: `type,severity,asset,impacted_users,confidence,source,msg
Data Exfiltration Alert,88,STORAGE-S3-GATEWAY,500,90,Palo Alto NGFW,Unusual HTTPS data transfer of 85 GB to untrusted foreign IP 185.190.140.22`
  }
];

export class CustomAlertModal {
  constructor(app) {
    this.app = app;
    this.container = document.getElementById('customAlertModalContainer');
    this.currentStep = 1; // 1: Input, 2: Review/Enrich, 3: Success
    this.parsedResult = null;
    this.userFactors = {};
    this.userMeta = {};
    this.ingestedAlert = null;
  }

  open() {
    if (!this.container) return;
    this.currentStep = 1;
    this.parsedResult = null;
    this.userFactors = {};
    this.userMeta = {};
    this.ingestedAlert = null;
    this.container.style.display = 'block';
    this.render();
  }

  close() {
    if (!this.container) return;
    this.container.style.display = 'none';
    this.container.innerHTML = '';
  }

  render() {
    if (!this.container) return;

    if (this.currentStep === 1) {
      this.container.innerHTML = this.renderStep1Input();
      this.bindStep1Events();
    } else if (this.currentStep === 2) {
      this.container.innerHTML = this.renderStep2Review();
      this.bindStep2Events();
    } else if (this.currentStep === 3) {
      this.container.innerHTML = this.renderStep3Success();
      this.bindStep3Events();
    }
  }

  renderStep1Input() {
    return `
      <div class="custom-modal-backdrop" id="customAlertBackdrop">
        <div class="custom-modal-dialog">
          <div class="custom-modal-header">
            <div class="custom-modal-title-col">
              <div class="custom-step-indicator">
                <span class="step-badge active">Step 1: Input Telemetry</span>
                <span class="step-divider">&rarr;</span>
                <span class="step-badge">Step 2: Review & Context</span>
                <span class="step-divider">&rarr;</span>
                <span class="step-badge">Step 3: Deterministic Scoring</span>
              </div>
              <h2 class="custom-modal-title">+ Analyze My Security Alert</h2>
              <p class="custom-modal-subtitle">Paste raw security logs, SIEM events, emails, or upload an incident file for deterministic prioritization.</p>
            </div>
            <button class="modal-close-btn" id="closeCustomModalBtn">&times;</button>
          </div>

          <div class="custom-modal-body">
            <!-- Input Method Tabs -->
            <div class="custom-input-tabs">
              <button class="custom-tab-btn active" id="inputTab_paste">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
                1. Paste Raw Alert / Telemetry
              </button>
              <button class="custom-tab-btn" id="inputTab_upload">
                <svg width="15" height="15" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                2. Upload Alert File (.json, .log, .csv, .txt, .eml)
              </button>
            </div>

            <!-- Panel 1: Paste Input -->
            <div class="custom-tab-panel active" id="panel_paste">
              <!-- Quick Sample Templates -->
              <div class="sample-templates-bar">
                <span class="sample-label">Or load realistic sample telemetry:</span>
                <div class="sample-btns-group">
                  ${SAMPLE_CUSTOM_ALERTS.map((s, idx) => `
                    <button class="btn-sample-load" data-index="${idx}">${s.name}</button>
                  `).join('')}
                </div>
              </div>

              <div class="textarea-wrapper">
                <textarea id="rawAlertTextarea" class="custom-textarea font-mono" placeholder="Paste your raw security alert, SIEM JSON log, Syslog event, EML email header, EDR alert, or incident description here..."></textarea>
              </div>
            </div>

            <!-- Panel 2: File Upload Input -->
            <div class="custom-tab-panel" id="panel_upload" style="display: none;">
              <div class="file-dropzone" id="fileDropzone">
                <svg width="36" height="36" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                <div class="dropzone-text">
                  <strong>Click to select alert file</strong> or drag & drop here
                </div>
                <div class="dropzone-hint text-muted">
                  Supported formats: .json, .log, .txt, .csv, .eml (Processed safely in browser, not executed)
                </div>
                <input type="file" id="alertFileInput" accept=".json,.log,.txt,.csv,.eml,text/*" style="display: none;" />
              </div>
              <div id="fileUploadStatus" class="file-status-box" style="display: none;"></div>
            </div>

            <div id="parseErrorMessage" class="parse-error-banner" style="display: none;"></div>
          </div>

          <div class="custom-modal-footer">
            <button class="btn-cyber" id="cancelCustomModalBtn">Cancel</button>
            <button class="btn-cyber primary" id="btnAnalyzeRawInput">
              Analyze Alert Telemetry &rarr;
            </button>
          </div>
        </div>
      </div>
    `;
  }

  bindStep1Events() {
    const backdrop = this.container.querySelector('#customAlertBackdrop');
    const closeBtn = this.container.querySelector('#closeCustomModalBtn');
    const cancelBtn = this.container.querySelector('#cancelCustomModalBtn');
    const tabPaste = this.container.querySelector('#inputTab_paste');
    const tabUpload = this.container.querySelector('#inputTab_upload');
    const panelPaste = this.container.querySelector('#panel_paste');
    const panelUpload = this.container.querySelector('#panel_upload');
    const textarea = this.container.querySelector('#rawAlertTextarea');
    const analyzeBtn = this.container.querySelector('#btnAnalyzeRawInput');
    const dropzone = this.container.querySelector('#fileDropzone');
    const fileInput = this.container.querySelector('#alertFileInput');
    const fileStatus = this.container.querySelector('#fileUploadStatus');
    const errorBanner = this.container.querySelector('#parseErrorMessage');

    const handleClose = () => this.close();
    closeBtn?.addEventListener('click', handleClose);
    cancelBtn?.addEventListener('click', handleClose);
    backdrop?.addEventListener('click', (e) => { if (e.target === backdrop) handleClose(); });

    // Tab toggling
    tabPaste?.addEventListener('click', () => {
      tabPaste.classList.add('active');
      tabUpload.classList.remove('active');
      panelPaste.style.display = 'block';
      panelUpload.style.display = 'none';
    });

    tabUpload?.addEventListener('click', () => {
      tabUpload.classList.add('active');
      tabPaste.classList.remove('active');
      panelUpload.style.display = 'block';
      panelPaste.style.display = 'none';
    });

    // Sample loaders
    const sampleBtns = this.container.querySelectorAll('.btn-sample-load');
    sampleBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.index, 10);
        if (SAMPLE_CUSTOM_ALERTS[idx]) {
          textarea.value = SAMPLE_CUSTOM_ALERTS[idx].content;
          errorBanner.style.display = 'none';
        }
      });
    });

    // File dropzone click & drag
    dropzone?.addEventListener('click', () => fileInput.click());
    dropzone?.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-active');
    });
    dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('drag-active'));
    dropzone?.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-active');
      if (e.dataTransfer.files.length > 0) {
        handleFileRead(e.dataTransfer.files[0]);
      }
    });

    fileInput?.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        handleFileRead(e.target.files[0]);
      }
    });

    let uploadedFileContent = null;
    let uploadedFileName = '';

    const handleFileRead = (file) => {
      const reader = new FileReader();
      reader.onload = (event) => {
        uploadedFileContent = event.target.result;
        uploadedFileName = file.name;
        fileStatus.style.display = 'block';
        fileStatus.innerHTML = `
          <div class="file-loaded-badge">
            ✓ Loaded <strong>${file.name}</strong> (${(file.size / 1024).toFixed(1)} KB)
          </div>
        `;
        textarea.value = uploadedFileContent;
        errorBanner.style.display = 'none';
      };
      reader.onerror = () => {
        errorBanner.style.display = 'block';
        errorBanner.textContent = 'Error reading uploaded file. Please verify file permissions and text encoding.';
      };
      reader.readAsText(file);
    };

    // Analyze action
    analyzeBtn?.addEventListener('click', () => {
      const content = textarea.value.trim();
      if (!content) {
        errorBanner.style.display = 'block';
        errorBanner.textContent = 'Please paste security alert content or select a file to analyze.';
        return;
      }

      try {
        const parsed = parseRawSecurityInput(content, uploadedFileName);
        this.parsedResult = parsed;
        
        // Initialize working factors
        this.userFactors = {
          severity: parsed.factors.severity.value !== null ? parsed.factors.severity.value : 75,
          assetImportance: parsed.factors.assetImportance.value !== null ? parsed.factors.assetImportance.value : 80,
          rawAffectedUsers: parsed.factors.rawAffectedUsers.value !== null ? parsed.factors.rawAffectedUsers.value : 100,
          dataSensitivity: parsed.factors.dataSensitivity.value !== null ? parsed.factors.dataSensitivity.value : 70,
          attackConfidence: parsed.factors.attackConfidence.value !== null ? parsed.factors.attackConfidence.value : 85,
          businessImpact: parsed.factors.businessImpact.value !== null ? parsed.factors.businessImpact.value : 75
        };

        this.userMeta = {
          alertType: parsed.extractedFields.alertType,
          shortDescription: parsed.extractedFields.shortDescription,
          source: parsed.extractedFields.source,
          asset: parsed.extractedFields.asset,
          timestamp: parsed.extractedFields.timestamp,
          mitreTechnique: parsed.extractedFields.mitreTechnique,
          evidence: parsed.extractedFields.evidence
        };

        this.currentStep = 2;
        this.render();
      } catch (err) {
        errorBanner.style.display = 'block';
        errorBanner.textContent = `Parser error: ${err.message}`;
      }
    });
  }

  renderStep2Review() {
    const p = this.parsedResult;
    const f = this.userFactors;
    const m = this.userMeta;

    const renderFactorCard = (key, label, weightStr, maxVal = 100, isUsers = false) => {
      const orig = p.factors[key];
      const isExtracted = orig.source === 'EXTRACTED';
      const badgeClass = isExtracted ? 'badge-extracted' : 'badge-user-provided';
      const badgeText = isExtracted ? '✓ Extracted from alert' : '⚠️ User-provided context';

      const currentVal = f[key];

      return `
        <div class="review-factor-card ${isExtracted ? 'is-extracted' : 'is-user-context'}">
          <div class="review-factor-header">
            <div class="factor-title-col">
              <strong>${label}</strong>
              <span class="text-muted font-mono">(${weightStr} weight)</span>
            </div>
            <span class="source-tag ${badgeClass}">${badgeText}</span>
          </div>

          <div class="review-factor-controls">
            <input type="range" class="custom-range-input" id="factorSlider_${key}" data-factor="${key}" min="0" max="${maxVal}" step="${isUsers ? '10' : '1'}" value="${currentVal}" />
            <div class="factor-val-display font-mono" id="factorDisplay_${key}">
              ${isUsers ? `${currentVal.toLocaleString()} users` : `${currentVal} / 100`}
            </div>
          </div>
          ${!isExtracted ? `<div class="user-context-hint">Not specified in raw alert. Specify organizational context for accurate scoring.</div>` : ''}
        </div>
      `;
    };

    return `
      <div class="custom-modal-backdrop" id="customAlertBackdrop">
        <div class="custom-modal-dialog modal-large">
          <div class="custom-modal-header">
            <div class="custom-modal-title-col">
              <div class="custom-step-indicator">
                <span class="step-badge completed">✓ Step 1: Input</span>
                <span class="step-divider">&rarr;</span>
                <span class="step-badge active">Step 2: Review Extracted Alert</span>
                <span class="step-divider">&rarr;</span>
                <span class="step-badge">Step 3: Deterministic Scoring</span>
              </div>
              <h2 class="custom-modal-title">Review Extracted Alert & Context</h2>
              <p class="custom-modal-subtitle">Review extracted attributes. Missing dimensions are highlighted for your organizational input. No facts are fabricated.</p>
            </div>
            <button class="modal-close-btn" id="closeCustomModalBtn">&times;</button>
          </div>

          <div class="custom-modal-body">
            <!-- Top Extracted Metadata Card -->
            <div class="extracted-meta-grid">
              <div class="meta-field-group">
                <label class="meta-label">Alert Type / Threat Category:</label>
                <input type="text" id="metaInput_type" class="custom-input" value="${m.alertType || ''}" />
              </div>
              <div class="meta-field-group">
                <label class="meta-label">Target Asset / Hostname:</label>
                <input type="text" id="metaInput_asset" class="custom-input font-mono" value="${m.asset || ''}" />
              </div>
              <div class="meta-field-group">
                <label class="meta-label">Telemetry Source:</label>
                <input type="text" id="metaInput_source" class="custom-input" value="${m.source || ''}" />
              </div>
              <div class="meta-field-group full-width">
                <label class="meta-label">Incident Summary Description:</label>
                <textarea id="metaInput_desc" class="custom-input" rows="2">${m.shortDescription || ''}</textarea>
              </div>
            </div>

            <!-- Observed Evidence Box -->
            <div class="observed-evidence-card">
              <div class="evidence-header">
                <span class="evidence-icon">🔍</span>
                <strong>Observed Technical Evidence:</strong>
                <span class="text-muted font-mono">(${m.evidence.length} indicators strictly parsed from alert)</span>
              </div>
              <div class="evidence-tags-list">
                ${m.evidence.length > 0 
                  ? m.evidence.map(e => `<span class="evidence-pill font-mono">${e}</span>`).join('')
                  : `<span class="text-muted" style="font-style: italic;">Not provided in raw alert text.</span>`}
              </div>
            </div>

            <!-- Six Scoring Factors Grid with Source Attribution -->
            <div class="review-factors-section">
              <div class="section-title-row">
                <h3 class="section-title">The Six Scoring Factors (Verification & User Context):</h3>
                <span class="engine-badge font-mono">SignalRank Deterministic Core</span>
              </div>

              <div class="review-factors-grid">
                ${renderFactorCard('severity', 'Severity', '25%')}
                ${renderFactorCard('assetImportance', 'Asset Importance', '15%')}
                ${renderFactorCard('rawAffectedUsers', 'Affected Users', '5%', 10000, true)}
                ${renderFactorCard('dataSensitivity', 'Data Sensitivity', '15%')}
                ${renderFactorCard('attackConfidence', 'Attack Confidence', '20%')}
                ${renderFactorCard('businessImpact', 'Business Impact', '20%')}
              </div>
            </div>
          </div>

          <div class="custom-modal-footer">
            <button class="btn-cyber" id="btnBackToStep1">&larr; Back to Raw Input</button>
            <button class="btn-cyber primary" id="btnConfirmAndScore">
              ✓ Confirm & Ingest into Deterministic Engine &rarr;
            </button>
          </div>
        </div>
      </div>
    `;
  }

  bindStep2Events() {
    const backdrop = this.container.querySelector('#customAlertBackdrop');
    const closeBtn = this.container.querySelector('#closeCustomModalBtn');
    const backBtn = this.container.querySelector('#btnBackToStep1');
    const confirmBtn = this.container.querySelector('#btnConfirmAndScore');

    const handleClose = () => this.close();
    closeBtn?.addEventListener('click', handleClose);
    backdrop?.addEventListener('click', (e) => { if (e.target === backdrop) handleClose(); });

    backBtn?.addEventListener('click', () => {
      this.currentStep = 1;
      this.render();
    });

    // Bind factor sliders
    const keys = ['severity', 'assetImportance', 'rawAffectedUsers', 'dataSensitivity', 'attackConfidence', 'businessImpact'];
    keys.forEach(k => {
      const slider = this.container.querySelector(`#factorSlider_${k}`);
      const display = this.container.querySelector(`#factorDisplay_${k}`);
      slider?.addEventListener('input', (e) => {
        const val = Number(e.target.value);
        this.userFactors[k] = val;
        if (display) {
          display.textContent = (k === 'rawAffectedUsers') ? `${val.toLocaleString()} users` : `${val} / 100`;
        }
      });
    });

    // Bind metadata inputs
    const inputType = this.container.querySelector('#metaInput_type');
    const inputAsset = this.container.querySelector('#metaInput_asset');
    const inputSource = this.container.querySelector('#metaInput_source');
    const inputDesc = this.container.querySelector('#metaInput_desc');

    confirmBtn?.addEventListener('click', () => {
      this.userMeta.alertType = inputType ? inputType.value.trim() : this.userMeta.alertType;
      this.userMeta.asset = inputAsset ? inputAsset.value.trim() : this.userMeta.asset;
      this.userMeta.source = inputSource ? inputSource.value.trim() : this.userMeta.source;
      this.userMeta.shortDescription = inputDesc ? inputDesc.value.trim() : this.userMeta.shortDescription;

      // Ingest through App's deterministic engine
      const ingested = this.app.ingestCustomAlert({
        alertType: this.userMeta.alertType || 'Custom Security Alert',
        shortDescription: this.userMeta.shortDescription || 'User-supplied custom security telemetry.',
        source: this.userMeta.source || 'User-Supplied Telemetry',
        asset: this.userMeta.asset || 'Asset Unspecified',
        timestamp: this.userMeta.timestamp || new Date().toISOString(),
        mitreTechnique: this.userMeta.mitreTechnique || null,
        iocs: this.userMeta.evidence || [],
        rawContent: this.parsedResult.rawContent,
        severity: this.userFactors.severity,
        assetImportance: this.userFactors.assetImportance,
        rawAffectedUsers: this.userFactors.rawAffectedUsers,
        dataSensitivity: this.userFactors.dataSensitivity,
        attackConfidence: this.userFactors.attackConfidence,
        businessImpact: this.userFactors.businessImpact,
        fieldSources: this.parsedResult.factors
      });

      this.ingestedAlert = ingested;
      this.currentStep = 3;
      this.render();
    });
  }

  renderStep3Success() {
    const alert = this.ingestedAlert;
    if (!alert) return '';

    const queue = this.app.rankedQueue;
    const currentIndex = queue.findIndex(a => a.id === alert.id);
    const aboveAlert = (currentIndex > 0) ? queue[currentIndex - 1] : null;
    const belowAlert = (currentIndex < queue.length - 1) ? queue[currentIndex + 1] : null;

    return `
      <div class="custom-modal-backdrop" id="customAlertBackdrop">
        <div class="custom-modal-dialog">
          <div class="custom-modal-header success-header">
            <div class="custom-modal-title-col">
              <div class="custom-step-indicator">
                <span class="step-badge completed">✓ Step 1: Input</span>
                <span class="step-divider">&rarr;</span>
                <span class="step-badge completed">✓ Step 2: Context</span>
                <span class="step-divider">&rarr;</span>
                <span class="step-badge completed">✓ Step 3: Priority Ranking Active</span>
              </div>
              <h2 class="custom-modal-title success-title">Your alert has been analyzed.</h2>
              <p class="custom-modal-subtitle">Prioritized strictly by SignalRank deterministic engine. Entire queue re-ranked.</p>
            </div>
            <button class="modal-close-btn" id="closeCustomModalBtn">&times;</button>
          </div>

          <div class="custom-modal-body">
            <!-- Telemetry Score Card -->
            <div class="success-score-hero">
              <div class="success-score-box">
                <span class="stat-label">Calculated Risk Score:</span>
                <span class="score-val-big text-cyan font-mono">${alert.score.toFixed(2)}</span>
                <span class="tier-badge ${alert.tier.badgeClass}">${alert.tier.label}</span>
              </div>
              <div class="success-meta-box">
                <div class="success-meta-row">
                  <span class="meta-label">Assigned Incident ID:</span>
                  <span class="meta-val font-mono">${alert.id}</span>
                </div>
                <div class="success-meta-row">
                  <span class="meta-label">New Priority Rank:</span>
                  <span class="meta-val rank-highlight font-mono">Rank #${alert.rank}</span>
                </div>
                <div class="success-meta-row">
                  <span class="meta-label">Queue Size Shift:</span>
                  <span class="meta-val font-mono">${queue.length - 1} &rarr; ${queue.length} incidents</span>
                </div>
              </div>
            </div>

            <!-- Adjacent Priority Queue Visualizer -->
            <div class="adjacent-queue-card">
              <div class="adjacent-card-title">Priority Queue Position Context:</div>
              <div class="adjacent-rows-list">
                ${aboveAlert ? `
                  <div class="adjacent-row above-row font-mono">
                    <span class="adj-rank">#${aboveAlert.rank}</span>
                    <span class="adj-id">${aboveAlert.id}</span>
                    <span class="adj-type">${aboveAlert.alertType}</span>
                    <span class="adj-score">${aboveAlert.score.toFixed(2)}</span>
                  </div>
                ` : ''}
                
                <div class="adjacent-row target-custom-row font-mono">
                  <span class="adj-rank">#${alert.rank}</span>
                  <span class="adj-id">${alert.id}</span>
                  <span class="adj-type"><strong>${alert.alertType}</strong></span>
                  <span class="adj-score text-cyan font-mono">${alert.score.toFixed(2)}</span>
                  <span class="adj-tag">&larr; YOUR ALERT</span>
                </div>

                ${belowAlert ? `
                  <div class="adjacent-row below-row font-mono">
                    <span class="adj-rank">#${belowAlert.rank}</span>
                    <span class="adj-id">${belowAlert.id}</span>
                    <span class="adj-type">${belowAlert.alertType}</span>
                    <span class="adj-score">${belowAlert.score.toFixed(2)}</span>
                  </div>
                ` : ''}
              </div>
            </div>
          </div>

          <div class="custom-modal-footer">
            <button class="btn-cyber" id="btnViewInQueue">View in Priority Queue</button>
            <button class="btn-cyber" id="btnGenerateCustomReport">
              <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
              Generate Formal Report
            </button>
            <button class="btn-cyber primary" id="btnInspectDecisionTrace">
              Inspect Decision Trace &rarr;
            </button>
          </div>
        </div>
      </div>
    `;
  }

  bindStep3Events() {
    const backdrop = this.container.querySelector('#customAlertBackdrop');
    const closeBtn = this.container.querySelector('#closeCustomModalBtn');
    const viewQueueBtn = this.container.querySelector('#btnViewInQueue');
    const reportBtn = this.container.querySelector('#btnGenerateCustomReport');
    const traceBtn = this.container.querySelector('#btnInspectDecisionTrace');

    const handleClose = () => this.close();
    closeBtn?.addEventListener('click', handleClose);
    backdrop?.addEventListener('click', (e) => { if (e.target === backdrop) handleClose(); });

    viewQueueBtn?.addEventListener('click', () => {
      this.close();
      const row = document.querySelector(`.queue-row[data-alert-id="${this.ingestedAlert.id}"]`);
      if (row) {
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });

    reportBtn?.addEventListener('click', () => {
      const alertId = this.ingestedAlert.id;
      this.close();
      this.app.openIncidentReportModal(alertId);
    });

    traceBtn?.addEventListener('click', () => {
      const alertId = this.ingestedAlert.id;
      this.close();
      this.app.openExplainabilityDrawer(alertId);
      setTimeout(() => {
        const whyBtn = document.querySelector('#btnWhyRankedHereHero');
        if (whyBtn) whyBtn.click();
      }, 200);
    });
  }
}
