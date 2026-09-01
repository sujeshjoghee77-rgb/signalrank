/**
 * SignalRank - Automated SOC Incident Report Generator
 * 
 * Automatically generates formal, audit-ready cybersecurity incident reports
 * with mathematical precision, grounded evidence, and zero fabrication.
 * Supports Copy to Clipboard, Markdown Download, and PDF Export.
 */

import { calculateRiskScore } from '../engine/scoring.js';
import { explainTieBreak, generateRankComparisonExplanation } from '../engine/comparator.js';
import { FACTOR_DEFINITIONS } from '../engine/types.js';

/**
 * Pure JavaScript synchronous SHA-256 implementation (FIPS 180-2 compliant).
 * Generates an authentic 64-character hexadecimal SHA-256 hash.
 */
export function computeSHA256Hex(ascii) {
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

/**
 * Builds the structured report object from incident data and scoring calculations.
 */
export function buildIncidentReportData(alert, nextAlert, weights) {
  const calc = calculateRiskScore(alert, weights);
  const c = calc.contributions;
  const f = calc.factors;
  const currentRank = alert.rank || 'N/A';

  // 1. Executive Summary (Zero-Fabrication, Evidence-Grounded)
  let execSummary = `This incident received a deterministic Risk Score of ${calc.score.toFixed(2)}/100 and is ranked #${currentRank} (${calc.tier.label}) in the current priority queue. `;
  execSummary += `Telemetry from ${alert.source || 'telemetry sensors'} recorded ${alert.alertType} associated with target asset ${alert.asset || 'target asset'}. `;
  if (f.rawAffectedUsers > 0) {
    execSummary += `Recorded user footprint is ${f.rawAffectedUsers.toLocaleString()} accounts with a Data Sensitivity rating of ${f.dataSensitivity.toFixed(0)}/100. `;
  }
  execSummary += `Priority is driven deterministically by Severity (${f.severity.toFixed(0)}/100), Attack Confidence (${f.attackConfidence.toFixed(0)}%), and Business Impact (${f.businessImpact.toFixed(0)}/100).`;

  // 2. Why This Incident Matters
  let whyItMatters = '';
  if (f.severity >= 85 && f.assetImportance >= 85) {
    whyItMatters = `Priority is driven by elevated technical Severity (${f.severity.toFixed(1)}/100, +${c.severity.toFixed(2)} pts) targeting critical infrastructure asset ${alert.asset} (Asset Importance: ${f.assetImportance.toFixed(1)}/100, +${c.assetImportance.toFixed(2)} pts).`;
  } else if (f.dataSensitivity >= 80) {
    whyItMatters = `Priority is driven by elevated Data Sensitivity score (${f.dataSensitivity.toFixed(0)}/100, +${c.dataSensitivity.toFixed(2)} pts) for data processed on ${alert.asset}.`;
  } else if (f.rawAffectedUsers >= 1000) {
    whyItMatters = `Priority is driven by organizational blast radius encompassing ${f.rawAffectedUsers.toLocaleString()} recorded user accounts (Normalized User Score: ${f.affectedUsers.toFixed(1)}/100, +${c.affectedUsers.toFixed(2)} pts).`;
  } else if (calc.tier.id === 'P1') {
    whyItMatters = `Priority is driven by critical composite risk score (${calc.score.toFixed(2)}/100) exceeding the tier-1 threshold (≥ 80.00).`;
  } else {
    whyItMatters = `Priority reflects standard telemetry evaluation (Risk Score: ${calc.score.toFixed(2)}/100) scheduled for investigation according to queue position.`;
  }

  // 3. Scoring Breakdown
  const factorRows = [
    { label: 'Severity', val: f.severity.toFixed(1), wt: Math.round(calc.weights.severity * 100), pts: c.severity.toFixed(2) },
    { label: 'Asset Importance', val: f.assetImportance.toFixed(1), wt: Math.round(calc.weights.assetImportance * 100), pts: c.assetImportance.toFixed(2) },
    { label: `Affected Users (Raw: ${f.rawAffectedUsers.toLocaleString()})`, val: f.affectedUsers.toFixed(1), wt: Math.round(calc.weights.affectedUsers * 100), pts: c.affectedUsers.toFixed(2) },
    { label: 'Data Sensitivity', val: f.dataSensitivity.toFixed(1), wt: Math.round(calc.weights.dataSensitivity * 100), pts: c.dataSensitivity.toFixed(2) },
    { label: 'Attack Confidence', val: f.attackConfidence.toFixed(1), wt: Math.round(calc.weights.attackConfidence * 100), pts: c.attackConfidence.toFixed(2) },
    { label: 'Business Impact', val: f.businessImpact.toFixed(1), wt: Math.round(calc.weights.businessImpact * 100), pts: c.businessImpact.toFixed(2) }
  ];

  const exactSum = `${c.severity.toFixed(2)} + ${c.assetImportance.toFixed(2)} + ${c.affectedUsers.toFixed(2)} + ${c.dataSensitivity.toFixed(2)} + ${c.attackConfidence.toFixed(2)} + ${c.businessImpact.toFixed(2)} = ${calc.score.toFixed(2)} / 100.00`;

  // 4. Ranking Justification
  const comparison = generateRankComparisonExplanation(alert, nextAlert, weights);
  const rankingJustification = comparison.explanation;

  // 5. Indicators / Evidence (Zero Fabrication - Strictly what is in alert)
  const evidence = [];
  const isCustomAlert = alert.isCustom || (alert.id && alert.id.startsWith('CUSTOM-'));
  if (isCustomAlert) {
    evidence.push(`• Source: User-supplied alert (${alert.source || 'User-Provided Security Telemetry'})`);
  } else {
    evidence.push(`• Telemetry Source: ${alert.source || 'Unavailable in telemetry'}`);
  }
  evidence.push(`• Target Asset: ${alert.asset || 'Unavailable in telemetry'}`);
  if (alert.mitreTechnique) {
    evidence.push(`• MITRE ATT&CK Technique: ${alert.mitreTechnique}`);
  }
  if (alert.iocs && Array.isArray(alert.iocs) && alert.iocs.length > 0) {
    alert.iocs.forEach(ioc => evidence.push(`• Observed IOC: ${ioc}`));
  } else if (alert.rawDetails) {
    evidence.push(`• Observed Details: ${alert.rawDetails}`);
  } else {
    evidence.push(`• Indicators of Compromise (IOCs): No additional host/network IOCs recorded in active telemetry payload.`);
  }

  // 6. Recommended Action (Framed clearly as recommendations, not autonomous execution)
  const actions = [];
  const alertTypeLower = (alert.alertType || '').toLowerCase();
  actions.push(`1. Containment Evaluation: Evaluate immediate isolation or network containment of ${alert.asset || 'target host'} according to organizational incident-response playbooks.`);

  if (alertTypeLower.includes('ransomware') || alertTypeLower.includes('encrypt')) {
    actions.push(`2. Backup Status Verification: Verify immutable offline status of backup snapshots and volume shadow copies.`);
    actions.push(`3. Process Forensics: Capture memory image and inspect suspect process trees on ${alert.asset || 'target host'}.`);
  } else if (alertTypeLower.includes('exfiltration') || alertTypeLower.includes('data')) {
    actions.push(`2. Perimeter Egress Verification: Evaluate perimeter firewall or proxy rules for recorded egress destinations.`);
    actions.push(`3. Data Impact Analysis: Review file access and database query audit logs on ${alert.asset || 'target host'}.`);
  } else if (alertTypeLower.includes('phishing') || alertTypeLower.includes('credential')) {
    actions.push(`2. Identity Verification: Consider session revocation and credential reset for potentially impacted accounts.`);
    actions.push(`3. Mail Gateway Sweep: Search mail gateway logs for matching subject lines or sender indicators.`);
  } else if (alertTypeLower.includes('privilege') || alertTypeLower.includes('lsass')) {
    actions.push(`2. Kerberos & Auth Audit: Review Active Directory Kerberos ticket requests (Event ID 4769) and privileged session logs.`);
    actions.push(`3. Account Access Review: Audit administrative logon events recorded on ${alert.asset || 'target host'}.`);
  } else {
    actions.push(`2. SIEM Correlation: Query SIEM logs for related authentication or network events from ${alert.asset || 'target host'}.`);
    actions.push(`3. Threat Hunting: Search enterprise endpoint telemetry for matching hashes or command-line indicators.`);
  }
  actions.push(`4. Case Documentation: Log all investigation findings and deterministic SignalRank scoring evidence in SOC case management.`);

  // Compute authentic SHA-256 verification hash of report payload
  const reportPayloadString = `${alert.id}|${alert.timestamp}|${alert.alertType}|${alert.asset}|${calc.score.toFixed(2)}|${currentRank}|${exactSum}`;
  const verificationHash = computeSHA256Hex(reportPayloadString);

  return {
    incidentId: alert.id,
    timestamp: alert.timestamp,
    alertType: alert.alertType,
    severity: `${f.severity.toFixed(0)} / 100`,
    riskScore: `${calc.score.toFixed(2)} / 100.00`,
    priorityRank: `Rank #${currentRank} (${calc.tier.label})`,
    priorityTier: calc.tier.label,
    targetAsset: alert.asset || 'N/A',
    execSummary,
    whyItMatters,
    factorRows,
    exactSum,
    rankingJustification,
    evidence,
    actions,
    verificationHash
  };
}

/**
 * Formats the incident report into a clean, markdown string.
 */
export function generateMarkdownReport(alert, nextAlert, weights) {
  const data = buildIncidentReportData(alert, nextAlert, weights);

  return `# SIGNALRANK INCIDENT REPORT

**Incident ID:** ${data.incidentId}  
**Timestamp:** ${data.timestamp}  
**Alert Type:** ${data.alertType}  
**Severity:** ${data.severity}  
**Risk Score:** ${data.riskScore}  
**Priority Rank:** ${data.priorityRank}  
**Target Asset:** ${data.targetAsset}  

---

## EXECUTIVE SUMMARY

${data.execSummary}

---

## WHY THIS INCIDENT MATTERS

${data.whyItMatters}

---

## SCORING BREAKDOWN

${data.factorRows.map(r => `- **${r.label}:** ${r.val} / 100 (${r.wt}% weight) &rarr; +${r.pts} pts`).join('\n')}

**Deterministic Arithmetic Sum:**  
\`${data.exactSum}\`

---

## RANKING JUSTIFICATION

${data.rankingJustification}

---

## INDICATORS / EVIDENCE

${data.evidence.join('\n')}

---

## RECOMMENDED ACTION

${data.actions.join('\n')}

---
*Report generated automatically by SignalRank Incident Prioritization Core.*  
*Scoring Engine: Deterministic (Numerical scores & ranks calculated without LLM)*  
*Verification Hash (SHA-256): \`${data.verificationHash}\`*
`;
}

/**
 * Copies the formatted markdown report to the user's clipboard.
 */
export async function copyReportToClipboard(alert, nextAlert, weights) {
  const md = generateMarkdownReport(alert, nextAlert, weights);
  await navigator.clipboard.writeText(md);
}

/**
 * Triggers a browser download of the report as a Markdown (.md) file.
 */
export function downloadMarkdownReport(alert, nextAlert, weights) {
  const md = generateMarkdownReport(alert, nextAlert, weights);
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `SignalRank_Report_${alert.id}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Triggers clean PDF generation / printing formatted specifically for PDF output.
 */
export function printPDFReport() {
  window.print();
}

/**
 * Renders the modal HTML for the Incident Report Viewer.
 */
export function renderReportModalHTML(alert, nextAlert, weights) {
  const data = buildIncidentReportData(alert, nextAlert, weights);

  return `
    <div class="report-backdrop" id="reportBackdrop">
      <div class="report-modal">
        <!-- Report Action Header Bar (Screen Only) -->
        <div class="report-action-header screen-only">
          <div class="report-header-left">
            <span class="report-badge-pill font-mono">SOC INCIDENT BRIEFING</span>
            <span class="report-id-text font-mono">${data.incidentId}</span>
          </div>
          <div class="report-header-actions">
            <button class="btn-report-action" id="modalCopyReportBtn">
              <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
              </svg>
              Copy Report
            </button>
            <button class="btn-report-action" id="modalDownloadMdBtn">
              <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
              </svg>
              Download Markdown (.md)
            </button>
            <button class="btn-report-action btn-pdf" id="modalDownloadPdfBtn">
              <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/>
              </svg>
              Download / Print PDF
            </button>
            <button class="report-close-btn" id="closeReportModalBtn">&times;</button>
          </div>
        </div>

        <!-- Printable Document Body -->
        <div class="report-document-body" id="printableReportDocument">
          <!-- Document Header -->
          <div class="doc-header-block">
            <div class="doc-logo-title">
              <span class="doc-logo-bracket">[</span>SIGNALRANK INCIDENT REPORT<span class="doc-logo-bracket">]</span>
            </div>
            <div class="doc-confidential-stamp">CONFIDENTIAL // SOC INTERNAL USE ONLY</div>
          </div>

          <!-- Metadata Grid -->
          <div class="doc-meta-grid">
            <div class="doc-meta-item">
              <span class="doc-meta-k">Incident ID:</span>
              <span class="doc-meta-v font-mono">${data.incidentId}</span>
            </div>
            <div class="doc-meta-item">
              <span class="doc-meta-k">Timestamp:</span>
              <span class="doc-meta-v font-mono">${data.timestamp}</span>
            </div>
            <div class="doc-meta-item">
              <span class="doc-meta-k">Alert Type:</span>
              <span class="doc-meta-v"><strong>${data.alertType}</strong></span>
            </div>
            <div class="doc-meta-item">
              <span class="doc-meta-k">Target Asset:</span>
              <span class="doc-meta-v font-mono">${data.targetAsset}</span>
            </div>
            <div class="doc-meta-item">
              <span class="doc-meta-k">Severity:</span>
              <span class="doc-meta-v font-mono text-red"><strong>${data.severity}</strong></span>
            </div>
            <div class="doc-meta-item">
              <span class="doc-meta-k">Risk Score:</span>
              <span class="doc-meta-v font-mono text-cyan"><strong>${data.riskScore}</strong></span>
            </div>
            <div class="doc-meta-item doc-meta-full">
              <span class="doc-meta-k">Priority Rank:</span>
              <span class="doc-meta-v font-mono"><strong>${data.priorityRank}</strong></span>
            </div>
          </div>

          <!-- 1. Executive Summary -->
          <div class="doc-section">
            <h3 class="doc-section-heading">EXECUTIVE SUMMARY</h3>
            <p class="doc-paragraph">${data.execSummary}</p>
          </div>

          <!-- 2. Why This Incident Matters -->
          <div class="doc-section">
            <h3 class="doc-section-heading">WHY THIS INCIDENT MATTERS</h3>
            <p class="doc-paragraph">${data.whyItMatters}</p>
          </div>

          <!-- 3. Scoring Breakdown -->
          <div class="doc-section">
            <h3 class="doc-section-heading">SCORING BREAKDOWN</h3>
            <div class="doc-table-wrapper">
              <table class="doc-table">
                <thead>
                  <tr>
                    <th>Scoring Factor</th>
                    <th>Normalized Value</th>
                    <th>Engine Weight</th>
                    <th>Points Contribution</th>
                  </tr>
                </thead>
                <tbody>
                  ${data.factorRows.map(r => `
                    <tr>
                      <td><strong>${r.label}</strong></td>
                      <td class="font-mono">${r.val} / 100</td>
                      <td class="font-mono">${r.wt}%</td>
                      <td class="font-mono text-green">+${r.pts} pts</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
            <div class="doc-calc-sum font-mono">
              <strong>Calculation Sum:</strong> ${data.exactSum}
            </div>
          </div>

          <!-- 4. Ranking Justification -->
          <div class="doc-section">
            <h3 class="doc-section-heading">RANKING JUSTIFICATION</h3>
            <p class="doc-paragraph">${data.rankingJustification}</p>
          </div>

          <!-- 5. Indicators / Evidence -->
          <div class="doc-section">
            <h3 class="doc-section-heading">INDICATORS / EVIDENCE</h3>
            <ul class="doc-list font-mono">
              ${data.evidence.map(e => `<li>${e}</li>`).join('')}
            </ul>
          </div>

          <!-- 6. Recommended Action -->
          <div class="doc-section">
            <h3 class="doc-section-heading">RECOMMENDED ACTION</h3>
            <ul class="doc-list">
              ${data.actions.map(a => `<li>${a}</li>`).join('')}
            </ul>
          </div>

          <!-- Document Footer -->
          <div class="doc-footer-block">
            <div>Report generated automatically by <strong>SignalRank Incident Prioritization Core</strong>.</div>
            <div class="font-mono" style="word-break: break-all; font-size: 0.72rem; color: var(--text-muted);">
              Verification Hash (SHA-256): <strong class="text-cyan">${data.verificationHash}</strong>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}
