/**
 * SignalRank - AI Explanation Layer
 * 
 * Synthesizes natural-language executive briefings, priority justifications,
 * contributing factor analyses, and investigation playbooks strictly from
 * structured scoring evidence.
 * 
 * CRITICAL RULE:
 * AI NEVER determines, calculates, or overrides the numerical risk score.
 * Deterministic engine output is the immutable single source of truth.
 */

import { FACTOR_DEFINITIONS, DEFAULT_WEIGHTS } from '../engine/types.js';
import { explainTieBreak } from '../engine/comparator.js';

export class AIService {
  constructor() {
    this.apiKey = localStorage.getItem('signalrank_gemini_api_key') || '';
    this.cachedExplanations = new Map();
  }

  setApiKey(key) {
    this.apiKey = (key || '').trim();
    if (this.apiKey) {
      localStorage.setItem('signalrank_gemini_api_key', this.apiKey);
    } else {
      localStorage.removeItem('signalrank_gemini_api_key');
    }
  }

  getApiKey() {
    return this.apiKey;
  }

  /**
   * Constructs the structured, hallucination-resistant prompt payload for an incident.
   */
  buildStructuredPromptPayload(alert, nextAlert, calculation, queue = []) {
    const factors = calculation.factors;
    const weights = calculation.weights;
    const contributions = calculation.contributions;
    const tieTrace = nextAlert ? explainTieBreak(alert, nextAlert, weights) : null;

    return {
      incidentId: alert.id,
      timestamp: alert.timestamp,
      alertType: alert.alertType,
      shortDescription: alert.shortDescription,
      telemetrySource: alert.source || 'Unavailable in telemetry',
      targetedAsset: alert.asset || 'Unavailable in telemetry',
      mitreTechnique: alert.mitreTechnique || 'Unavailable in telemetry',
      iocs: (alert.iocs && alert.iocs.length > 0) ? alert.iocs : 'No IOCs recorded in telemetry',
      status: alert.status || 'New',
      groundTruthCalculations: {
        riskScore: calculation.score,
        priorityTier: calculation.tier.label,
        priorityTierId: calculation.tier.id,
        currentRank: alert.rank,
        slaMinutes: calculation.tier.slaMinutes,
        sixFactors: {
          severity: { value: factors.severity, weight: weights.severity, points: contributions.severity },
          assetImportance: { value: factors.assetImportance, weight: weights.assetImportance, points: contributions.assetImportance },
          affectedUsers: { rawCount: factors.rawAffectedUsers, normalizedValue: factors.affectedUsers, weight: weights.affectedUsers, points: contributions.affectedUsers },
          dataSensitivity: { value: factors.dataSensitivity, weight: weights.dataSensitivity, points: contributions.dataSensitivity },
          attackConfidence: { value: factors.attackConfidence, weight: weights.attackConfidence, points: contributions.attackConfidence },
          businessImpact: { value: factors.businessImpact, weight: weights.businessImpact, points: contributions.businessImpact }
        }
      },
      comparisonWithNextIncident: nextAlert ? {
        nextIncidentId: nextAlert.id,
        nextRank: nextAlert.rank,
        nextRiskScore: nextAlert.score,
        scoreDelta: Math.round((calculation.score - nextAlert.score) * 100) / 100,
        tieBreakReason: tieTrace ? tieTrace.explanation : null
      } : 'No subsequent incident in active queue (End of Queue)'
    };
  }

  /**
   * Generates natural language AI explanation for an incident.
   * Uses Gemini API if key is present, or built-in grounded zero-hallucination synthesizer.
   * 
   * @param {Object} alert - The selected alert
   * @param {Object} nextAlert - The next alert in queue
   * @param {Object} calculation - Deterministic engine calculation
   * @param {Array<Object>} queue - Full queue
   * @returns {Promise<Object>} 5-part structured AI briefing
   */
  async generateExplanation(alert, nextAlert, calculation, queue = []) {
    const cacheKey = `${alert.id}_${calculation.score}_${nextAlert ? nextAlert.id : 'none'}`;
    if (this.cachedExplanations.has(cacheKey)) {
      return this.cachedExplanations.get(cacheKey);
    }

    const payload = this.buildStructuredPromptPayload(alert, nextAlert, calculation, queue);

    // If custom Gemini API key is configured, attempt live calling
    if (this.apiKey) {
      try {
        const liveResult = await this.callGeminiAPI(payload);
        this.cachedExplanations.set(cacheKey, liveResult);
        return liveResult;
      } catch (err) {
        console.warn('Gemini API call failed, falling back to grounded analyst synthesizer:', err);
      }
    }

    // Default: High-fidelity grounded analyst synthesizer
    // Simulate realistic AI generation latency (600ms)
    await new Promise(resolve => setTimeout(resolve, 600));

    const synthesizedResult = this.synthesizeGroundedExplanation(payload);
    this.cachedExplanations.set(cacheKey, synthesizedResult);
    return synthesizedResult;
  }

  /**
   * Calls Google Gemini API with strict structured prompt.
   */
  async callGeminiAPI(payload) {
    const systemPrompt = `You are SignalRank AI, an expert SOC Incident Prioritization Analyst.
CRITICAL CONSTRAINT: You MUST NEVER calculate or change the numerical risk score. All numerical scores, weights, and ranks are ground truth calculated by SignalRank's deterministic engine.
Your role is to produce a natural-language security briefing strictly based on the provided JSON payload.
DO NOT INVENT facts, missing IOCs, attack vectors, or affected users not present in the payload. If an item is missing or unavailable, explicitly state "Information unavailable in telemetry".

Return a valid JSON object with these EXACT keys:
{
  "executiveSummary": "Concise 2-3 sentence executive threat briefing.",
  "priorityJustification": "Detailed explanation of why this incident is classified in its Priority Tier.",
  "contributingFactorsAnalysis": "Ranked analysis of the primary factors that elevated or mitigated the risk score.",
  "outranksNextExplanation": "Clear mathematical and threat comparison explaining why this alert is prioritized above the immediately following incident.",
  "recommendedActions": [
    "Step 1 containment action",
    "Step 2 investigation action",
    "Step 3 remediation action"
  ]
}`;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${this.apiKey}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [
          { role: 'user', parts: [{ text: `${systemPrompt}\n\nStructured Telemetry Payload:\n${JSON.stringify(payload, null, 2)}` }] }
        ],
        generationConfig: {
          responseMimeType: 'application/json',
          temperature: 0.2
        }
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Gemini API Error (${response.status}): ${errText}`);
    }

    const data = await response.json();
    const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
    const parsed = JSON.parse(rawText);

    return {
      ...parsed,
      isLiveApi: true,
      generatedAt: new Date().toISOString()
    };
  }

  /**
   * High-fidelity zero-hallucination analyst synthesizer.
   * Deterministically constructs the 5 required sections strictly from structured payload.
   */
  synthesizeGroundedExplanation(p) {
    const gt = p.groundTruthCalculations;
    const f = gt.sixFactors;

    // 1. Executive Summary
    let execSummary = `SignalRank has flagged ${p.alertType} associated with ${p.targetedAsset} detected via ${p.telemetrySource}. `;
    if (f.affectedUsers.rawCount > 0) {
      execSummary += `Recorded telemetry indicates an affected scope of ${f.affectedUsers.rawCount.toLocaleString()} user accounts with a Data Sensitivity score of ${f.dataSensitivity.value.toFixed(0)}/100. `;
    }
    execSummary += `With an Attack Confidence of ${f.attackConfidence.value.toFixed(0)}% and Business Impact assessed at ${f.businessImpact.value.toFixed(0)}/100, deterministic priority scoring places this at ${gt.priorityTier}.`;

    // 2. Why this incident is High/Medium/Low Priority
    let priorityJustification = `This incident is assigned to ${gt.priorityTier} because its deterministic Risk Score of ${gt.riskScore.toFixed(2)}/100 `;
    if (gt.priorityTierId === 'P1') {
      priorityJustification += `exceeds the critical threshold (≥ 80.00). It is driven by elevated technical severity and critical asset exposure on ${p.targetedAsset}, placing it at the top of the investigation queue.`;
    } else if (gt.priorityTierId === 'P2') {
      priorityJustification += `falls within the high priority tier (60.00 – 79.99), reflecting significant severity or asset criticality.`;
    } else if (gt.priorityTierId === 'P3') {
      priorityJustification += `falls in the medium priority range (40.00 – 59.99), reflecting moderate impact without acute critical asset exposure.`;
    } else {
      priorityJustification += `is in the low priority tier (< 40.00), representing baseline or low-severity events suitable for routine review.`;
    }

    // 3. Most Important Contributing Factors
    const factorEntries = [
      { name: 'Severity', pts: f.severity.points, val: f.severity.value, wt: f.severity.weight },
      { name: 'Attack Confidence', pts: f.attackConfidence.points, val: f.attackConfidence.value, wt: f.attackConfidence.weight },
      { name: 'Business Impact', pts: f.businessImpact.points, val: f.businessImpact.value, wt: f.businessImpact.weight },
      { name: 'Asset Importance', pts: f.assetImportance.points, val: f.assetImportance.value, wt: f.assetImportance.weight },
      { name: 'Data Sensitivity', pts: f.dataSensitivity.points, val: f.dataSensitivity.value, wt: f.dataSensitivity.weight },
      { name: 'Affected Users', pts: f.affectedUsers.points, val: f.affectedUsers.normalizedValue, wt: f.affectedUsers.weight, raw: f.affectedUsers.rawCount }
    ];
    factorEntries.sort((a, b) => b.pts - a.pts);

    const topDrivers = factorEntries.slice(0, 3).map(e => 
      `• ${e.name}: Contributed +${e.pts.toFixed(2)} points (${e.val.toFixed(0)}/100 at ${(e.wt * 100).toFixed(0)}% weight).`
    ).join('\n');

    const lowestEntry = factorEntries[factorEntries.length - 1];
    let contributingFactorsAnalysis = `The primary risk drivers elevating this incident's score are:\n${topDrivers}\n\n` +
      `Mitigating / Lower Factors:\n• ${lowestEntry.name}: Only contributed +${lowestEntry.pts.toFixed(2)} points (${lowestEntry.val.toFixed(0)}/100), preventing further score escalation.`;

    // 4. Why it outranks the next incident
    let outranksNextExplanation = '';
    if (p.comparisonWithNextIncident && typeof p.comparisonWithNextIncident === 'object') {
      const cmp = p.comparisonWithNextIncident;
      if (cmp.scoreDelta > 0) {
        outranksNextExplanation = `Rank #${gt.currentRank} (${p.incidentId}, Score: ${gt.riskScore.toFixed(2)}) outranks Rank #${cmp.nextRank} (${cmp.nextIncidentId}, Score: ${cmp.nextRiskScore.toFixed(2)}) by a deterministic margin of +${cmp.scoreDelta.toFixed(2)} points. Priority is driven by factor contribution differences on ${p.targetedAsset}.`;
      } else {
        outranksNextExplanation = `Rank #${gt.currentRank} (${p.incidentId}) is tied with Rank #${cmp.nextRank} (${cmp.nextIncidentId}) at ${gt.riskScore.toFixed(2)} points. Priority was resolved at Deterministic Tie-Break: ${cmp.tieBreakReason}.`;
      }
    } else {
      outranksNextExplanation = `This alert holds the final position in the active queue with no subsequent incident.`;
    }

    // 5. Recommended Investigation Actions (Framed as recommendations)
    const recommendedActions = this.generatePlaybookActions(p);

    return {
      executiveSummary: execSummary,
      priorityJustification: priorityJustification,
      contributingFactorsAnalysis: contributingFactorsAnalysis,
      outranksNextExplanation: outranksNextExplanation,
      recommendedActions: recommendedActions,
      isLiveApi: false,
      generatedAt: new Date().toISOString()
    };
  }

  generatePlaybookActions(p) {
    const alertType = (p.alertType || '').toLowerCase();
    const asset = p.targetedAsset || 'target asset';
    const mitre = p.mitreTechnique || '';

    const actions = [
      `1. Containment Evaluation: Evaluate immediate network isolation or agent containment of ${asset} according to organization incident response procedures.`
    ];

    if (alertType.includes('ransomware') || alertType.includes('encrypt')) {
      actions.push(`2. Backup Status Verification: Verify immutable offline status of backup snapshots and volume shadow copies.`);
      actions.push(`3. Process Forensics: Capture memory image and inspect suspect process trees on ${asset}.`);
    } else if (alertType.includes('exfiltration') || alertType.includes('data')) {
      actions.push(`2. Egress Perimeter Review: Review outbound firewall connections and proxy logs for recorded destination endpoints.`);
      actions.push(`3. Data Impact Analysis: Inspect database and file access logs on ${asset} to determine exposed records.`);
    } else if (alertType.includes('phishing') || alertType.includes('credential')) {
      actions.push(`2. Identity Verification: Consider session token revocation and password resets for potentially impacted accounts.`);
      actions.push(`3. Mailbox Sweep: Search enterprise mail gateway logs for matching phishing message IDs.`);
    } else if (alertType.includes('privilege') || alertType.includes('lsass')) {
      actions.push(`2. Auth Audit: Review Kerberos ticket requests (Event ID 4769) and administrative session events in Active Directory.`);
      actions.push(`3. Privileged Account Audit: Review all active domain and local Administrator sessions logged on ${asset}.`);
    } else {
      actions.push(`2. SIEM Timeline Correlation: Query SIEM logs for related authentication or network events from ${asset}.`);
      actions.push(`3. IOC Threat Hunting: Search enterprise endpoint telemetry for matching hashes, command-line arguments, or IPs.`);
    }

    actions.push(`4. Incident Documentation: Attach MITRE ATT&CK mapping (${mitre}) and archive scoring evidence in SOC case management.`);
    return actions;
  }
}

export const aiService = new AIService();
