/**
 * SignalRank - Factor & Configuration Definitions
 * 
 * Defines the six normalized factors (0-100) and default weights:
 * 1. Severity (weight: 0.25)
 * 2. Asset Importance (weight: 0.15)
 * 3. Affected Users (weight: 0.05) - log normalized from raw count
 * 4. Data Sensitivity (weight: 0.15)
 * 5. Attack Confidence (weight: 0.20)
 * 6. Business Impact (weight: 0.20)
 * 
 * Sum of weights = 1.00.
 */

export const DEFAULT_WEIGHTS = Object.freeze({
  severity: 0.25,
  assetImportance: 0.15,
  affectedUsers: 0.05,
  dataSensitivity: 0.15,
  attackConfidence: 0.20,
  businessImpact: 0.20
});

export const FACTOR_DEFINITIONS = Object.freeze({
  severity: {
    key: 'severity',
    label: 'Severity',
    shortLabel: 'SEV',
    description: 'Technical criticality of the vulnerability, exploit, or threat behavior.',
    defaultWeight: 0.25,
    min: 0,
    max: 100,
    color: '#ef4444' // Red
  },
  assetImportance: {
    key: 'assetImportance',
    label: 'Asset Importance',
    shortLabel: 'AST',
    description: 'Criticality of the targeted host, database, service, or identity tier.',
    defaultWeight: 0.15,
    min: 0,
    max: 100,
    color: '#f97316' // Orange
  },
  affectedUsers: {
    key: 'affectedUsers',
    label: 'Affected Users',
    shortLabel: 'USR',
    description: 'Log-normalized score of user accounts or identities impacted.',
    defaultWeight: 0.05,
    min: 0,
    max: 100,
    color: '#eab308' // Yellow
  },
  dataSensitivity: {
    key: 'dataSensitivity',
    label: 'Data Sensitivity',
    shortLabel: 'DAT',
    description: 'Classification level of exposed or targeted data (e.g., PII, PCI-DSS, secrets).',
    defaultWeight: 0.15,
    min: 0,
    max: 100,
    color: '#06b6d4' // Cyan
  },
  attackConfidence: {
    key: 'attackConfidence',
    label: 'Attack Confidence',
    shortLabel: 'CNF',
    description: 'Signal fidelity and certainty that this alert is a true positive.',
    defaultWeight: 0.20,
    min: 0,
    max: 100,
    color: '#8b5cf6' // Purple
  },
  businessImpact: {
    key: 'businessImpact',
    label: 'Business Impact',
    shortLabel: 'IMP',
    description: 'Financial, operational, compliance, or brand harm if unmitigated.',
    defaultWeight: 0.20,
    min: 0,
    max: 100,
    color: '#ec4899' // Pink
  }
});

export const PRIORITY_TIERS = Object.freeze({
  P1: {
    id: 'P1',
    label: 'P1 - Critical',
    minScore: 80.0,
    maxScore: 100.0,
    badgeClass: 'tier-p1',
    color: '#ef4444',
    slaMinutes: 15,
    description: 'Immediate containment required. Active breach or catastrophic risk.'
  },
  P2: {
    id: 'P2',
    label: 'P2 - High',
    minScore: 60.0,
    maxScore: 79.999,
    badgeClass: 'tier-p2',
    color: '#f97316',
    slaMinutes: 60,
    description: 'Urgent investigation. High likelihood of lateral movement or critical asset reach.'
  },
  P3: {
    id: 'P3',
    label: 'P3 - Medium',
    minScore: 40.0,
    maxScore: 59.999,
    badgeClass: 'tier-p3',
    color: '#06b6d4',
    slaMinutes: 240,
    description: 'Standard queue. Suspicious activity needing verification.'
  },
  P4: {
    id: 'P4',
    label: 'P4 - Low',
    minScore: 0.0,
    maxScore: 39.999,
    badgeClass: 'tier-p4',
    color: '#64748b',
    slaMinutes: 1440,
    description: 'Low severity or low confidence telemetry. Batch review / audit.'
  }
});

export const NORMALIZATION_CONFIG = Object.freeze({
  maxUserCap: 10000,
  minScore: 0,
  maxScore: 100
});

export const PRESET_WEIGHT_PROFILES = Object.freeze({
  default: {
    id: 'default',
    name: 'Standard SOC Balance',
    description: 'Balanced baseline prioritizing Severity and Confidence with broad factor coverage.',
    weights: { ...DEFAULT_WEIGHTS }
  },
  ransomwareSurge: {
    id: 'ransomwareSurge',
    name: 'Ransomware / Critical Asset Surge',
    description: 'Elevates Asset Importance (0.30) and Business Impact (0.25) to protect core infrastructure.',
    weights: {
      severity: 0.20,
      assetImportance: 0.30,
      affectedUsers: 0.05,
      dataSensitivity: 0.05,
      attackConfidence: 0.15,
      businessImpact: 0.25
    }
  },
  dataBreachDLP: {
    id: 'dataBreachDLP',
    name: 'Data Exfiltration & Privacy (GDPR/HIPAA)',
    description: 'Heavily weights Data Sensitivity (0.35) and Affected Users (0.15) for compliance risks.',
    weights: {
      severity: 0.15,
      assetImportance: 0.10,
      affectedUsers: 0.15,
      dataSensitivity: 0.35,
      attackConfidence: 0.15,
      businessImpact: 0.10
    }
  },
  highFidelityZeroTrust: {
    id: 'highFidelityZeroTrust',
    name: 'High-Fidelity Automated Triage',
    description: 'Prioritizes Attack Confidence (0.35) and Severity (0.30) to eliminate alert fatigue.',
    weights: {
      severity: 0.30,
      assetImportance: 0.15,
      affectedUsers: 0.05,
      dataSensitivity: 0.05,
      attackConfidence: 0.35,
      businessImpact: 0.10
    }
  }
});
