/**
 * SignalRank - Custom Security Alert Parser & Extractor
 * 
 * Safely parses user-supplied alerts across multiple formats:
 * - JSON (SIEM events, Splunk/Elastic JSON, CloudTrail, Defender, GuardDuty)
 * - CSV (Security alerts table, incident exports)
 * - Syslog / Key-Value (CEF, LEEF, RFC5424, KV pairs)
 * - EML / Email formats (Phishing emails, alert digests)
 * - Freeform Raw Text / Logs (EDR alerts, terminal dumps, incident descriptions)
 * 
 * Extracts available scoring dimensions, identifies missing context without hallucination,
 * and extracts observed technical evidence (IPs, hashes, domains, CVEs, commands).
 */

import { normalizeAffectedUsers } from './scoring.js';

/**
 * Extracts observed technical indicators (IoCs) strictly from the raw content.
 * Never fabricates or hallucinates nonexistent indicators.
 */
export function extractEvidenceFromText(text) {
  if (!text || typeof text !== 'string') return [];
  const evidence = new Set();

  // 1. IPv4 Addresses (exclude broadcast/loopback/bogus)
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  let match;
  while ((match = ipRegex.exec(text)) !== null) {
    const ip = match[0];
    if (ip !== '0.0.0.0' && ip !== '255.255.255.255' && !ip.startsWith('127.0.0.')) {
      evidence.add(`IP: ${ip}`);
    }
  }

  // 2. SHA-256 Hashes
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  while ((match = sha256Regex.exec(text)) !== null) {
    evidence.add(`SHA256: ${match[0]}`);
  }

  // 3. MD5 / SHA-1 Hashes
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  while ((match = md5Regex.exec(text)) !== null) {
    evidence.add(`MD5: ${match[0]}`);
  }

  // 4. CVE Identifiers
  const cveRegex = /\bCVE-\d{4}-\d{4,}\b/gi;
  while ((match = cveRegex.exec(text)) !== null) {
    evidence.add(`Vulnerability: ${match[0].toUpperCase()}`);
  }

  // 5. MITRE ATT&CK Techniques
  const mitreRegex = /\bT\d{4}(?:\.\d{3})?\b/g;
  while ((match = mitreRegex.exec(text)) !== null) {
    evidence.add(`MITRE: ${match[0]}`);
  }

  // 6. Suspicious CLI commands / tools
  const cmdPatterns = [
    /(?:cmd\.exe|powershell(?:\.exe)?|bash|sh|sudo|vssadmin|rundll32(?:\.exe)?|certutil(?:\.exe)?|whoami|psexec(?:\.exe)?|wmic(?:\.exe)?)\s+[^\r\n;]+(?:\r?\n|;|$)/gi,
    /(?:curl|wget)\s+https?:\/\/[^\s]+/gi
  ];

  cmdPatterns.forEach(pattern => {
    while ((match = pattern.exec(text)) !== null) {
      const cleanCmd = match[0].trim().slice(0, 120);
      if (cleanCmd.length > 5) {
        evidence.add(`Command: ${cleanCmd}`);
      }
    }
  });

  return Array.from(evidence);
}

/**
 * Normalizes text/string severity into 0-100 numerical value.
 */
export function parseSeverityValue(rawSev) {
  if (rawSev === undefined || rawSev === null) return null;
  if (typeof rawSev === 'number' && !isNaN(rawSev)) {
    if (rawSev >= 0 && rawSev <= 10) return Math.min(100, Math.round(rawSev * 10));
    return Math.min(100, Math.max(0, Math.round(rawSev)));
  }

  const str = String(rawSev).toLowerCase().trim();
  if (!str) return null;

  if (str.includes('critical') || str.includes('crit') || str.includes('sev-1') || str.includes('sev1') || str.includes('p1')) return 95;
  if (str.includes('high') || str.includes('sev-2') || str.includes('sev2') || str.includes('p2')) return 80;
  if (str.includes('medium') || str.includes('med') || str.includes('moderate') || str.includes('sev-3') || str.includes('sev3') || str.includes('p3')) return 50;
  if (str.includes('low') || str.includes('sev-4') || str.includes('sev4') || str.includes('p4')) return 25;
  if (str.includes('info') || str.includes('informational') || str.includes('p5')) return 10;

  const num = parseFloat(str);
  if (!isNaN(num)) {
    if (num >= 0 && num <= 10) return Math.min(100, Math.round(num * 10));
    if (num >= 0 && num <= 100) return Math.min(100, Math.max(0, Math.round(num)));
  }

  return null;
}

/**
 * Main parser entry point.
 */
export function parseRawSecurityInput(rawContent, filename = '') {
  if (!rawContent || typeof rawContent !== 'string') {
    throw new Error('No content provided for alert analysis.');
  }

  const trimmed = rawContent.trim();
  const fileExt = filename ? filename.slice(filename.lastIndexOf('.')).toLowerCase() : '';

  let detectedFormat = 'RAW_TEXT';
  let alertType = null;
  let shortDescription = null;
  let source = null;
  let asset = null;
  let timestamp = null;
  let mitreTechnique = null;

  let severity = null;
  let assetImportance = null;
  let rawAffectedUsers = null;
  let dataSensitivity = null;
  let attackConfidence = null;
  let businessImpact = null;

  // 1. Check for JSON format
  if (fileExt === '.json' || (trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsed = JSON.parse(trimmed);
      detectedFormat = 'JSON';
      const obj = Array.isArray(parsed) ? (parsed[0] || {}) : parsed;

      alertType = obj.alertType || obj.type || obj.category || obj.rule_name || obj.signature || obj.name || obj.title || obj.event_type || null;
      shortDescription = obj.shortDescription || obj.description || obj.msg || obj.message || obj.details || obj.summary || null;
      source = obj.source || obj.detector || obj.vendor || obj.product || obj.agent || 'Custom JSON Ingestion';
      asset = obj.asset || obj.host || obj.hostname || obj.target || obj.destination || obj.dest_host || obj.server || obj.device || null;
      timestamp = obj.timestamp || obj.time || obj.event_time || obj['@timestamp'] || new Date().toISOString();
      mitreTechnique = obj.mitreTechnique || obj.mitre || obj.technique || null;

      severity = parseSeverityValue(obj.severity ?? obj.level ?? obj.priority ?? obj.crit);
      assetImportance = parseSeverityValue(obj.assetImportance ?? obj.asset_importance ?? obj.asset_criticality ?? obj.criticality);
      
      if (obj.rawAffectedUsers !== undefined || obj.affected_users !== undefined || obj.user_count !== undefined || obj.affectedUsers !== undefined) {
        const u = obj.rawAffectedUsers ?? obj.affected_users ?? obj.user_count ?? obj.affectedUsers;
        rawAffectedUsers = typeof u === 'number' ? Math.max(0, u) : parseInt(String(u), 10);
      }

      dataSensitivity = parseSeverityValue(obj.dataSensitivity ?? obj.data_sensitivity ?? obj.classification);
      attackConfidence = parseSeverityValue(obj.attackConfidence ?? obj.attack_confidence ?? obj.confidence ?? obj.fidelity);
      businessImpact = parseSeverityValue(obj.businessImpact ?? obj.business_impact ?? obj.impact);

    } catch (e) {
      // Fall through to text parsing if JSON parse failed
    }
  }

  // 2. Check for CSV format
  if (detectedFormat === 'RAW_TEXT' && (fileExt === '.csv' || (trimmed.includes(',') && trimmed.includes('\n')))) {
    const lines = trimmed.split(/\r?\n/).filter(l => l.trim().length > 0);
    if (lines.length >= 2 && lines[0].includes(',')) {
      const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/['"]/g, ''));
      const row = lines[1].split(',').map(c => c.trim().replace(/['"]/g, ''));
      
      detectedFormat = 'CSV';
      source = 'Custom CSV Export';

      headers.forEach((h, i) => {
        const val = row[i] || '';
        if (!val) return;

        if (h.includes('type') || h.includes('category') || h.includes('alert') || h.includes('signature')) {
          if (!alertType) alertType = val;
        } else if (h.includes('desc') || h.includes('summary') || h.includes('msg') || h.includes('message')) {
          if (!shortDescription) shortDescription = val;
        } else if (h.includes('asset') || h.includes('host') || h.includes('target') || h.includes('dest')) {
          if (!asset) asset = val;
        } else if (h.includes('sev') || h.includes('priority') || h.includes('level')) {
          if (severity === null) severity = parseSeverityValue(val);
        } else if (h.includes('user') || h.includes('impacted_users') || h.includes('affected_users')) {
          if (rawAffectedUsers === null) rawAffectedUsers = parseInt(val, 10);
        } else if (h.includes('conf') || h.includes('fidelity')) {
          if (attackConfidence === null) attackConfidence = parseSeverityValue(val);
        } else if (h.includes('impact') || h.includes('business')) {
          if (businessImpact === null) businessImpact = parseSeverityValue(val);
        } else if (h.includes('data') || h.includes('sensitivity')) {
          if (dataSensitivity === null) dataSensitivity = parseSeverityValue(val);
        } else if (h.includes('source') || h.includes('detector') || h.includes('vendor')) {
          source = val;
        }
      });
    }
  }

  // 3. Check for EML / Email format
  if (detectedFormat === 'RAW_TEXT' && (fileExt === '.eml' || trimmed.includes('Subject:') || trimmed.includes('From:'))) {
    detectedFormat = 'EML';
    source = 'Email Gateway / Phishing Parser';
    
    const subjectMatch = trimmed.match(/Subject:\s*([^\r\n]+)/i);
    if (subjectMatch) alertType = `Suspicious Email: ${subjectMatch[1].trim()}`;
    
    const fromMatch = trimmed.match(/From:\s*([^\r\n]+)/i);
    const toMatch = trimmed.match(/To:\s*([^\r\n]+)/i);
    if (fromMatch || toMatch) {
      shortDescription = `Inbound email message from ${fromMatch ? fromMatch[1].trim() : 'Unknown sender'} to ${toMatch ? toMatch[1].trim() : 'Target mailbox'}.`;
    }
    
    if (toMatch && !asset) {
      asset = `Mailbox: ${toMatch[1].trim()}`;
    }
    
    rawAffectedUsers = 1; // Direct email targets individual recipient
    attackConfidence = 85; // Directly captured email payload
  }

  // 4. Freeform Text & Syslog / Key-Value Extraction
  if (detectedFormat === 'RAW_TEXT') {
    // Check for Syslog / CEF Key-Values
    if (trimmed.includes('CEF:') || trimmed.includes('src=') || trimmed.includes('dst=') || trimmed.includes('msg=')) {
      detectedFormat = 'SYSLOG_KV';
      source = 'SIEM / Syslog Stream';

      const kvMatches = trimmed.matchAll(/(\w+)=([^=\s]+(?:\s+[^=\s]+)*?)(?=\s+\w+=|$)/g);
      for (const m of kvMatches) {
        const k = m[1].toLowerCase();
        const v = m[2].trim();
        if (k === 'msg' || k === 'message') shortDescription = v;
        else if (k === 'cat' || k === 'act' || k === 'name') alertType = v;
        else if (k === 'dst' || k === 'dhost' || k === 'destination') asset = v;
        else if (k === 'sev' || k === 'severity') severity = parseSeverityValue(v);
        else if (k === 'suser' || k === 'duser') {
          if (!asset) asset = `User Account: ${v}`;
          rawAffectedUsers = 1;
        }
      }
    }

    // Heuristic Alert Type Classification from Text Keywords
    if (!alertType) {
      const lower = trimmed.toLowerCase();
      if (lower.includes('ransomware') || lower.includes('encrypt') || lower.includes('vssadmin') || lower.includes('.locked')) {
        alertType = 'Ransomware / File Encryption Threat';
      } else if (lower.includes('exfiltration') || lower.includes('mega.nz') || lower.includes('upload') || lower.includes('unauthorized sync')) {
        alertType = 'Data Exfiltration / Unauthorized Cloud Sync';
      } else if (lower.includes('sql injection') || lower.includes('sqli') || lower.includes('xp_cmdshell') || lower.includes("' union select")) {
        alertType = 'SQL Injection / Public Exploit Attempt';
      } else if (lower.includes('lsass') || lower.includes('mimikatz') || lower.includes('comsvcs.dll') || lower.includes('credential dump')) {
        alertType = 'Privilege Escalation / Credential Dumping';
      } else if (lower.includes('phishing') || lower.includes('credential harvesting') || lower.includes('spoofed')) {
        alertType = 'Phishing / Suspicious Communication';
      } else if (lower.includes('brute force') || lower.includes('failed logins') || lower.includes('password spray')) {
        alertType = 'Authentication / Password Spray Attack';
      } else if (lower.includes('root') || lower.includes('unauthorized admin') || lower.includes('iam:createaccesskey')) {
        alertType = 'Privileged IAM / Root Account Compromise';
      } else if (lower.includes('port scan') || lower.includes('nmap') || lower.includes('syn scan')) {
        alertType = 'Reconnaissance / Network Port Scan';
      } else if (lower.includes('malware') || lower.includes('trojan') || lower.includes('c2') || lower.includes('beacon')) {
        alertType = 'Malware Detection / Command & Control';
      } else {
        alertType = 'Custom Security Event / Anomaly';
      }
    }

    // Heuristic Severity Detection from text
    if (severity === null) {
      const lower = trimmed.toLowerCase();
      if (lower.includes('severity: critical') || lower.includes('sev: critical') || lower.includes('sev 1') || lower.includes('severity 1')) severity = 95;
      else if (lower.includes('severity: high') || lower.includes('sev: high') || lower.includes('sev 2') || lower.includes('severity 2')) severity = 80;
      else if (lower.includes('severity: medium') || lower.includes('sev: medium') || lower.includes('sev 3') || lower.includes('severity 3')) severity = 50;
      else if (lower.includes('severity: low') || lower.includes('sev: low') || lower.includes('sev 4') || lower.includes('severity 4')) severity = 25;
    }

    // Heuristic Affected Users Detection from text
    if (rawAffectedUsers === null) {
      const userMatch = trimmed.match(/(\d{1,6})\s*(?:users?|accounts?|identities|employees|mailboxes|customers)/i);
      if (userMatch) {
        rawAffectedUsers = parseInt(userMatch[1], 10);
      }
    }

    // Heuristic Asset Detection
    if (!asset) {
      const hostMatch = trimmed.match(/(?:host(?:name)?|asset|server|target|destination|device)\s*[:=]\s*([a-zA-Z0-9_.-]+)/i);
      if (hostMatch) {
        asset = hostMatch[1].trim();
      } else {
        // Look for domain/host tokens like DC-..., DB-..., PROD-..., or IP
        const serverToken = trimmed.match(/\b([A-Z0-9_-]+(?:-DC-|-DB-|-PROD-|-API-|-MGMT-)[A-Z0-9_-]+)\b/);
        if (serverToken) asset = serverToken[1];
      }
    }

    if (!shortDescription) {
      // First 200 characters of meaningful text
      const cleanFirstLine = trimmed.split(/\r?\n/)[0].slice(0, 200).trim();
      shortDescription = cleanFirstLine || 'User-supplied custom security telemetry.';
    }

    if (!source) {
      source = 'User-Supplied Security Log';
    }
  }

  // Fallbacks for non-scoring metadata
  if (!alertType) alertType = 'Custom Security Event';
  if (!shortDescription) shortDescription = trimmed.slice(0, 180).trim();
  if (!asset) asset = 'Asset Unspecified';
  if (!source) source = 'User-Supplied Telemetry';
  if (!timestamp) timestamp = new Date().toISOString();

  // Extract observed technical evidence
  const evidence = extractEvidenceFromText(trimmed);

  // Extract MITRE technique if found in evidence
  if (!mitreTechnique) {
    const mitreItem = evidence.find(e => e.startsWith('MITRE: '));
    if (mitreItem) mitreTechnique = mitreItem.replace('MITRE: ', '');
  }

  // Construct scoring factors record with source tracking
  const factors = {
    severity: {
      value: severity !== null ? severity : null,
      source: severity !== null ? 'EXTRACTED' : 'MISSING',
      label: 'Severity'
    },
    assetImportance: {
      value: assetImportance !== null ? assetImportance : null,
      source: assetImportance !== null ? 'EXTRACTED' : 'MISSING',
      label: 'Asset Importance'
    },
    rawAffectedUsers: {
      value: rawAffectedUsers !== null ? rawAffectedUsers : null,
      source: rawAffectedUsers !== null ? 'EXTRACTED' : 'MISSING',
      label: 'Affected Users'
    },
    dataSensitivity: {
      value: dataSensitivity !== null ? dataSensitivity : null,
      source: dataSensitivity !== null ? 'EXTRACTED' : 'MISSING',
      label: 'Data Sensitivity'
    },
    attackConfidence: {
      value: attackConfidence !== null ? attackConfidence : null,
      source: attackConfidence !== null ? 'EXTRACTED' : 'MISSING',
      label: 'Attack Confidence'
    },
    businessImpact: {
      value: businessImpact !== null ? businessImpact : null,
      source: businessImpact !== null ? 'EXTRACTED' : 'MISSING',
      label: 'Business Impact'
    }
  };

  const missingFieldKeys = Object.keys(factors).filter(k => factors[k].source === 'MISSING');

  return {
    rawContent: trimmed,
    detectedFormat,
    extractedFields: {
      alertType,
      shortDescription,
      source,
      asset,
      timestamp,
      mitreTechnique,
      evidence
    },
    factors,
    missingFieldKeys
  };
}
