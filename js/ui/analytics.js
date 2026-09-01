/**
 * SignalRank - SOC Telemetry & Queue Analytics
 * 
 * Aggregates summary telemetry: Total Alerts, Critical (P1),
 * High (P2), Medium (P3), and Average Risk Score.
 */

export function computeQueueAnalytics(queue = []) {
  if (!queue || queue.length === 0) {
    return {
      total: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      avgScore: 0.0
    };
  }

  const total = queue.length;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let totalScore = 0;

  queue.forEach(alert => {
    const score = alert.score || 0;
    totalScore += score;

    const tierId = alert.tier?.id || (score >= 80 ? 'P1' : score >= 60 ? 'P2' : score >= 40 ? 'P3' : 'P4');
    if (tierId === 'P1') criticalCount++;
    else if (tierId === 'P2') highCount++;
    else if (tierId === 'P3') mediumCount++;
    else lowCount++;
  });

  return {
    total,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    avgScore: Math.round((totalScore / total) * 100) / 100
  };
}

export function renderAnalyticsSummaryBar(analytics) {
  return `
    <div class="metrics-grid">
      <!-- 1. Total Alerts -->
      <div class="metric-card glow-cyan">
        <div class="metric-icon-box cyan">
          <svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
          </svg>
        </div>
        <div class="metric-content">
          <div class="metric-val font-mono">${analytics.total}</div>
          <div class="metric-label">Total Alerts</div>
        </div>
      </div>

      <!-- 2. Critical Incidents (P1) -->
      <div class="metric-card glow-red">
        <div class="metric-icon-box red">
          <svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
        </div>
        <div class="metric-content">
          <div class="metric-val font-mono text-red">${analytics.criticalCount}</div>
          <div class="metric-label">Critical Incidents</div>
        </div>
      </div>

      <!-- 3. High Priority Incidents (P2) -->
      <div class="metric-card glow-orange">
        <div class="metric-icon-box orange">
          <svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <div class="metric-content">
          <div class="metric-val font-mono text-orange">${analytics.highCount}</div>
          <div class="metric-label">High Priority Incidents</div>
        </div>
      </div>

      <!-- 4. Medium Priority Incidents (P3) -->
      <div class="metric-card glow-blue">
        <div class="metric-icon-box blue">
          <svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
        </div>
        <div class="metric-content">
          <div class="metric-val font-mono text-blue">${analytics.mediumCount}</div>
          <div class="metric-label">Medium Priority (P3)</div>
        </div>
      </div>

      <!-- 5. Low Priority Incidents (P4) -->
      <div class="metric-card glow-green">
        <div class="metric-icon-box green">
          <svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
          </svg>
        </div>
        <div class="metric-content">
          <div class="metric-val font-mono text-green">${analytics.lowCount}</div>
          <div class="metric-label">Low Priority (P4)</div>
        </div>
      </div>

      <!-- 6. Average Risk Score -->
      <div class="metric-card glow-purple">
        <div class="metric-icon-box purple">
          <svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
          </svg>
        </div>
        <div class="metric-content">
          <div class="metric-val font-mono">${analytics.avgScore.toFixed(1)} <small style="font-size: 0.8rem; color: var(--text-muted);">/100</small></div>
          <div class="metric-label">Average Risk Score</div>
        </div>
      </div>
    </div>
  `;
}
