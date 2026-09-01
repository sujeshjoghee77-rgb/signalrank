/**
 * SignalRank - Main Application Bootstrap
 */

import { SignalRankApp } from './ui/app.js';

document.addEventListener('DOMContentLoaded', () => {
  // Initialize application
  const app = new SignalRankApp();
  window.__SIGNAL_RANK_APP__ = app;

  // Live UTC Clock in Navbar
  const clockEl = document.getElementById('utcLiveClock');
  if (clockEl) {
    const updateClock = () => {
      const now = new Date();
      clockEl.textContent = now.toUTCString().slice(17, 25) + ' UTC';
    };
    updateClock();
    setInterval(updateClock, 1000);
  }
});
