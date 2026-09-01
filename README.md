# SignalRank: Cybersecurity Incident Prioritization System & Priority Queue

SignalRank is an incident triage and prioritization platform for Security Operations Centers (SOC). It solves alert fatigue by calculating **deterministic, mathematically explainable risk scores** for 100+ incoming security alerts and organizing them into an interactive, multi-tiered priority queue.

---

## Key Features

1. **Deterministic Linear Scoring Engine**:
   - Computes exact risk scores without LLM hallucination:
     $$\text{Risk Score} = 0.25 \times \text{Severity} + 0.15 \times \text{Asset Importance} + 0.05 \times \text{Affected Users}_{\text{norm}} + 0.15 \times \text{Data Sensitivity} + 0.20 \times \text{Attack Confidence} + 0.20 \times \text{Business Impact}$$
   - Output is strictly bounded in $[0.00, 100.00]$.

2. **Continuous Logarithmic User Normalization**:
   - Normalizes raw user counts $N$ so massive user numbers do not overpower critical infrastructure risks:
     $$U(N) = \min\left(100, \text{round}\left(\frac{\ln(1 + N)}{\ln(1 + 10,000)} \times 100, 2\right)\right)$$

3. **6-Tier Deterministic Tie-Breaking**:
   - Guarantees 100% deterministic, reproducible queue ordering:
     1. Risk Score (Descending)
     2. Attack Confidence (Descending)
     3. Business Impact (Descending)
     4. Data Sensitivity (Descending)
     5. Asset Importance (Descending)
     6. Timestamp (Ascending / FIFO)
     7. Incident ID (Ascending)

4. **Interactive Mathematical Explainability Drawer**:
   - Click any incident in the queue to inspect its exact mathematical breakdown, weight contributions, user normalization scale, and rule-level tie-break decisions against adjacent queue items.

5. **Dynamic Weight Tuner & Threat Profiles**:
   - Real-time sliders with auto-normalization.
   - Presets for *Standard SOC Balance*, *Ransomware Surge*, *Data Exfiltration/GDPR*, and *Zero-Trust High-Fidelity*.
   - Live queue re-ordering with rank delta indicators ($\Delta \text{Rank} +3, -2$).

6. **105 Realistic Security Alerts Dataset**:
   - Varied threats across ransomware, data exfiltration, credential harvesting, Kerberoasting, LSASS dumps, port scans, SQL injection, API keys, and DDoS.

7. **SOC Operations & Triage**:
   - Live alert ingestion simulation.
   - Status updates (`New`, `Investigating`, `Contained`, `Resolved`, `Suppressed`).
   - One-click CSV and JSON export.

---

## How to Run

### Option 1: Quick Launch (Windows)
Double-click `start_signalrank.bat` in this folder to start the local server and open SignalRank in your default browser at `http://localhost:8080/index.html`.

### Option 2: PowerShell
Run the built-in HTTP server:
```powershell
powershell -ExecutionPolicy Bypass -File .\serve.ps1 -Port 8080
```

### Option 3: Direct Browser Open
Open `index.html` or `test_runner.html` directly in any modern browser.

---

## Running Unit Tests

### In Browser:
Open `test_runner.html` to run all 6 test suites visually.

### In Terminal / PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\run_all_tests.ps1
```
All 27 automated test assertions execute and output detailed pass/fail reports.
