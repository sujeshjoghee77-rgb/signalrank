@echo off
title SignalRank SOC Incident Prioritization System
echo Starting SignalRank Local Server...
powershell -ExecutionPolicy Bypass -File "%~dp0serve.ps1" -Port 8080
pause
