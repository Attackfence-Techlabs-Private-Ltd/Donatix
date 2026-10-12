@echo off
rem Stop a capture that is already running, it would keep the new definition from ever starting
schtasks /end /tn "TsharkQuery" >nul 2>&1
schtasks /create /tn "TsharkQuery" /tr "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%~dp0tsharkQuery.ps1\"" /sc minute /mo 5 /rl HIGHEST /f
