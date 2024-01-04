@echo off
set script_path=C:\Donatix\Windows\scripts\src\analyseDNSData.py

schtasks /create /sc minute /mo 5 /tn "DNSDataAnalytics" /tr "python %script_path%" /ru INTERACTIVE /rl HIGHEST


