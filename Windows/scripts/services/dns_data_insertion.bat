@echo off
set script_path=%~dp0..\src\analyseDNSData.py

schtasks /create /sc minute /mo 5 /tn "DNSDataAnalytics" /tr "pythonw \"%script_path%\"" /ru INTERACTIVE /rl HIGHEST /f


