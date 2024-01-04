@echo off
set script_path=C:\Donatix\Windows\scripts\src\analyticsTIReq.py

schtasks /create /sc minute /mo 5 /tn "TiAnalytics" /tr "python %script_path%" /ru INTERACTIVE /rl HIGHEST

