@echo off
set script_path=%~dp0..\src\analyticsTIReq.py

schtasks /create /sc minute /mo 5 /tn "TiAnalytics" /tr "pythonw \"%script_path%\"" /ru INTERACTIVE /rl HIGHEST /f

