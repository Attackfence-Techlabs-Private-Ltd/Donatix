@echo off
set script_path=%~dp0..\src\beaconingHosts.py

schtasks /create /sc daily /tn "findBeaconingHosts" /tr "pythonw \"%script_path%\"" /ru INTERACTIVE /rl HIGHEST /f

