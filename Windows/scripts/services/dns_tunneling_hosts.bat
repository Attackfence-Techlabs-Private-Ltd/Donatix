@echo off
set script_path=%~dp0..\src\dnsTunnelingHosts.py

schtasks /create /sc minute /mo 5 /tn "findDnsTunnelingHosts" /tr "pythonw \"%script_path%\"" /ru INTERACTIVE /rl HIGHEST /f

