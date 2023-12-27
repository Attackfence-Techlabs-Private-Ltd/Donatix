@echo off
set script_path=C:\donaticsInstaller\Windows\scripts\src\dnsTunnelingHosts.py

schtasks /create /sc minute /mo 5 /tn "findDnsTunnelingHosts" /tr "python %script_path%" /ru INTERACTIVE

