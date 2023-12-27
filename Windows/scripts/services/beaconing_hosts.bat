@echo off
set script_path=C:\Donatix\Windows\scripts\src\beaconingHosts.py

schtasks /create /sc minute /mo 1440 /tn "findBeaconingHosts" /tr "python %script_path%" /ru INTERACTIVE

