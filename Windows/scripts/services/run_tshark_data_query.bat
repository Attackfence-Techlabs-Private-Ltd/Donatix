@echo off
schtasks /create /tn "TsharkQuery" /tr "powershell.exe C:\Donatix\Windows\scripts\services\tsharkQuery.ps1" /sc minute /mo 5
