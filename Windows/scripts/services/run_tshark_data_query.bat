@echo off
schtasks /create /tn "TsharkQuery" /tr "C:\donaticsInstaller\Windows\scripts\services\tsharkQuery.ps1" /sc minute /mo 5
