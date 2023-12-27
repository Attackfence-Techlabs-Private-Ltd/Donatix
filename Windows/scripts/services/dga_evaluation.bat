@echo off
schtasks /create /tn "DGAEvaluation" /tr "C:\donaticsInstaller\Windows\dga_evaluate.exe" /sc minute /mo 5
