@echo off
schtasks /create /tn "DGAEvaluation" /tr "C:\Donatix\Windows\dga_evaluate.exe" /sc minute /mo 5 /rl HIGHEST
