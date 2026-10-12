@echo off
schtasks /create /tn "DGAEvaluation" /tr "\"%~dp0..\..\dga_evaluate.exe\"" /sc minute /mo 5 /rl HIGHEST /f
