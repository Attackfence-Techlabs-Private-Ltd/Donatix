@echo off
rem Starts Donatix again after StopDonatix.bat stopped it. Captured data is kept.
setlocal

rem Administrator rights are needed to enable the tasks
fltmc >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

schtasks /query /tn TsharkQuery >nul 2>&1 || (
    echo Donatix is not installed. Run Donatix.exe or install.bat first.
    pause
    exit /b 1
)

for %%t in (DNSDataAnalytics TiAnalytics findBeaconingHosts DGAEvaluation findDnsTunnelingHosts TsharkQuery) do (
    schtasks /change /tn %%t /enable >nul 2>&1
)
rem Capture starts now instead of at the next 5 minute trigger
schtasks /run /tn TsharkQuery >nul 2>&1
echo Donatix started. Use "Stop Donatix and get report" to stop it and get the report.
pause
