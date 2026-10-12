@echo off
rem Stops Donatix and writes the report on everything it captured to the Downloads folder.
rem Kept out of scripts\services: install.bat runs every .bat in there.
setlocal

rem Administrator rights are needed to stop the tasks
fltmc >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

rem Disabled as well as ended, the 5 minute triggers would start them again
for %%t in (DNSDataAnalytics TiAnalytics findBeaconingHosts DGAEvaluation findDnsTunnelingHosts TsharkQuery) do (
    schtasks /change /tn %%t /disable >nul 2>&1
    schtasks /end /tn %%t >nul 2>&1
)
echo Donatix stopped. Run StartDonatix.bat or the "Start Donatix" shortcut to restart it.

echo Generating the report, this can take a minute...
cd /d "%USERPROFILE%\Downloads" || goto :failed
python "%~dp0scripts\src\generateReport.py" || goto :failed

rem The report is named after today's date, dir /od lists the newest last
for /f "delims=" %%f in ('dir /b /od Donatix_Report_*.pdf') do set "report=%%f"
start "" "%report%"
pause
exit /b 0

:failed
echo.
echo The report could not be generated, see the message above.
pause
exit /b 1
