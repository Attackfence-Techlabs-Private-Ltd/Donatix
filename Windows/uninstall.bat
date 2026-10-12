@echo off
rem Removes what Donatix.exe or install.bat set up: the scheduled tasks, the installed copy and the C:\Donatix link.
setlocal

rem Administrator rights are needed to delete the tasks
fltmc >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set /p deleteData=Delete the captured DNS data as well? [y/N]

rem A copy installed by Donatix.exe has its own uninstaller, which removes the installed files.
rem It is never run on a link or a source checkout: there it would delete the source files.
fsutil reparsepoint query C:\Donatix >nul 2>&1
if not errorlevel 1 goto :tasks
if exist C:\Donatix\.git goto :tasks
if exist C:\Donatix\unins000.exe (
    echo Running the Donatix uninstaller...
    start /wait "" C:\Donatix\unins000.exe /SILENT
)

:tasks
for %%t in (DNSDataAnalytics TiAnalytics findBeaconingHosts DGAEvaluation findDnsTunnelingHosts TsharkQuery) do (
    schtasks /end /tn %%t >nul 2>&1
    schtasks /delete /tn %%t /f >nul 2>&1
)
echo Scheduled tasks removed.

if /i not "%deleteData%"=="y" goto :link
del /q "%~dp0scripts\src\networkdata.db*" 2>nul
del /q "C:\Donatix\Windows\scripts\src\networkdata.db*" 2>nul
echo Captured data deleted.

:link
rem install.bat links C:\Donatix to the checkout: remove the link only, never the files behind it.
rem Otherwise remove the folders the uninstaller left behind; rd only removes a folder that is empty.
fsutil reparsepoint query C:\Donatix >nul 2>&1
if not errorlevel 1 (
    rmdir C:\Donatix
    echo C:\Donatix link removed.
) else (
    for %%d in (C:\Donatix\Windows\scripts\src C:\Donatix\Windows\scripts C:\Donatix\Windows C:\Donatix) do rd "%%d" 2>nul
)

echo.
echo Donatix is uninstalled. Python, Wireshark and the Python packages aiohttp and matplotlib were left installed.
pause
