@echo off
rem Installs whatever Donatix needs that is missing, then creates the scheduled tasks.
setlocal

rem Administrator rights are needed to create the tasks
fltmc >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

for %%i in ("%~dp0..") do set "root=%%~fi"

python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed. Installing...
    call :winget Python.Python.3.11 || goto :failed
    echo Python was installed. Close this window and run the installation again to continue.
    pause
    exit /b
)
echo Python is already installed.

if exist "C:\Program Files\Wireshark\tshark.exe" (
    echo Wireshark is already installed.
) else (
    echo Wireshark is not installed. Installing, keep Npcap ticked in its setup window...
    call :winget WiresharkFoundation.Wireshark --interactive || goto :failed
)

for %%p in (aiohttp matplotlib) do (
    python -c "import %%p" >nul 2>&1
    if errorlevel 1 (
        echo %%p is not installed. Installing...
        python -m pip install %%p || goto :failed
    ) else (
        echo %%p is already installed.
    )
)

rem dga_evaluate.exe only looks for its database under C:\Donatix
if not exist C:\Donatix mklink /J C:\Donatix "%root%" >nul

for %%f in ("%~dp0scripts\services\*.bat") do call "%%f"

echo.
echo Donatix is installed.
pause
exit /b 0

:winget
where winget >nul 2>&1
if errorlevel 1 (
    echo winget is not available. Install %~1 manually and run install.bat again.
    exit /b 1
)
winget install --id %~1 -e --accept-package-agreements --accept-source-agreements %~2
exit /b

:failed
echo.
echo Installation failed, see the message above.
pause
exit /b 1
