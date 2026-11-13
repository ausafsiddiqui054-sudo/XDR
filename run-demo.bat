@echo off
setlocal
rem ---------------------------------------------------------------------------
rem  SecurePulse - start the portal on in-memory sample data.
rem  No database, no Worker: a simulated Worker finishes scans and approved
rem  actions, and nothing is sent to Microsoft or any engine.
rem
rem  Usage:  run-demo.bat              build, start, open the browser
rem          run-demo.bat --no-browser  same, without opening the browser
rem  Stop it with Ctrl+C in this window.
rem ---------------------------------------------------------------------------

cd /d "%~dp0"
set "PORT=5106"
set "URL=http://localhost:%PORT%"
set "OPEN_BROWSER=1"
if /i "%~1"=="--no-browser" set "OPEN_BROWSER=0"

where dotnet >nul 2>nul
if errorlevel 1 (
    echo The .NET SDK was not found. Install the .NET 10 SDK from https://dotnet.microsoft.com/download
    pause
    exit /b 1
)

rem Already running? Then just open it.
netstat -ano -p tcp | findstr /r /c:":%PORT% .*LISTENING" >nul
if not errorlevel 1 (
    echo Port %PORT% is already in use - SecurePulse is probably running already: %URL%
    if "%OPEN_BROWSER%"=="1" start "" "%URL%"
    exit /b 0
)

set "ASPNETCORE_ENVIRONMENT=Development"
set "ASPNETCORE_URLS=%URL%"
rem Placeholder client IDs: they only switch on the consent-link screens (see README, "Live demo").
set "Onboarding__AppClientId=11111111-1111-1111-1111-111111111111"
set "Onboarding__RemediationAppClientId=22222222-2222-2222-2222-222222222222"
set "Onboarding__ConfigurationAppClientId=33333333-3333-3333-3333-333333333333"
rem PDF reports also need Reports__QuestPdfLicense (your organisation's QuestPDF tier); not set here.

echo Building SecurePulse...
dotnet build src\SecurePulse.Web --nologo -v q
if errorlevel 1 (
    echo.
    echo Build failed - see the errors above.
    pause
    exit /b 1
)

if "%OPEN_BROWSER%"=="1" (
    rem Opens the browser as soon as the portal answers, giving up after 60 seconds.
    start "" /b powershell -NoProfile -ExecutionPolicy Bypass -Command "for ($i = 0; $i -lt 60; $i++) { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 '%URL%' | Out-Null; Start-Process '%URL%'; break } catch { Start-Sleep -Seconds 1 } }"
)

echo.
echo Starting SecurePulse at %URL%  (Ctrl+C to stop)
echo.
dotnet run --project src\SecurePulse.Web --no-build --no-launch-profile
