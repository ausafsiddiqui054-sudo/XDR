@echo off
setlocal
rem ---------------------------------------------------------------------------
rem  SecurePulse - start the portal on its PostgreSQL database.
rem  Run setup-database.bat once first. The first start creates the tables and
rem  loads the sample tenants (Development only). Data is kept between starts.
rem
rem  There is no simulated Worker in this mode: queued scans and approved actions
rem  wait for a real Worker (dotnet run --project src\SecurePulse.Worker).
rem  For the self-contained demo use run-demo.bat.
rem
rem  Usage:  run-with-database.bat              build, start, open the browser
rem          run-with-database.bat --no-browser  same, without opening the browser
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

dotnet user-secrets list --project src\SecurePulse.Web 2>nul | findstr /b /c:"ConnectionStrings:SecurePulse" >nul
if errorlevel 1 (
    echo No database is set up yet. Run setup-database.bat first.
    pause
    exit /b 1
)

netstat -ano -p tcp | findstr /r /c:":%PORT% .*LISTENING" >nul
if not errorlevel 1 (
    echo Port %PORT% is already in use - a portal is running already. Stop it first: it may be the in-memory demo.
    pause
    exit /b 1
)

set "ASPNETCORE_ENVIRONMENT=Development"
set "ASPNETCORE_URLS=%URL%"

echo Building SecurePulse...
dotnet build src\SecurePulse.Web --nologo -v q
if errorlevel 1 (
    echo.
    echo Build failed - see the errors above.
    pause
    exit /b 1
)

if "%OPEN_BROWSER%"=="1" (
    rem Opens the browser as soon as the portal answers, giving up after 90 seconds.
    start "" /b powershell -NoProfile -ExecutionPolicy Bypass -Command "for ($i = 0; $i -lt 90; $i++) { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 '%URL%' | Out-Null; Start-Process '%URL%'; break } catch { Start-Sleep -Seconds 1 } }"
)

echo.
echo Starting SecurePulse on PostgreSQL at %URL%  (Ctrl+C to stop)
echo.
dotnet run --project src\SecurePulse.Web --no-build --no-launch-profile
