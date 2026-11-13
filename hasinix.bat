@echo off
setlocal EnableExtensions
rem =============================================================================
rem  Hasinix - one launcher for the portal.
rem
rem    hasinix.bat           show the menu
rem    hasinix.bat demo      start on in-memory sample data, with a simulated Worker
rem    hasinix.bat db        start on the PostgreSQL database
rem    hasinix.bat setup     one-time database setup; asks for the PostgreSQL admin password
rem    hasinix.bat stop      stop the running portal
rem
rem  Add --no-browser after demo or db to skip opening the browser.
rem  A running portal also stops with Ctrl+C in its window.
rem
rem  Database setup takes its defaults from these optional environment variables:
rem    HASINIX_PG_SERVER, HASINIX_PG_PORT, HASINIX_PG_ADMIN, HASINIX_PG_DATABASE,
rem    HASINIX_PG_ROLE, HASINIX_DEFAULT_ADMIN
rem =============================================================================

cd /d "%~dp0"
set "PORT=5106"
set "URL=http://localhost:%PORT%"
set "PROJECT=src\Hasinix.Web"
set "MODE=%~1"
set "OPEN_BROWSER=1"
set "FROM_MENU=0"
if /i "%~1"=="--no-browser" set "MODE="
if /i "%~1"=="--no-browser" set "OPEN_BROWSER=0"
if /i "%~2"=="--no-browser" set "OPEN_BROWSER=0"
if not "%MODE%"=="" goto dispatch

set "FROM_MENU=1"
echo.
echo   Hasinix
echo.
echo   1  Start the demo          sample data, nothing to set up
echo   2  Start on the database   needs option 3 once
echo   3  Set up the database     one time, asks for the PostgreSQL admin password
echo   4  Stop the running portal
echo   5  Exit
echo.
set "CHOICE="
set /p "CHOICE=Choose 1-5: "
if "%CHOICE%"=="1" set "MODE=demo"
if "%CHOICE%"=="2" set "MODE=db"
if "%CHOICE%"=="3" set "MODE=setup"
if "%CHOICE%"=="4" set "MODE=stop"
if "%MODE%"=="" exit /b 0
echo.

:dispatch
if /i "%MODE%"=="demo" goto demo
if /i "%MODE%"=="db" goto db
if /i "%MODE%"=="database" goto db
if /i "%MODE%"=="setup" goto setup
if /i "%MODE%"=="stop" goto stop
echo Unknown option "%MODE%". Use demo, db, setup or stop.
goto fail

rem ----------------------------------------------------------------------------- demo
:demo
call :need_dotnet
if errorlevel 1 goto fail
call :is_running
if errorlevel 1 goto demo_start
echo A portal is already running at %URL%
if "%OPEN_BROWSER%"=="1" start "" "%URL%"
exit /b 0

:demo_start
rem Placeholder client IDs: they only switch on the consent-link screens.
set "Onboarding__AppClientId=11111111-1111-1111-1111-111111111111"
set "Onboarding__RemediationAppClientId=22222222-2222-2222-2222-222222222222"
set "Onboarding__ConfigurationAppClientId=33333333-3333-3333-3333-333333333333"
rem PDF reports also need Reports__QuestPdfLicense, your organisation's QuestPDF tier; not set here.
call :build
if errorlevel 1 goto fail
call :open_when_ready
echo.
echo Starting the Hasinix demo at %URL%   Ctrl+C to stop
echo.
rem The empty connection string keeps the demo on sample data even after a database has been set up.
dotnet run --project %PROJECT% --no-build --no-launch-profile -- --ConnectionStrings:Hasinix=
exit /b 0

rem ----------------------------------------------------------------------------- database
:db
call :need_dotnet
if errorlevel 1 goto fail
dotnet user-secrets list --project %PROJECT% 2>nul | findstr /b /c:"ConnectionStrings:Hasinix" >nul
if errorlevel 1 echo No database is set up yet. Run "hasinix.bat setup" first.
if errorlevel 1 goto fail
call :is_running
if errorlevel 1 goto db_start
echo Port %PORT% is in use: a portal is already running. Stop it first with "hasinix.bat stop".
goto fail

:db_start
rem No simulated Worker in this mode: queued scans and approved actions wait for a real Worker,
rem started with: dotnet run --project src\Hasinix.Worker
call :build
if errorlevel 1 goto fail
call :open_when_ready
echo.
echo Starting Hasinix on PostgreSQL at %URL%   Ctrl+C to stop
echo.
dotnet run --project %PROJECT% --no-build --no-launch-profile
exit /b 0

rem ----------------------------------------------------------------------------- stop
:stop
powershell -NoProfile -ExecutionPolicy Bypass -Command "$c = Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; if (-not $c) { 'No portal is running.'; exit 0 }; $p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $c.OwningProcess); if ($p.Name -ne 'Hasinix.Web.exe') { 'Port %PORT% is used by ' + $p.Name + ', which is not the portal. Left alone.'; exit 1 }; Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; 'Portal stopped.'"
if errorlevel 1 goto fail
if "%FROM_MENU%"=="1" pause
exit /b 0

rem ----------------------------------------------------------------------------- setup
:setup
call :need_dotnet
if errorlevel 1 goto fail
set "HASINIX_SELF=%~f0"
rem The setup itself is the PowerShell at the end of this file.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$t = [IO.File]::ReadAllText($env:HASINIX_SELF); $m = '#__POWER' + 'SHELL__'; Invoke-Expression $t.Substring($t.IndexOf($m))"
if errorlevel 1 goto fail
if "%FROM_MENU%"=="1" pause
exit /b 0

rem ----------------------------------------------------------------------------- helpers
:need_dotnet
where dotnet >nul 2>nul
if errorlevel 1 echo The .NET SDK was not found. Install the .NET 10 SDK from https://dotnet.microsoft.com/download
if errorlevel 1 exit /b 1
exit /b 0

:is_running
rem Exit code 0 when something is listening on the portal's port.
netstat -ano -p tcp | findstr /r /c:":%PORT% .*LISTENING" >nul
exit /b %errorlevel%

:build
set "ASPNETCORE_ENVIRONMENT=Development"
set "ASPNETCORE_URLS=%URL%"
echo Building Hasinix...
dotnet build %PROJECT% --nologo -v q
if errorlevel 1 echo.
if errorlevel 1 echo Build failed - see the errors above.
if errorlevel 1 exit /b 1
exit /b 0

:open_when_ready
if not "%OPEN_BROWSER%"=="1" exit /b 0
rem Opens the browser as soon as the portal answers, giving up after 90 seconds.
start "" /b powershell -NoProfile -ExecutionPolicy Bypass -Command "for ($i = 0; $i -lt 90; $i++) { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 '%URL%' | Out-Null; Start-Process '%URL%'; break } catch { Start-Sleep -Seconds 1 } }"
exit /b 0

:fail
echo.
pause
exit /b 1

rem =============================================================================
rem  Everything below is PowerShell, run by "hasinix.bat setup". cmd never reads it.
rem =============================================================================
#__POWERSHELL__
# One-time setup of a local PostgreSQL database for Hasinix (development).
#   1. Asks for the PostgreSQL administrator password (typed here, hidden, never stored).
#   2. Creates a login role and a database for the portal. The role is an ordinary login:
#      not a superuser, and it cannot create roles or other databases.
#   3. Generates a random password for that role and saves the connection string in .NET
#      user-secrets for the portal and the Worker. It is never printed or written to the repo.
#   4. Registers a default admin: a sign-in name the portal makes an Owner at startup.
# Safe to run again: it keeps the database and its data, gives the role a new password and
# updates the saved connection string.
$ErrorActionPreference = 'Stop'
function Fail([string]$message) { Write-Host ''; Write-Host $message -ForegroundColor Red; exit 1 }
function Setting([string]$name, [string]$default) { $v = [Environment]::GetEnvironmentVariable($name); if ([string]::IsNullOrWhiteSpace($v)) { $default } else { $v } }

$repo = Split-Path -Parent $env:HASINIX_SELF
$Server = Setting 'HASINIX_PG_SERVER' 'localhost'
$Port = Setting 'HASINIX_PG_PORT' '5432'
$Admin = Setting 'HASINIX_PG_ADMIN' 'postgres'
$Database = Setting 'HASINIX_PG_DATABASE' 'hasinix'
$AppRole = Setting 'HASINIX_PG_ROLE' 'hasinix'
# The development sign-in's "Owner" persona. With Microsoft Entra sign-in, use your own sign-in name.
$DefaultAdmin = Setting 'HASINIX_DEFAULT_ADMIN' 'owner@securepulse.dev'

# Names go into SQL as identifiers, so only plain lowercase names are accepted.
foreach ($name in @($Database, $AppRole)) {
    if ($name -notmatch '^[a-z_][a-z0-9_]{0,62}$') { Fail "'$name' isn't a plain lowercase PostgreSQL name (letters, digits, underscore)." }
}
if ($Server -notmatch '^[A-Za-z0-9._-]+$') { Fail "'$Server' isn't a valid server name." }
if ($Port -notmatch '^\d{1,5}$') { Fail "'$Port' isn't a port number." }
if ($Admin -notmatch '^[A-Za-z0-9_.-]+$') { Fail "'$Admin' isn't a valid PostgreSQL user name." }
if ($DefaultAdmin -notmatch '^[^@\s;"'']+@[^@\s;"'']+\.[^@\s;"'']+$') { Fail "'$DefaultAdmin' isn't a sign-in name like you@company.com." }

$psql = (Get-Command psql -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
if (-not $psql) {
    $psql = Get-ChildItem 'C:\Program Files\PostgreSQL\*\bin\psql.exe' -ErrorAction SilentlyContinue |
        Sort-Object { [int]($_.Directory.Parent.Name -replace '\D', '') } -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $psql) { Fail 'psql was not found. Install PostgreSQL 14 or newer, or add its bin folder to PATH.' }

Write-Host "Hasinix database setup: server ${Server}:$Port, database '$Database', role '$AppRole'."
$secure = Read-Host "Password for PostgreSQL administrator '$Admin'" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)

# A random password for the portal's own login: 48 hex characters, so it needs no escaping anywhere.
$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$appPassword = -join ($bytes | ForEach-Object { $_.ToString('x2') })

$sql = @'
DO $do$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '__ROLE__') THEN CREATE ROLE __ROLE__ LOGIN; END IF;
END $do$;
ALTER ROLE __ROLE__ LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '__PASSWORD__';
SELECT 'CREATE DATABASE __DB__ OWNER __ROLE__' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '__DB__') \gexec
'@.Replace('__ROLE__', $AppRole).Replace('__DB__', $Database).Replace('__PASSWORD__', $appPassword)

try {
    # The administrator password lives only in this process's environment, for the next command.
    $env:PGPASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $sql | & $psql -h $Server -p $Port -U $Admin -d postgres -w -X -q -v ON_ERROR_STOP=1 -f - | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the role and database (see the message above). Check the '$Admin' password." }

    # Prove the new login works before saving it.
    $env:PGPASSWORD = $appPassword
    $who = & $psql -h $Server -p $Port -U $AppRole -d $Database -w -X -At -c 'select current_user'
    if ($LASTEXITCODE -ne 0 -or $who -ne $AppRole) { Fail "The '$AppRole' login was created but could not connect to '$Database'." }
}
finally {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

$connection = "Host=$Server;Port=$Port;Database=$Database;Username=$AppRole;Password=$appPassword"
# Secrets are piped in as JSON, so the password never appears on a command line.
$webSecrets = @{ 'ConnectionStrings:Hasinix' = $connection; 'Auth:BootstrapOwners:0' = $DefaultAdmin } | ConvertTo-Json -Compress
$workerSecrets = @{ 'ConnectionStrings:Hasinix' = $connection } | ConvertTo-Json -Compress
$webSecrets | & dotnet user-secrets set --project (Join-Path $repo 'src\Hasinix.Web') | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'Could not save the portal''s user-secrets.' }
$workerSecrets | & dotnet user-secrets set --project (Join-Path $repo 'src\Hasinix.Worker') | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'Could not save the Worker''s user-secrets.' }

Write-Host ''
Write-Host "Done. Database '$Database' is ready and the connection string is saved in user-secrets." -ForegroundColor Green
Write-Host "Default admin (Owner): $DefaultAdmin"
Write-Host 'Start the portal on the database with: hasinix.bat db'
Write-Host 'The first start creates the tables and loads the sample tenants. "hasinix.bat demo" still starts the in-memory demo.'
