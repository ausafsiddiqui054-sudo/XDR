<#
  One-time setup of a local PostgreSQL database for Hasinix (development).

  What it does:
    1. Asks for your PostgreSQL administrator password (typed here, hidden, never stored).
    2. Creates a login role and a database for the portal. The role is an ordinary login:
       not a superuser, and it cannot create roles or other databases.
    3. Generates a random password for that role and saves the connection string in
       .NET user-secrets for the portal and the Worker. It is never printed or written to the repo.
    4. Registers a default admin: a sign-in name the portal makes an Owner at startup
       (Auth:BootstrapOwners).

  Safe to run again: it keeps the database and its data, gives the role a new password
  and updates the saved connection string.

  Usage:  setup-database.bat                     (or: powershell -File setup-database.ps1)
          setup-database.bat -Admin postgres -Server localhost -Port 5432
          setup-database.bat -DefaultAdmin you@yourcompany.com
#>
param(
    [string]$Server = 'localhost',
    [int]$Port = 5432,
    [string]$Admin = 'postgres',
    [string]$Database = 'hasinix',
    [string]$AppRole = 'hasinix',
    # The development sign-in's "Owner" persona. With Microsoft Entra sign-in, use your own sign-in name.
    [string]$DefaultAdmin = 'owner@securepulse.dev'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path

function Fail([string]$message) { Write-Host ''; Write-Host $message -ForegroundColor Red; exit 1 }

# Names go into SQL as identifiers, so only plain lowercase names are accepted.
foreach ($name in @($Database, $AppRole)) {
    if ($name -notmatch '^[a-z_][a-z0-9_]{0,62}$') { Fail "'$name' isn't a plain lowercase PostgreSQL name (letters, digits, underscore)." }
}
if ($Server -notmatch '^[A-Za-z0-9._-]+$') { Fail "'$Server' isn't a valid server name." }
if ($DefaultAdmin -notmatch '^[^@\s;"'']+@[^@\s;"'']+\.[^@\s;"'']+$') { Fail "'$DefaultAdmin' isn't a sign-in name like you@company.com." }

$psql = (Get-Command psql -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
if (-not $psql) {
    $psql = Get-ChildItem 'C:\Program Files\PostgreSQL\*\bin\psql.exe' -ErrorAction SilentlyContinue |
        Sort-Object { [int]($_.Directory.Parent.Name -replace '\D', '') } -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $psql) { Fail 'psql was not found. Install PostgreSQL 14 or newer, or add its bin folder to PATH.' }
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { Fail 'The .NET SDK was not found.' }

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
Write-Host 'Start the portal on the database with run-with-database.bat. The first start creates the tables'
Write-Host 'and loads the sample tenants. run-demo.bat still starts the in-memory demo.'
