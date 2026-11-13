@echo off
rem One-time setup of a local PostgreSQL database for Hasinix. See setup-database.ps1 for what it does.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-database.ps1" %*
echo.
pause
