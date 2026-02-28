@echo off
echo Updating pnpm lockfile...
cd /d "%~dp0"
pnpm install
echo Done!
pause
