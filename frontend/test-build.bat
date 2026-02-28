@echo off
echo Testing production build...
cd /d "%~dp0"
npm run build
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)
echo Build successful!
pause
