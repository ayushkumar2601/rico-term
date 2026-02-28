@echo off
REM RICO Frontend-Backend Integration Test Script (Windows)
REM Tests the integration between frontend and deployed backend

echo.
echo RICO Frontend-Backend Integration Test
echo ==========================================
echo.

set BACKEND_URL=https://rico-term.onrender.com
set FRONTEND_URL=http://localhost:3000

echo Backend URL: %BACKEND_URL%
echo Frontend URL: %FRONTEND_URL%
echo.

REM Test 1: Check environment configuration
echo Test 1: Environment Configuration
echo ---------------------------------
if exist .env.local (
    echo [OK] .env.local exists
    findstr /C:"NEXT_PUBLIC_API_URL" .env.local >nul
    if %ERRORLEVEL% EQU 0 (
        echo [OK] NEXT_PUBLIC_API_URL is configured
    ) else (
        echo [FAIL] NEXT_PUBLIC_API_URL not found in .env.local
        exit /b 1
    )
) else (
    echo [FAIL] .env.local not found
    exit /b 1
)
echo.

REM Test 2: Check backend health
echo Test 2: Backend Health Check
echo ----------------------------
curl -s -o nul -w "%%{http_code}" %BACKEND_URL%/health > temp_status.txt
set /p HTTP_CODE=<temp_status.txt
del temp_status.txt

if "%HTTP_CODE%"=="200" (
    echo [OK] Backend is healthy (HTTP %HTTP_CODE%)
) else (
    echo [FAIL] Backend health check failed (HTTP %HTTP_CODE%)
    exit /b 1
)
echo.

REM Test 3: Check API files exist
echo Test 3: API Layer Files
echo ----------------------
if exist lib\api.ts (
    echo [OK] lib\api.ts exists
) else (
    echo [FAIL] lib\api.ts not found
    exit /b 1
)

if exist components\real-scanner.tsx (
    echo [OK] components\real-scanner.tsx exists
) else (
    echo [FAIL] components\real-scanner.tsx not found
    exit /b 1
)

if exist app\scan\page.tsx (
    echo [OK] app\scan\page.tsx exists
) else (
    echo [FAIL] app\scan\page.tsx not found
    exit /b 1
)
echo.

REM Test 4: Check dependencies
echo Test 4: Dependencies
echo -------------------
if exist package.json (
    echo [OK] package.json exists
    
    if exist node_modules (
        echo [OK] node_modules directory exists
    ) else (
        echo [WARN] node_modules not found. Run: npm install
    )
) else (
    echo [FAIL] package.json not found
    exit /b 1
)
echo.

REM Test 5: Check if frontend is running
echo Test 5: Frontend Server
echo ----------------------
curl -s -o nul -w "%%{http_code}" %FRONTEND_URL% > temp_status.txt 2>nul
set /p FRONTEND_STATUS=<temp_status.txt
del temp_status.txt 2>nul

if "%FRONTEND_STATUS%"=="200" (
    echo [OK] Frontend is running at %FRONTEND_URL%
) else (
    echo [WARN] Frontend not running. Start with: npm run dev
)
echo.

REM Summary
echo ==========================================
echo Integration Test Summary
echo ==========================================
echo.
echo [OK] Environment configured correctly
echo [OK] Backend is healthy and accessible
echo [OK] API layer files are in place
echo [OK] Frontend structure is correct
echo.
echo Next Steps:
echo   1. Start frontend: npm run dev
echo   2. Navigate to: http://localhost:3000/scan
echo   3. Upload OpenAPI spec: ..\demo-api\openapi.yaml
echo   4. Enter base URL: http://localhost:8000
echo   5. Click 'Start Scan' and verify end-to-end flow
echo.
echo Documentation: See INTEGRATION.md for details
echo.
