#!/bin/bash

# RICO Frontend-Backend Integration Test Script
# Tests the integration between frontend and deployed backend

set -e

echo "🧪 RICO Frontend-Backend Integration Test"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BACKEND_URL="https://rico-term.onrender.com"
FRONTEND_URL="http://localhost:3000"

echo "📍 Backend URL: $BACKEND_URL"
echo "📍 Frontend URL: $FRONTEND_URL"
echo ""

# Test 1: Check environment configuration
echo "Test 1: Environment Configuration"
echo "---------------------------------"
if [ -f ".env.local" ]; then
    echo -e "${GREEN}✓${NC} .env.local exists"
    if grep -q "NEXT_PUBLIC_API_URL" .env.local; then
        echo -e "${GREEN}✓${NC} NEXT_PUBLIC_API_URL is configured"
        API_URL=$(grep NEXT_PUBLIC_API_URL .env.local | cut -d '=' -f2)
        echo "  API URL: $API_URL"
    else
        echo -e "${RED}✗${NC} NEXT_PUBLIC_API_URL not found in .env.local"
        exit 1
    fi
else
    echo -e "${RED}✗${NC} .env.local not found"
    exit 1
fi
echo ""

# Test 2: Check backend health
echo "Test 2: Backend Health Check"
echo "----------------------------"
HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$BACKEND_URL/health")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
HEALTH_BODY=$(echo "$HEALTH_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓${NC} Backend is healthy (HTTP $HTTP_CODE)"
    echo "  Response: $HEALTH_BODY"
else
    echo -e "${RED}✗${NC} Backend health check failed (HTTP $HTTP_CODE)"
    exit 1
fi
echo ""

# Test 3: Check API files exist
echo "Test 3: API Layer Files"
echo "----------------------"
if [ -f "lib/api.ts" ]; then
    echo -e "${GREEN}✓${NC} lib/api.ts exists"
else
    echo -e "${RED}✗${NC} lib/api.ts not found"
    exit 1
fi

if [ -f "components/real-scanner.tsx" ]; then
    echo -e "${GREEN}✓${NC} components/real-scanner.tsx exists"
else
    echo -e "${RED}✗${NC} components/real-scanner.tsx not found"
    exit 1
fi

if [ -f "app/scan/page.tsx" ]; then
    echo -e "${GREEN}✓${NC} app/scan/page.tsx exists"
else
    echo -e "${RED}✗${NC} app/scan/page.tsx not found"
    exit 1
fi
echo ""

# Test 4: Check dependencies
echo "Test 4: Dependencies"
echo "-------------------"
if [ -f "package.json" ]; then
    echo -e "${GREEN}✓${NC} package.json exists"
    
    # Check if node_modules exists
    if [ -d "node_modules" ]; then
        echo -e "${GREEN}✓${NC} node_modules directory exists"
    else
        echo -e "${YELLOW}⚠${NC} node_modules not found. Run: npm install"
    fi
else
    echo -e "${RED}✗${NC} package.json not found"
    exit 1
fi
echo ""

# Test 5: Check if frontend is running
echo "Test 5: Frontend Server"
echo "----------------------"
if curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL" | grep -q "200"; then
    echo -e "${GREEN}✓${NC} Frontend is running at $FRONTEND_URL"
else
    echo -e "${YELLOW}⚠${NC} Frontend not running. Start with: npm run dev"
fi
echo ""

# Test 6: Test backend /scan endpoint (without file)
echo "Test 6: Backend /scan Endpoint"
echo "------------------------------"
SCAN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BACKEND_URL/scan" \
    -F "base_url=http://example.com" 2>&1 || echo "error")

if echo "$SCAN_RESPONSE" | grep -q "422\|400"; then
    echo -e "${GREEN}✓${NC} /scan endpoint is accessible (validation working)"
    echo "  Expected 422/400 without file - endpoint is working"
else
    echo -e "${YELLOW}⚠${NC} Unexpected response from /scan endpoint"
    echo "  Response: $SCAN_RESPONSE"
fi
echo ""

# Summary
echo "=========================================="
echo "✅ Integration Test Summary"
echo "=========================================="
echo ""
echo -e "${GREEN}✓${NC} Environment configured correctly"
echo -e "${GREEN}✓${NC} Backend is healthy and accessible"
echo -e "${GREEN}✓${NC} API layer files are in place"
echo -e "${GREEN}✓${NC} Frontend structure is correct"
echo ""
echo "🚀 Next Steps:"
echo "  1. Start frontend: npm run dev"
echo "  2. Navigate to: http://localhost:3000/scan"
echo "  3. Upload OpenAPI spec: ../demo-api/openapi.yaml"
echo "  4. Enter base URL: http://localhost:8000"
echo "  5. Click 'Start Scan' and verify end-to-end flow"
echo ""
echo "📚 Documentation: See INTEGRATION.md for details"
echo ""
