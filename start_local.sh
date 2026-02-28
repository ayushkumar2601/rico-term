#!/bin/bash

echo "========================================"
echo "Starting RICO Local Development"
echo "========================================"
echo ""

# Set environment variable
export DEMO_API_URL=http://localhost:8000
echo "[OK] DEMO_API_URL set to $DEMO_API_URL"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "[INFO] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "[INFO] Activating virtual environment..."
source venv/bin/activate

# Install dependencies if needed
echo "[INFO] Checking dependencies..."
pip install -q -e .

echo ""
echo "========================================"
echo "Starting Backend on http://localhost:10000"
echo "========================================"
echo ""
echo "API Docs: http://localhost:10000/docs"
echo "Health: http://localhost:10000/health"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start backend
uvicorn rico.web.main:app --host 0.0.0.0 --port 10000 --reload
