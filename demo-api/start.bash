#!/bin/bash

echo "========================================"
echo "RICO Security Testing Playground"
echo "========================================"
echo
echo "Starting vulnerable API server..."
echo "WARNING: This API contains intentional vulnerabilities"
echo "DO NOT use in production!"
echo
echo "API will be available at:"
echo "- http://localhost:8000"
echo "- Docs: http://localhost:8000/docs"
echo
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo

# Change directory to script location
cd "$(dirname "$0")"

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000