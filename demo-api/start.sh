#!/bin/bash

# RICO Security Testing Playground
# Starting vulnerable API server...

echo "========================================"
echo "RICO Security Testing Playground"
echo "========================================"
echo ""
echo "Starting vulnerable API server..."
echo "WARNING: This API contains intentional vulnerabilities"
echo "DO NOT use in production!"
echo ""
echo "API will be available at:"
echo " - http://localhost:8000"
echo " - Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo "========================================"
echo ""

# Get the directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Check if uvicorn is installed
if ! command -v uvicorn &> /dev/null
then
    echo "Error: uvicorn is not installed or not in PATH."
    echo "Please install dependencies using: pip install -r ../requirements.txt"
    exit 1
fi

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
