#!/bin/bash

# Load environment variables from .env file
if [ -f .env ]; then
    while IFS='=' read -r key value || [ -n "$key" ]; do
        # Ignore comments and empty lines
        if [[ ! "$key" =~ ^# && -n "$key" ]]; then
            # Remove leading/trailing whitespace and quotes from value
            value=$(echo "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//')
            export "$key=$value"
        fi
    done < .env
    echo "Environment variables loaded from .env"
else
    echo "Error: .env file not found"
    exit 1
fi
