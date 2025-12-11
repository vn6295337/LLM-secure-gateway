#!/bin/bash

# Validate at least one LLM provider API key is set
if [ -z "$GEMINI_API_KEY" ] && [ -z "$GROQ_API_KEY" ] && [ -z "$OPENROUTER_API_KEY" ]; then
    echo "ERROR: No LLM provider API key configured!"
    echo "Set at least one: GEMINI_API_KEY, GROQ_API_KEY, or OPENROUTER_API_KEY"
    exit 1
fi

# Start uvicorn on HF Spaces default port, pointing to src.main
exec uvicorn src.main:app --host 0.0.0.0 --port 7860