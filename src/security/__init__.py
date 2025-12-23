"""
Security utilities for the LLM Secure Gateway
"""

import os
import re
import requests
from fastapi import HTTPException, Depends, status
from fastapi.security import APIKeyHeader

# --- Security Configuration ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY")
ENABLE_PROMPT_INJECTION_CHECK = os.getenv("ENABLE_PROMPT_INJECTION_CHECK", "true").lower() == "true"

# --- Prompt Injection Detection ---
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|above|prior)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|above|prior)\s+instructions?",
    r"you\s+are\s+now",
    r"system\s*:\s*",
]

def detect_prompt_injection(prompt: str) -> bool:
    """Detect potential prompt injection attacks"""
    if not ENABLE_PROMPT_INJECTION_CHECK:
        return False
    prompt_lower = prompt.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            return True
    return False

# --- PII Detection ---
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "tax_id": r"\b\d{2}-\d{7}\b",
    "api_key": r"(sk|pk|api|bearer)[_-]?[a-zA-Z0-9]{20,}",
}

def detect_pii(prompt: str) -> dict:
    """Detect PII in prompt, returns {has_pii: bool, pii_types: list, matches: dict}"""
    matches = {}
    pii_types = []

    for pii_type, pattern in PII_PATTERNS.items():
        found = re.findall(pattern, prompt, re.IGNORECASE)
        if found:
            pii_types.append(pii_type)
            matches[pii_type] = len(found)

    return {
        "has_pii": len(pii_types) > 0,
        "pii_types": pii_types,
        "matches": matches
    }

# --- API Key Validation ---
async def validate_api_key(api_key: str = Depends(api_key_header)):
    """Validate API key for request authentication"""
    if not SERVICE_API_KEY:
        raise HTTPException(status_code=500, detail="Server misconfiguration: API Key missing")
    if api_key != SERVICE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key


# --- Perspective API Toxicity Detection ---
# Uses Google API Client library as per official documentation
PERSPECTIVE_DISCOVERY_URL = "https://commentanalyzer.googleapis.com/$discovery/rest?version=v1alpha1"

# Attributes to check with Perspective API
PERSPECTIVE_ATTRIBUTES = {
    "TOXICITY": {},
    "SEVERE_TOXICITY": {},
    "IDENTITY_ATTACK": {},
    "INSULT": {},
    "PROFANITY": {},
    "THREAT": {},
    "SEXUALLY_EXPLICIT": {},
}

def detect_toxicity(text: str) -> dict:
    """
    Detect toxic content using Google's Perspective API.
    Uses API_KEY environment variable for authentication.
    Uses Google API Client library as per official documentation.
    Returns: {is_toxic: bool, scores: dict, blocked_categories: list, error: str|None}
    """
    # Read API key at runtime to pick up HF Spaces secrets
    api_key = os.getenv("API_KEY")
    toxicity_threshold = float(os.getenv("TOXICITY_THRESHOLD", "0.7"))

    if not api_key:
        return {
            "is_toxic": False,
            "scores": {},
            "blocked_categories": [],
            "error": "API_KEY not configured for Perspective API"
        }

    try:
        from googleapiclient import discovery
        from googleapiclient.errors import HttpError

        # Build client using Google API Client library (per documentation)
        client = discovery.build(
            "commentanalyzer",
            "v1alpha1",
            developerKey=api_key,
            discoveryServiceUrl=PERSPECTIVE_DISCOVERY_URL,
            static_discovery=False,
        )

        analyze_request = {
            "comment": {"text": text},
            "requestedAttributes": PERSPECTIVE_ATTRIBUTES,
            "languages": ["en"]
        }

        response = client.comments().analyze(body=analyze_request).execute()

        scores = {}
        blocked_categories = []

        for attr, attr_data in response.get("attributeScores", {}).items():
            score = attr_data.get("summaryScore", {}).get("value", 0)
            scores[attr] = round(score, 3)
            if score >= toxicity_threshold:
                blocked_categories.append(attr)

        return {
            "is_toxic": len(blocked_categories) > 0,
            "scores": scores,
            "blocked_categories": blocked_categories,
            "error": None
        }

    except HttpError as e:
        error_msg = str(e)
        if hasattr(e, 'reason'):
            error_msg = e.reason
        return {
            "is_toxic": False,
            "scores": {},
            "blocked_categories": [],
            "error": f"Perspective API error: {error_msg}"
        }
    except Exception as e:
        return {
            "is_toxic": False,
            "scores": {},
            "blocked_categories": [],
            "error": str(e)
        }