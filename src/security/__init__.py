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


# --- Gemini Safety Filter for Toxicity Detection ---
# Uses Gemini's built-in content safety that returns HARM_CATEGORY_* ratings
GEMINI_SAFETY_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

# Gemini harm categories (all available categories)
HARM_CATEGORIES = [
    "HARM_CATEGORY_SEXUALLY_EXPLICIT",
    "HARM_CATEGORY_HATE_SPEECH",
    "HARM_CATEGORY_HARASSMENT",
    "HARM_CATEGORY_DANGEROUS_CONTENT",
    "HARM_CATEGORY_CIVIC_INTEGRITY",
]

def detect_toxicity(text: str) -> dict:
    """
    Detect toxic content using Gemini's built-in safety filters.
    Uses GEMINI_API_KEY environment variable for authentication.
    Returns: {is_toxic: bool, scores: dict, blocked_categories: list, error: str|None}
    """
    # Read API key at runtime to pick up HF Spaces secrets
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return {
            "is_toxic": False,
            "scores": {},
            "blocked_categories": [],
            "error": "GEMINI_API_KEY not configured"
        }

    try:
        # Set safety settings to BLOCK_NONE to get ratings without blocking
        # This lets us see the safety scores and make our own decision
        safety_settings = [
            {"category": cat, "threshold": "BLOCK_NONE"}
            for cat in HARM_CATEGORIES
        ]

        payload = {
            "contents": [{"parts": [{"text": text}]}],
            "safetySettings": safety_settings,
        }

        response = requests.post(
            f"{GEMINI_SAFETY_URL}?key={api_key}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code != 200:
            error_detail = ""
            try:
                error_detail = response.json().get("error", {}).get("message", "")
            except:
                pass
            return {
                "is_toxic": False,
                "scores": {},
                "blocked_categories": [],
                "error": f"Gemini API error {response.status_code}: {error_detail}"
            }

        data = response.json()
        scores = {}
        blocked_categories = []

        # Check if content was blocked
        if "promptFeedback" in data:
            feedback = data["promptFeedback"]
            if feedback.get("blockReason"):
                blocked_categories.append(feedback["blockReason"])

            # Extract safety ratings
            for rating in feedback.get("safetyRatings", []):
                category = rating.get("category", "UNKNOWN")
                probability = rating.get("probability", "NEGLIGIBLE")

                # Convert probability to score
                prob_scores = {
                    "NEGLIGIBLE": 0.1,
                    "LOW": 0.3,
                    "MEDIUM": 0.6,
                    "HIGH": 0.9
                }
                score = prob_scores.get(probability, 0.0)
                scores[category] = score

                # Block if HIGH probability
                if probability == "HIGH":
                    blocked_categories.append(category)

        # Also check candidate safety ratings
        for candidate in data.get("candidates", []):
            for rating in candidate.get("safetyRatings", []):
                category = rating.get("category", "UNKNOWN")
                probability = rating.get("probability", "NEGLIGIBLE")

                prob_scores = {
                    "NEGLIGIBLE": 0.1,
                    "LOW": 0.3,
                    "MEDIUM": 0.6,
                    "HIGH": 0.9
                }
                score = prob_scores.get(probability, 0.0)
                scores[category] = score

                if probability == "HIGH" and category not in blocked_categories:
                    blocked_categories.append(category)

        return {
            "is_toxic": len(blocked_categories) > 0,
            "scores": scores,
            "blocked_categories": blocked_categories,
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "is_toxic": False,
            "scores": {},
            "blocked_categories": [],
            "error": "Gemini API timeout"
        }
    except Exception as e:
        return {
            "is_toxic": False,
            "scores": {},
            "blocked_categories": [],
            "error": str(e)
        }