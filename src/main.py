import os
import re
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import time
from typing import Optional, List

from src.config import llm_client # Import the instantiated LLMClient

# Load environment variables
load_dotenv()

# --- Configuration (Service-level, not LLM client specific) ---
SERVICE_API_KEY = os.getenv("SERVICE_API_KEY")
RATE_LIMIT = os.getenv("RATE_LIMIT", "10/minute")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")  # Comma-separated list
ENABLE_PROMPT_INJECTION_CHECK = os.getenv("ENABLE_PROMPT_INJECTION_CHECK", "true").lower() == "true"

# --- FastAPI App Setup ---
app = FastAPI(
    title="LLM Secure Gateway",
    description="A FastAPI service with secure LLM query routing and multi-provider fallback.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # e.g., ["https://example.com"] or ["*"] for all
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Only allow GET and POST
    allow_headers=["*"],  # Allow all headers (including X-API-Key)
    max_age=600,  # Cache preflight requests for 10 minutes
)

# --- Rate Limiting Setup ---
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- API Key Authentication ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def validate_api_key(api_key: str = Depends(api_key_header)):
    if not SERVICE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Service API key not configured on server."
        )
    if api_key != SERVICE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    return api_key

# --- Prompt Injection Detection ---
# Common prompt injection patterns (basic detection)
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|above|prior)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|above|prior)\s+instructions?",
    r"forget\s+(all\s+)?(previous|above|prior)\s+instructions?",
    r"you\s+are\s+now",
    r"new\s+instructions?:",
    r"system\s*:\s*",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[INST]",
    r"\[/INST]",
]

def detect_prompt_injection(prompt: str) -> bool:
    """
    Basic prompt injection detection using pattern matching.
    Returns True if potential injection detected.
    """
    if not ENABLE_PROMPT_INJECTION_CHECK:
        return False

    prompt_lower = prompt.lower()

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            return True

    return False

# --- Pydantic Models for Input Validation and Responses ---
class QueryRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000, example="Explain quantum computing in one sentence")
    max_tokens: int = Field(256, ge=1, le=2048, example=256)
    temperature: float = Field(0.7, ge=0.0, le=2.0, example=0.7)

    @validator('prompt')
    def check_prompt_injection(cls, v):
        """Validate prompt doesn't contain injection attempts"""
        if detect_prompt_injection(v):
            raise ValueError(
                "Potential prompt injection detected. Please rephrase your request."
            )
        return v

class HealthResponse(BaseModel):
    status: str = Field(..., example="healthy")
    provider: Optional[str] = Field(None, example="gemini")
    model: Optional[str] = Field(None, example="gemini-2.0-flash-exp")
    timestamp: float = Field(..., example=1733558400.0)

class QueryResponse(BaseModel):
    response: Optional[str] = Field(None, example="Quantum computing uses quantum mechanics principles...")
    provider: Optional[str] = Field(None, example="gemini")
    latency_ms: int = Field(..., example=1247)
    status: str = Field(..., example="success")
    error: Optional[str] = Field(None, example="All LLM providers failed")

# --- Endpoints ---
@app.get("/health", response_model=HealthResponse, summary="Health Check")
async def health_check(request: Request):
    """
    Checks the health of the service and reports the active LLM provider.
    This endpoint does not require authentication.
    """
    active_provider = None
    active_model = None

    if llm_client.providers:
        # Report the first available provider in the cascade as the active one for health check
        first_provider = llm_client.providers[0]
        active_provider = first_provider["name"]
        active_model = first_provider["model"]

    return HealthResponse(
        status="healthy",
        provider=active_provider,
        model=active_model,
        timestamp=time.time()
    )

@app.post("/query", response_model=QueryResponse, summary="LLM Query Endpoint")
@limiter.limit(RATE_LIMIT)
async def query_llm(request: Request, query: QueryRequest, api_key: str = Depends(validate_api_key)):
    """
    Sends a query to an LLM provider with multi-provider fallback.
    Requires API key authentication.
    """
    response_content, provider_used, latency_ms, error_message = await llm_client.query_llm_cascade(
        prompt=query.prompt,
        max_tokens=query.max_tokens,
        temperature=query.temperature
    )

    if response_content:
        return QueryResponse(
            response=response_content,
            provider=provider_used,
            latency_ms=latency_ms,
            status="success"
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_message or "All LLM providers failed to generate a response."
        )

# Optional: Root endpoint for basic access
@app.get("/", include_in_schema=False)
async def read_root():
    return {"message": "Welcome to the LLM Secure Gateway. Access /docs for API documentation."}
