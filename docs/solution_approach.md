# Solution Approach: LLM Router REST API

## Architecture

FastAPI service with two primary endpoints:

1. **GET /health** - Health check endpoint
   - Returns service status
   - Reports active LLM provider
   - Timestamp for uptime monitoring

2. **POST /query** - LLM query endpoint
   - Accepts JSON payload: `{prompt, max_tokens, temperature}`
   - Returns JSON response: `{response, provider, latency, status}`
   - Automatic provider fallback on failure

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Web Framework | FastAPI | Async support, automatic OpenAPI docs, type validation |
| ASGI Server | Uvicorn | Production-grade async server |
| LLM Providers | Gemini → Groq → OpenRouter | Multi-provider cascade (reuse from poc-rag) |
| Configuration | python-dotenv + config.py | Environment-based secrets management |
| Security | slowapi + API key auth | Rate limiting and access control |
| Deployment | Hugging Face Spaces (Docker) | Free tier, 16GB RAM, proven success with poc-rag |
| Container | Python 3.11-slim | Lightweight, cross-platform compatibility |

## Data Flow

```
Client Request (POST /query with X-API-Key header)
        |
        v
+------------------+
| API Key Auth     |  Validate X-API-Key header
+------------------+
        |
        v
+------------------+
| Rate Limiter     |  Check per-client request quota
| (slowapi)        |  Return 429 if exceeded
+------------------+
        |
        v
+------------------+
| FastAPI Endpoint |  Validate input (Pydantic)
+------------------+
        |
        v
+------------------+
| LLM Cascade      |  Try Gemini → Groq → OpenRouter
| (src/config.py)  |  Return on first success
+------------------+
        |
        v
+------------------+
| Response Builder |  Format: {response, provider, latency, status}
+------------------+
        |
        v
JSON Response to Client
```

## Multi-Provider Fallback Logic

Reuse pattern from poc-rag:

1. **Primary**: Gemini API (15 RPM free tier)
   - Try first if `GEMINI_API_KEY` is set
   - On failure → fallback to Groq

2. **Fallback 1**: Groq API (30 RPM free tier, fastest)
   - Try if Gemini fails or key missing
   - On failure → fallback to OpenRouter

3. **Fallback 2**: OpenRouter (free models available)
   - Last resort provider
   - On failure → return error to client

## Deployment Strategy

**Hugging Face Spaces** (same as poc-rag):

- **Why**: Free tier with 16GB RAM, Docker support, proven successful
- **Entry point**: `app.py` at repository root (HF Spaces convention)
- **Port**: 7860 (HF Spaces default)
- **Environment**: Secrets configured via HF Spaces UI
- **Startup**: `start-app.sh` validates environment before launching uvicorn

## API Design

### Endpoint 1: Health Check

**Request:**
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "provider": "gemini",
  "model": "gemini-2.0-flash-exp",
  "timestamp": 1733558400.0
}
```

**Note**: Health check does NOT require authentication (public monitoring endpoint).

### Endpoint 2: LLM Query

**Request:**
```http
POST /query
Content-Type: application/json
X-API-Key: your-api-key-here

{
  "prompt": "Explain quantum computing in one sentence",
  "max_tokens": 256,
  "temperature": 0.7
}
```

**Response (Success):**
```json
{
  "response": "Quantum computing uses quantum mechanics principles...",
  "provider": "gemini",
  "latency_ms": 1247,
  "status": "success"
}
```

**Response (Validation Error):**
```json
{
  "detail": [
    {
      "loc": ["body", "max_tokens"],
      "msg": "ensure this value is less than or equal to 2048",
      "type": "value_error.number.not_le"
    }
  ]
}
```

**Response (Authentication Error):**
```json
{
  "detail": "Invalid or missing API key"
}
```

**Response (Rate Limit Exceeded):**
```json
{
  "error": "Rate limit exceeded: 10 per 1 minute"
}
```

**Response (LLM Provider Failure):**
```json
{
  "response": null,
  "provider": null,
  "latency_ms": 0,
  "status": "error",
  "error": "All LLM providers failed"
}
```

## Reuse from poc-rag

| Component | Reuse Strategy |
|-----------|----------------|
| Deployment platform | Hugging Face Spaces (Docker) - same approach |
| LLM provider pattern | Multi-provider cascade with graceful fallback |
| Configuration | Environment variables via python-dotenv |
| Entry points | app.py at root for HF Spaces compatibility |
| Startup script | start-app.sh with environment validation |
| Free-tier services | Same LLM providers (Gemini, Groq, OpenRouter) |

## Differences from poc-rag

| Aspect | poc-rag | LLM-secure-gateway |
|--------|---------|------------------|
| Interface | Streamlit UI | REST API (FastAPI) |
| Complexity | 5 components (RAG pipeline) | 2 endpoints (simple router) |
| Primary skill | RAG architecture | **Secure REST API design** |
| Security | None (public UI) | **API key auth + rate limiting** |
| Input validation | Streamlit widgets | **Pydantic models with constraints** |
| Use case | Document Q&A | **LLM service integration with access control** |
| Dependencies | sentence-transformers, Pinecone, Streamlit | FastAPI, uvicorn, slowapi |

## Performance Targets

- **Response time**: < 10s per query (LLM-dependent)
- **Cold start**: < 60s (Docker container initialization)
- **Uptime**: 99%+ through multi-provider redundancy
- **Cost**: $0/month (all free tiers)

## Error Handling

1. **Input validation**: Pydantic models reject malformed requests (returns 422 with details)
2. **Authentication failures**: Missing/invalid API key (returns 401)
3. **Rate limit exceeded**: Client exceeded quota (returns 429)
4. **Provider failures**: Automatic cascade to next provider
5. **All providers fail**: Return error response with 500 status
6. **Missing API keys**: Startup validation prevents deployment

## Security Implementation

### 1. API Key Authentication

**Implementation:**
```python
from fastapi import Security, HTTPException
from fastapi.security import APIKeyHeader

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def validate_api_key(api_key: str = Security(api_key_header)):
    if api_key != os.getenv("SERVICE_API_KEY"):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return api_key
```

**Configuration:**
- Set `SERVICE_API_KEY` environment variable
- Clients pass via `X-API-Key` header
- Health check endpoint bypasses auth (public)

**Benefits:**
- Simple access control
- No database required
- Demonstrates security fundamentals

### 2. Rate Limiting (slowapi)

**Implementation:**
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/query")
@limiter.limit("10/minute")
async def query_llm(...):
    ...
```

**Configuration:**
- 10 requests per minute per client IP
- Configurable via environment variable
- Returns 429 with retry-after header

**Benefits:**
- Prevents abuse
- Protects LLM provider quotas
- Production-ready pattern

### 3. Input Validation (Pydantic)

**Implementation:**
```python
from pydantic import BaseModel, Field

class QueryRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
    max_tokens: int = Field(256, ge=1, le=2048)
    temperature: float = Field(0.7, ge=0.0, le=2.0)
```

**Constraints:**
- Prompt: 1-4000 characters
- max_tokens: 1-2048 (prevents excessive costs)
- temperature: 0.0-2.0 (LLM parameter range)

**Benefits:**
- Automatic validation
- Clear error messages
- API contract enforcement

## Security Considerations

**Implemented:**
- ✅ **API Key Authentication**: X-API-Key header validation
- ✅ **Rate Limiting**: 10 req/min per client IP (slowapi)
- ✅ **Input Validation**: Pydantic constraints on all parameters
- ✅ **LLM API Keys**: Environment variables only (never hardcoded)

**Not Implemented (PoC scope):**
- CORS configuration (assumes trusted clients)
- HTTPS enforcement (HF Spaces handles TLS)
- Request logging / audit trail
- Multi-tier API keys (all keys have equal access)
- Prompt injection detection (basic sanitization only)

## Non-Goals (Intentionally Excluded)

- Vector database integration
- RAG pipeline
- Streaming responses
- User authentication
- Per-user rate limiting
- Persistent storage
- Logging infrastructure
- Horizontal scaling

These are excluded to keep the PoC focused on **REST API design** and **multi-provider orchestration**.
