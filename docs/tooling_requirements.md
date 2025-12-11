# Tooling Requirements: Cross-Platform & Free-Tier

## Development Environment

### Required Software (Local Development)

| Tool | Version | Purpose | Installation |
|------|---------|---------|--------------|
| Python | 3.11+ | Runtime environment | python.org or package manager |
| pip | Latest | Package management | Bundled with Python |
| git | Latest | Version control | git-scm.com |
| Virtual environment | Built-in venv | Dependency isolation | `python -m venv` |
| Docker | Latest (optional) | Local testing | docker.com |

**Cross-Platform Compatibility:**
- Linux, macOS, Windows fully supported
- No platform-specific dependencies
- Docker ensures deployment consistency

## Free-Tier Cloud Services

### 1. Hugging Face Spaces (Deployment Platform)

**Specs:**
- **RAM**: 16GB (free tier)
- **CPU**: Shared (sufficient for PoC)
- **Storage**: Persistent (git-based)
- **Cost**: $0/month
- **Docker support**: ✅ Yes
- **Public URL**: ✅ Auto-generated

**Why chosen:**
- Proven success with poc-rag deployment
- No credit card required
- Zero cost for PoC workloads
- Simple git-based deployment

**Setup:**
1. Create account at huggingface.co (free)
2. Create new Space with Docker SDK
3. Configure secrets via UI
4. Git push to deploy

### 2. LLM Providers (At least one required)

| Provider | Free Tier | Rate Limit | API Key Location |
|----------|-----------|------------|------------------|
| **Gemini** | 15 RPM | 1500 requests/day | aistudio.google.com |
| **Groq** | 30 RPM | Free (fastest inference) | console.groq.com |
| **OpenRouter** | Free models | Varies by model | openrouter.ai |

**Configuration:**
- Set at least one of: `GEMINI_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`
- All three recommended for maximum redundancy
- No credit card required for free tiers

### 3. Version Control (GitHub)

**Cost**: $0/month (public repositories)

**Purpose:**
- Source code hosting
- Portfolio demonstration
- HF Spaces deployment source

## Python Dependencies

### Production Requirements

Create `requirements.txt`:

```txt
# Web framework
fastapi>=0.104.0

# ASGI server
uvicorn[standard]>=0.24.0

# Environment variables
python-dotenv>=1.0.0

# Data validation
pydantic>=2.0.0

# HTTP client for LLM calls
requests>=2.31.0

# Security - Rate limiting
slowapi>=0.1.9
```

**Installation:**
```bash
pip install -r requirements.txt
```

**Total size**: ~55MB (lightweight compared to poc-rag's ~800MB)

### Development Dependencies (Optional)

```txt
# Testing
pytest>=7.4.0

# Code quality
black>=23.0.0
ruff>=0.1.0
```

## Deployment Files Required

### 1. Dockerfile

**Purpose**: Container definition for HF Spaces

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make startup script executable
RUN chmod +x start-app.sh

# Expose HF Spaces default port
EXPOSE 7860

# Run startup script
CMD ["./start-app.sh"]
```

**Base image**: python:3.11-slim (~150MB)
**Build time**: ~2-3 minutes on HF Spaces

### 2. start-app.sh

**Purpose**: Environment validation + server startup

```bash
#!/bin/bash

# Validate at least one LLM provider API key is set
if [ -z "$GEMINI_API_KEY" ] && [ -z "$GROQ_API_KEY" ] && [ -z "$OPENROUTER_API_KEY" ]; then
    echo "ERROR: No LLM provider API key configured!"
    echo "Set at least one: GEMINI_API_KEY, GROQ_API_KEY, or OPENROUTER_API_KEY"
    exit 1
fi

# Start uvicorn on HF Spaces default port
exec uvicorn app:app --host 0.0.0.0 --port 7860
```

**Permissions**: `chmod +x start-app.sh`

### 3. app.py

**Purpose**: FastAPI application entry point (HF Spaces convention)

**Location**: Repository root (required by HF Spaces)

### 4. .env.example

**Purpose**: Template for local development

```bash
# Service API Key (for client authentication)
SERVICE_API_KEY=your-secret-api-key-here

# LLM Provider API Keys (set at least one)
GEMINI_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
OPENROUTER_API_KEY=your_openrouter_key_here

# Model selection (optional, defaults in config.py)
GEMINI_MODEL=gemini-2.0-flash-exp
GROQ_MODEL=llama-3.3-70b-versatile
OPENROUTER_MODEL=google/gemini-2.0-flash-exp:free

# Rate limiting (optional, default: 10/minute)
RATE_LIMIT=10/minute
```

**Security**: Never commit actual `.env` file (add to `.gitignore`)

## Tooling Comparison: poc-rag vs LLM-secure-gateway

| Aspect | poc-rag | LLM-secure-gateway |
|--------|---------|------------------|
| **Base image** | python:3.11-slim | python:3.11-slim (same) |
| **Framework** | Streamlit | FastAPI |
| **Security** | None | slowapi + API key auth |
| **Vector DB** | Pinecone | None (not needed) |
| **Embeddings** | sentence-transformers | None (not needed) |
| **Dependencies size** | ~800MB | ~55MB |
| **Build time** | ~5 min | ~2 min |
| **Deployment** | HF Spaces Docker | HF Spaces Docker (same) |
| **LLM providers** | Gemini/Groq/OpenRouter | Gemini/Groq/OpenRouter (same) |
| **Cost** | $0/month | $0/month |

**Key insights**:
- Much simpler dependency footprint (no RAG pipeline)
- Adds security layer (API auth + rate limiting) not present in poc-rag

## Local Development Workflow

### Setup (One-time)

```bash
# Clone repository
git clone https://github.com/vn6295337/LLM-secure-gateway.git
cd LLM-secure-gateway

# Create virtual environment
python3 -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate
# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
# Edit .env and add at least one API key
```

### Running Locally

```bash
# Activate virtual environment
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Run with auto-reload (development)
uvicorn app:app --reload --port 8000

# Access API
# - Swagger UI: http://localhost:8000/docs
# - Health check: http://localhost:8000/health
```

### Testing

```bash
# Health check (no auth required)
curl http://localhost:8000/health

# Query endpoint (requires API key)
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-api-key-here" \
  -d '{"prompt": "Hello world", "max_tokens": 50, "temperature": 0.7}'

# Test validation error (max_tokens too high)
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-api-key-here" \
  -d '{"prompt": "Test", "max_tokens": 9999}'

# Test auth error (missing API key)
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Test"}'

# Test rate limiting (run 11 times quickly)
for i in {1..11}; do
  curl -X POST http://localhost:8000/query \
    -H "Content-Type: application/json" \
    -H "X-API-Key: your-secret-api-key-here" \
    -d '{"prompt": "Test '$i'"}'
done
```

## Deployment Workflow

### Hugging Face Spaces Deployment

```bash
# 1. Create new Space at huggingface.co
#    - Name: llm-router-poc
#    - SDK: Docker
#    - Visibility: Public

# 2. Clone HF Space repository
git clone https://huggingface.co/spaces/vn6295337/llm-router-poc
cd llm-router-poc

# 3. Copy files from local dev
cp -r /path/to/LLM-secure-gateway/* .

# 4. Configure secrets in HF Spaces UI
#    - Go to Space settings → Repository secrets
#    - Add: SERVICE_API_KEY (for client authentication)
#    - Add: GEMINI_API_KEY (or GROQ_API_KEY or OPENROUTER_API_KEY)

# 5. Deploy
git add .
git commit -m "Initial deployment"
git push

# 6. Wait for build (~2-3 min)
#    - Check build logs in HF Spaces UI
#    - Access at: https://huggingface.co/spaces/vn6295337/llm-router-poc
```

## Platform-Specific Notes

### Linux/macOS
- Virtual environment: `source venv/bin/activate`
- Executable permissions: `chmod +x start-app.sh`
- Docker (optional): Install via package manager

### Windows
- Virtual environment: `venv\Scripts\activate`
- Executable permissions: Not needed (handled by Docker)
- Docker Desktop: Install from docker.com
- Line endings: Use `.gitattributes` to force LF for shell scripts

### Cross-Platform Verification

All platforms can:
- ✅ Run Python 3.11+
- ✅ Use git for version control
- ✅ Deploy to HF Spaces (platform-agnostic)
- ✅ Access same free-tier LLM providers
- ✅ Run Docker (optional for local testing)

## Cost Breakdown

| Service | Cost | Notes |
|---------|------|-------|
| Hugging Face Spaces | $0/month | 16GB RAM free tier |
| Gemini API | $0/month | 15 RPM free tier |
| Groq API | $0/month | 30 RPM free tier |
| OpenRouter | $0/month | Free models available |
| GitHub | $0/month | Public repositories |
| **Total** | **$0/month** | Fully free-tier PoC |

## Summary

**Development Requirements:**
- Python 3.11+, pip, git, venv (all free, cross-platform)
- 5 dependencies (FastAPI, uvicorn, dotenv, pydantic, requests)
- Optional: Docker for local container testing

**Deployment Requirements:**
- Hugging Face Spaces account (free, no credit card)
- At least one LLM provider API key (free tier)
- GitHub account (free, public repo)

**Cross-Platform:**
- ✅ Linux, macOS, Windows fully supported
- ✅ No platform-specific code
- ✅ Docker ensures deployment consistency

**Free-Tier:**
- ✅ Zero monthly cost
- ✅ No credit card required
- ✅ Proven successful with poc-rag
