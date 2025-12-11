# Operations Guide - LLM Secure Gateway

This guide covers running, deploying, monitoring, and troubleshooting the LLM Secure Gateway.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development](#local-development)
3. [Configuration](#configuration)
4. [Deployment](#deployment)
5. [Monitoring](#monitoring)
6. [Troubleshooting](#troubleshooting)
7. [Common Operations](#common-operations)

---

## Prerequisites

### Required

- **Python**: 3.11 or higher
- **Git**: For cloning repository
- **API Keys**: At least one LLM provider API key

### Recommended

- **Virtual Environment**: `python-venv` or `conda`
- **curl**: For API testing
- **Docker**: For containerized deployment (optional)

### Get API Keys

| Provider | Sign Up | Free Tier |
|----------|---------|-----------|
| Gemini | https://ai.google.dev/ | 15 RPM |
| Groq | https://console.groq.com/ | 30 RPM |
| OpenRouter | https://openrouter.ai/ | Various free models |

---

## Local Development

### Quick Start (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/vn6295337/LLM-secure-gateway
cd LLM-secure-gateway

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env and add your API keys

# 5. Run server
uvicorn main:app --reload

# 6. Test
curl http://localhost:8000/health
```

### Development Server Options

**Basic** (auto-reload on code changes):
```bash
uvicorn main:app --reload
```

**Custom Port**:
```bash
uvicorn main:app --port 8080 --reload
```

**Custom Host** (allow external connections):
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

**Production Mode** (no reload, multiple workers):
```bash
uvicorn main:app --workers 4
```

---

## Configuration

### Environment Variables

All configuration via environment variables for portability.

#### Required

At least ONE LLM provider key must be set:

```bash
# Option 1: Gemini (Google)
GEMINI_API_KEY=AIza...

# Option 2: Groq
GROQ_API_KEY=gsk_...

# Option 3: OpenRouter
OPENROUTER_API_KEY=sk-or-v1-...
```

#### Service Configuration

```bash
# API key for this service (create your own secure key)
SERVICE_API_KEY=your-secure-api-key-here

# Rate limiting (default: 10/minute)
RATE_LIMIT=10/minute
```

#### Optional Model Configuration

```bash
# Override default models
GEMINI_MODEL=gemini-2.0-flash-exp
GROQ_MODEL=llama-3.3-70b-versatile
OPENROUTER_MODEL=google/gemini-2.0-flash-exp:free
```

### Configuration Files

#### Local Development

Create `.env` file in project root:

```bash
# .env
SERVICE_API_KEY=test-api-key-local
GEMINI_API_KEY=your_gemini_key
GROQ_API_KEY=your_groq_key
OPENROUTER_API_KEY=your_openrouter_key
RATE_LIMIT=10/minute
```

**Important**: `.env` is in `.gitignore` - never commit it!

#### Hugging Face Spaces

Configure in Space settings UI:

1. Go to Space settings → Repository secrets
2. Add each secret individually:
   - Name: `SERVICE_API_KEY`
   - Value: `your-secure-key`
3. Repeat for all LLM provider keys

#### Docker

Pass via `-e` flag or `--env-file`:

```bash
# Individual variables
docker run -e SERVICE_API_KEY=abc123 -e GEMINI_API_KEY=xyz789 ...

# Or use env file
docker run --env-file .env LLM-secure-gateway
```

---

## Deployment

### Option 1: Hugging Face Spaces (Recommended)

**Why**: Free tier, 16GB RAM, auto-scaling, HTTPS included

**Steps**:

1. **Create Space**
   ```
   Go to: https://huggingface.co/new-space
   - Name: secure-llm-api
   - SDK: Docker
   - Template: Blank
   ```

2. **Configure Secrets**
   ```
   Settings → Repository secrets → Add each:
   - SERVICE_API_KEY
   - GEMINI_API_KEY (or others)
   ```

3. **Push Code**
   ```bash
   git remote add hf https://huggingface.co/spaces/YOUR_USERNAME/secure-llm-api
   git push hf main
   ```

4. **Wait for Build** (~2-3 minutes)

5. **Verify**
   ```bash
   curl https://YOUR_USERNAME-secure-llm-api.hf.space/health
   ```

**Live Example**: https://vn6295337-secure-llm-api.hf.space

---

### Option 2: Docker (Local or Cloud)

**Build Image**:
```bash
docker build -t secure-llm-api .
```

**Run Container**:
```bash
docker run -p 7860:7860 \
  -e SERVICE_API_KEY=your-key \
  -e GEMINI_API_KEY=your-gemini-key \
  secure-llm-api
```

**Test**:
```bash
curl http://localhost:7860/health
```

---

### Option 3: Cloud Run (GCP)

**Prerequisites**: GCP account with billing enabled

**Deploy**:
```bash
# Authenticate
gcloud auth login

# Deploy
gcloud run deploy secure-llm-api \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

**Set Secrets**:
```bash
gcloud run services update secure-llm-api \
  --update-env-vars SERVICE_API_KEY=your-key,GEMINI_API_KEY=your-gemini-key
```

---

## Monitoring

### Health Checks

**Endpoint**: `GET /health`

**Expected Response**:
```json
{
  "status": "healthy",
  "provider": "gemini",
  "model": "gemini-2.0-flash-exp",
  "timestamp": 1765193753.29
}
```

**Monitor Script**:
```bash
#!/bin/bash
while true; do
  STATUS=$(curl -s https://YOUR-API-URL/health | jq -r '.status')
  if [ "$STATUS" != "healthy" ]; then
    echo "ALERT: Service unhealthy!"
  fi
  sleep 60
done
```

---

### Application Logs

#### Local Development

Logs appear in terminal:
```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

#### Hugging Face Spaces

View logs in Space UI:
1. Go to your Space
2. Click "Logs" tab
3. See real-time output

#### Docker

```bash
docker logs <container-id>
```

---

### Performance Metrics

**What to Monitor**:

| Metric | How to Measure | Threshold |
|--------|----------------|-----------|
| Response Time | `latency_ms` in response | < 500ms |
| Error Rate | Failed requests / total | < 1% |
| Provider Distribution | Track which provider used | Balanced |
| Rate Limit Hits | 429 responses | Adjust limit if frequent |

**Sample Monitoring Query**:
```bash
# Get response times for last 10 requests
for i in {1..10}; do
  curl -s -X POST https://YOUR-API-URL/query \
    -H "X-API-Key: YOUR_KEY" \
    -d '{"prompt": "test"}' | jq '.latency_ms'
done | awk '{sum+=$1; n++} END {print "Average:", sum/n, "ms"}'
```

---

## Troubleshooting

### Issue 1: Service Won't Start

**Symptoms**:
```
ERROR: No LLM provider API key configured!
```

**Cause**: Missing LLM provider API keys

**Solution**:
```bash
# Check environment
echo $GEMINI_API_KEY
echo $GROQ_API_KEY

# Set at least one
export GEMINI_API_KEY=your-key-here

# Or update .env file
```

---

### Issue 2: 401 Unauthorized

**Symptoms**:
```json
{"detail": "Invalid or missing API key"}
```

**Cause**: Missing or incorrect `X-API-Key` header

**Solution**:
```bash
# Correct request
curl -H "X-API-Key: YOUR_SERVICE_KEY" ...

# Check what key is expected
echo $SERVICE_API_KEY
```

---

### Issue 3: 422 Validation Error

**Symptoms**:
```json
{"detail": [{"type": "string_too_short", "loc": ["body", "prompt"], ...}]}
```

**Cause**: Invalid request parameters

**Solution**: Check parameter constraints:
- `prompt`: 1-4000 characters
- `max_tokens`: 1-2048
- `temperature`: 0.0-2.0

```bash
# Valid request
curl -X POST ... -d '{
  "prompt": "Valid question here",
  "max_tokens": 100,
  "temperature": 0.7
}'
```

---

### Issue 4: 500 Internal Server Error

**Symptoms**:
```json
{"response": null, "error": "All LLM providers failed"}
```

**Cause**: All LLM providers returned errors

**Possible Reasons**:
- Provider API keys are invalid
- Providers are rate-limited
- Network connectivity issues

**Solution**:
1. Check API keys are valid
2. Verify provider status pages:
   - Gemini: https://status.cloud.google.com/
   - Groq: https://status.groq.com/
   - OpenRouter: https://status.openrouter.ai/
3. Check application logs for specific errors
4. Test each provider individually:
   ```bash
   # Test Gemini
   curl -H "Authorization: Bearer $GEMINI_API_KEY" \
     https://generativelanguage.googleapis.com/v1beta/models
   ```

---

### Issue 5: Slow Response Times

**Symptoms**: `latency_ms` > 1000ms

**Possible Causes**:
1. Primary provider is slow
2. Network latency
3. Large `max_tokens` value
4. Cold start (first request)

**Solutions**:
1. Check which provider is being used (in response)
2. Try smaller `max_tokens`
3. Wait for cold start to complete (~30s)
4. Use different provider

---

### Issue 6: Rate Limiting Not Working on HF

**Symptoms**: All requests succeed, even when > 10/min

**Cause**: HF Spaces proxy architecture

**Explanation**: Documented behavior - see [deployment_test_results.md](deployment_test_results.md)

**Solution**: Works as designed locally, consider API-key-based limiting for production

---

## Common Operations

### Update API Keys

**Local**:
```bash
# Edit .env file
nano .env

# Restart server
# (uvicorn --reload does this automatically)
```

**HF Spaces**:
1. Go to Space settings → Repository secrets
2. Click secret name
3. Update value
4. Space will automatically rebuild

---

### Change Rate Limit

**Local**:
```bash
# In .env
RATE_LIMIT=20/minute  # Increase to 20 per minute

# Restart server
```

**HF Spaces**:
Add `RATE_LIMIT` environment secret

---

### Add New LLM Provider

1. **Update `src/config.py`**:
   ```python
   self.new_provider_key = os.getenv("NEW_PROVIDER_API_KEY")
   if self.new_provider_key:
       self.providers.append({
           "name": "new_provider",
           "key": self.new_provider_key,
           "model": os.getenv("NEW_PROVIDER_MODEL", "default-model")
       })
   ```

2. **Add provider call logic**:
   ```python
   elif provider_name == "new_provider":
       url = "https://api.newprovider.com/v1/chat/completions"
       # ... implementation
   ```

3. **Update environment variables**

4. **Test locally**

5. **Deploy**

---

### View Live Logs

**HF Spaces**:
1. Go to your Space page
2. Click "Logs" tab
3. See real-time output

**Docker**:
```bash
docker logs -f <container-id>
```

**Local**:
Logs appear in terminal where you ran `uvicorn`

---

### Backup Configuration

**What to Backup**:
- `.env` file (encrypted!)
- HF Spaces secrets list
- API provider keys

**Recommended**:
Store in password manager (1Password, LastPass, etc.)

---

### Roll Back Deployment

**HF Spaces**:
```bash
# Revert to previous commit
git revert HEAD
git push hf main
```

**Docker**:
```bash
# Use previous image tag
docker run secure-llm-api:v1.0
```

---

## Production Checklist

Before going to production, verify:

- [ ] All API keys are valid and have sufficient quota
- [ ] `SERVICE_API_KEY` is strong (not "test-api-key")
- [ ] Rate limits are appropriate for expected traffic
- [ ] Health check endpoint is accessible
- [ ] `/docs` endpoint is accessible (or restricted if needed)
- [ ] HTTPS is enabled (automatic on HF Spaces)
- [ ] Monitoring is set up
- [ ] Backups of configuration are stored securely
- [ ] Error tracking is configured (e.g., Sentry)
- [ ] Documentation is up to date

---

## Support & Resources

- **Documentation**: https://github.com/vn6295337/LLM-secure-gateway/tree/main/docs
- **Live Demo**: https://vn6295337-secure-llm-api.hf.space
- **API Docs**: https://vn6295337-secure-llm-api.hf.space/docs
- **Issues**: https://github.com/vn6295337/LLM-secure-gateway/issues

---

## Related Documents

- [Architecture](architecture.md) - System design
- [Implementation](implementation.md) - How it was built
- [API Testing Guide](api_testing_guide.md) - Testing examples
- [Deployment Results](deployment_test_results.md) - Validation report
