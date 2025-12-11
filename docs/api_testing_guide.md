# API Testing Guide - LLM Secure Gateway

**Service URL**: https://vn6295337-secure-llm-api.hf.space
**API Documentation**: https://vn6295337-secure-llm-api.hf.space/docs
**Repository**: https://github.com/vn6295337/LLM-secure-gateway

---

## Authentication

All `/query` requests require the `X-API-Key` header with a valid API key.

**Test API Key** (for demo purposes):
```
X-API-Key: secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE
```

---

## Quick Test Examples

### 1. Health Check (No Auth Required)

```bash
curl https://vn6295337-secure-llm-api.hf.space/health
```

**Expected Response**:
```json
{
  "status": "healthy",
  "provider": "gemini",
  "model": "gemini-2.0-flash-exp",
  "timestamp": 1765193753.2943742
}
```

**Response Time**: < 100ms

---

### 2. Successful LLM Query

```bash
curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE" \
  -d '{
    "prompt": "Explain quantum computing in one sentence",
    "max_tokens": 256,
    "temperature": 0.7
  }'
```

**Expected Response**:
```json
{
  "response": "Quantum computing harnesses quantum mechanics principles...",
  "provider": "groq",
  "latency_ms": 87,
  "status": "success",
  "error": null
}
```

**Response Time**: 87-200ms (varies by provider)

---

## Security Testing Examples

### 3. Missing API Key (401 Error)

```bash
curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "test",
    "max_tokens": 50
  }'
```

**Expected Response**:
```json
{
  "detail": "Invalid or missing API key"
}
```

**HTTP Status**: 401 Unauthorized

---

### 4. Invalid API Key (401 Error)

```bash
curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: wrong-key-12345" \
  -d '{
    "prompt": "test",
    "max_tokens": 50
  }'
```

**Expected Response**:
```json
{
  "detail": "Invalid or missing API key"
}
```

**HTTP Status**: 401 Unauthorized

---

## Input Validation Testing

### 5. Empty Prompt (422 Validation Error)

```bash
curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE" \
  -d '{
    "prompt": "",
    "max_tokens": 50
  }'
```

**Expected Response**:
```json
{
  "detail": [
    {
      "type": "string_too_short",
      "loc": ["body", "prompt"],
      "msg": "String should have at least 1 character",
      "input": "",
      "ctx": {"min_length": 1}
    }
  ]
}
```

**Validation**: Prompt must be 1-4000 characters

---

### 6. Max Tokens Too Large (422 Validation Error)

```bash
curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE" \
  -d '{
    "prompt": "test",
    "max_tokens": 5000
  }'
```

**Expected Response**:
```json
{
  "detail": [
    {
      "type": "less_than_equal",
      "loc": ["body", "max_tokens"],
      "msg": "Input should be less than or equal to 2048",
      "input": 5000,
      "ctx": {"le": 2048}
    }
  ]
}
```

**Validation**: max_tokens must be 1-2048

---

### 7. Temperature Out of Range (422 Validation Error)

```bash
curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE" \
  -d '{
    "prompt": "test",
    "max_tokens": 100,
    "temperature": 2.5
  }'
```

**Expected Response**:
```json
{
  "detail": [
    {
      "type": "less_than_equal",
      "loc": ["body", "temperature"],
      "msg": "Input should be less than or equal to 2",
      "input": 2.5,
      "ctx": {"le": 2.0}
    }
  ]
}
```

**Validation**: temperature must be 0.0-2.0

---

## Rate Limiting Testing

### 8. Test Rate Limiting (10 req/min)

**Note**: Rate limiting is IP-based. On HF Spaces, proxy architecture may affect results.

```bash
# Send 12 rapid requests
for i in {1..12}; do
  curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
    -H "Content-Type: application/json" \
    -H "X-API-Key: secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE" \
    -d '{"prompt": "Hi", "max_tokens": 10}' &
done
wait
```

**Expected Local Behavior**: 10 succeed, 2 fail with rate limit error
**HF Spaces Behavior**: All may succeed due to proxy IP distribution

**Rate Limit Error Response**:
```json
{
  "error": "Rate limit exceeded: 10 per 1 minute"
}
```

---

## Multi-Provider Fallback Testing

### 9. Verify Provider Cascade

The API uses multi-provider fallback in this order:
1. **Gemini** (gemini-2.0-flash-exp) - Primary
2. **Groq** (llama-3.3-70b-versatile) - Fallback 1
3. **OpenRouter** (google/gemini-2.0-flash-exp:free) - Fallback 2

**Test Command**:
```bash
curl -X POST https://vn6295337-secure-llm-api.hf.space/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE" \
  -d '{
    "prompt": "What is AI in one sentence?",
    "max_tokens": 50
  }' | jq '.provider'
```

**Expected**: Response will include the provider name (gemini, groq, or openrouter)

**Observation**: Groq is commonly used, indicating successful fallback from Gemini

---

## Performance Metrics

### Measured Performance

| Metric | Value | Status |
|--------|-------|--------|
| Health Check Latency | < 100ms | ✅ Excellent |
| Query Response Time | 87-200ms | ✅ Excellent |
| Cold Start Time | < 30s | ✅ Good |
| Build Time | ~2-3 min | ✅ Acceptable |

---

## OpenAPI Documentation

### 10. Access Interactive API Docs

**Swagger UI**: https://vn6295337-secure-llm-api.hf.space/docs
**ReDoc**: https://vn6295337-secure-llm-api.hf.space/redoc

Features:
- Interactive API testing
- Complete request/response schemas
- Authentication testing
- Example values

---

## Request Schema

```json
{
  "prompt": "string (1-4000 chars)",
  "max_tokens": "integer (1-2048)",
  "temperature": "float (0.0-2.0)"
}
```

**Defaults**:
- `max_tokens`: 256
- `temperature`: 0.7

---

## Response Schema

### Success Response
```json
{
  "response": "string | null",
  "provider": "string | null",
  "latency_ms": "integer",
  "status": "success",
  "error": "null"
}
```

### Error Response
```json
{
  "response": null,
  "provider": null,
  "latency_ms": 0,
  "status": "error",
  "error": "string"
}
```

---

## Python Example

```python
import requests

# Configuration
API_URL = "https://vn6295337-secure-llm-api.hf.space/query"
API_KEY = "secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE"

# Headers
headers = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY
}

# Request payload
payload = {
    "prompt": "Explain quantum computing in one sentence",
    "max_tokens": 256,
    "temperature": 0.7
}

# Make request
response = requests.post(API_URL, headers=headers, json=payload)
result = response.json()

# Print results
print(f"Status: {result['status']}")
print(f"Provider: {result['provider']}")
print(f"Latency: {result['latency_ms']}ms")
print(f"Response: {result['response']}")
```

---

## JavaScript/Node.js Example

```javascript
const axios = require('axios');

const API_URL = 'https://vn6295337-secure-llm-api.hf.space/query';
const API_KEY = 'secure-YDiNiwSV5k6A4lKu2EgKt2us-JzdMHEiOeM_rz76CvE';

const headers = {
  'Content-Type': 'application/json',
  'X-API-Key': API_KEY
};

const payload = {
  prompt: 'Explain quantum computing in one sentence',
  max_tokens: 256,
  temperature: 0.7
};

axios.post(API_URL, payload, { headers })
  .then(response => {
    const result = response.data;
    console.log(`Status: ${result.status}`);
    console.log(`Provider: ${result.provider}`);
    console.log(`Latency: ${result.latency_ms}ms`);
    console.log(`Response: ${result.response}`);
  })
  .catch(error => {
    console.error('Error:', error.response?.data || error.message);
  });
```

---

## Testing Checklist

- [x] Health check endpoint accessible
- [x] Successful query with valid API key
- [x] Authentication blocking (missing/invalid key)
- [x] Input validation (prompt, max_tokens, temperature)
- [x] Rate limiting (works locally, proxy-aware on HF)
- [x] Multi-provider fallback functional
- [x] OpenAPI documentation accessible
- [x] Performance within acceptable ranges

---

## Troubleshooting

### Issue: 401 Unauthorized
**Cause**: Missing or invalid API key
**Solution**: Include correct `X-API-Key` header

### Issue: 422 Validation Error
**Cause**: Invalid request parameters
**Solution**: Check constraints (prompt: 1-4000, max_tokens: 1-2048, temperature: 0-2)

### Issue: 500 Internal Server Error
**Cause**: All LLM providers failed
**Solution**: Check provider API keys and rate limits

### Issue: Slow Response
**Cause**: Cold start or provider latency
**Solution**: Wait for warm-up, or retry with different provider

---

## Security Notes

1. **API Key Protection**: Never commit API keys to version control
2. **Rate Limiting**: IP-based (10 req/min), may need adjustment for production
3. **HTTPS**: All traffic encrypted via HF Spaces
4. **Input Validation**: All parameters validated before processing
5. **Error Messages**: Generic errors to avoid information leakage

---

## Support

- **Issues**: https://github.com/vn6295337/LLM-secure-gateway/issues
- **Documentation**: https://github.com/vn6295337/LLM-secure-gateway
- **Live Demo**: https://vn6295337-secure-llm-api.hf.space
