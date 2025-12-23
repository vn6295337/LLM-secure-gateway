# Configuration

> **Primary Responsibility:** All environment variables and configuration settings

Environment variables for the Enterprise AI Gateway.

## Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SERVICE_API_KEY` | Gateway authentication key | `secure-abc123xyz` |
| `GEMINI_API_KEY` | Google Gemini API key | `your_gemini_key` |

## Optional Variables

### LLM Providers (Fallback)

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key for fallback | None |
| `OPENROUTER_API_KEY` | OpenRouter API key for fallback | None |
| `GEMINI_MODEL` | Gemini model to use | `gemini-2.5-flash` |
| `GROQ_MODEL` | Groq model to use | `llama-3.3-70b-versatile` |
| `OPENROUTER_MODEL` | OpenRouter model | `google/gemini-2.0-flash-exp:free` |

### Safety & Security

| Variable | Description | Default |
|----------|-------------|---------|
| `LAKERA_API_KEY` | Lakera Guard API key (safety fallback) | None |
| `TOXICITY_THRESHOLD` | Safety block threshold (0-1) | `0.7` |
| `RATE_LIMIT` | Server rate limit | `10/minute` |
| `ENABLE_PROMPT_INJECTION_CHECK` | Enable injection detection | `true` |

### Server

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8000` |
| `ALLOWED_ORIGINS` | CORS origins (comma-separated) | `*` |

## Example .env File

```bash
# Required
SERVICE_API_KEY=secure-YourSecretKey123
GEMINI_API_KEY=your_gemini_api_key

# Optional - Fallback LLMs
GROQ_API_KEY=gsk_your_groq_key
OPENROUTER_API_KEY=sk-or-your_openrouter_key

# Optional - Safety
LAKERA_API_KEY=your_lakera_api_key
TOXICITY_THRESHOLD=0.7

# Optional - Server
RATE_LIMIT=10/minute
ALLOWED_ORIGINS=https://yourdomain.com
```

## HuggingFace Spaces Secrets

Add these in your Space settings under "Repository secrets":

1. `SERVICE_API_KEY` (required)
2. `GEMINI_API_KEY` (required)
3. `LAKERA_API_KEY` (optional - safety fallback)
4. `GROQ_API_KEY` (optional - LLM fallback)
5. `OPENROUTER_API_KEY` (optional - LLM fallback)

## Provider Priority

The LLM cascade tries providers in this order:
1. **Gemini** (if `GEMINI_API_KEY` set)
2. **Groq** (if `GROQ_API_KEY` set)
3. **OpenRouter** (if `OPENROUTER_API_KEY` set)

## Safety Priority

Content safety checks use this order:
1. **Gemini Classification** (primary) - Uses `GEMINI_API_KEY`
2. **Lakera Guard** (fallback on Gemini failure) - Uses `LAKERA_API_KEY`

## Docker

```bash
docker run -d \
  -e SERVICE_API_KEY=your_key \
  -e GEMINI_API_KEY=your_gemini_key \
  -e LAKERA_API_KEY=your_lakera_key \
  -p 8000:8000 \
  llm-secure-gateway
```
