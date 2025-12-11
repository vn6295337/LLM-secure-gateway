FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code from src directory
COPY src/ ./src/

# Make startup script executable
RUN chmod +x start-app.sh

# Expose HF Spaces default port
EXPOSE 7860

# Run startup script with main.py from src
CMD ["./start-app.sh"]