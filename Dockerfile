FROM python:3.12-slim

WORKDIR /app

# System deps: androguard/reportlab need native libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train the demo model at build time if it isn't already present
RUN python models/train_model.py

EXPOSE 8000

# Default: launch FastAPI (which serves both the REST API and the React Web UI at http://0.0.0.0:8000)
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
