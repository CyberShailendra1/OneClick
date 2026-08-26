FROM python:3.12-slim

WORKDIR /app

# System deps: androguard/reportlab need some native libs; aapt is optional (for dynamic analysis package-name lookup)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Dynamic-analysis-only deps (frida) are optional; skip them in the container
# since a containerized deployment won't have an Android emulator attached.
RUN grep -v -E "^(frida|frida-tools)" requirements.txt > requirements.docker.txt \
    && pip install --no-cache-dir -r requirements.docker.txt

COPY . .

# Train the demo model at build time if it isn't already present
RUN python models/train_model.py

EXPOSE 8501
EXPOSE 8000

# Default: launch the Streamlit dashboard.
# To run the FastAPI backend instead: docker run <image> uvicorn api:app --host 0.0.0.0 --port 8000
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
