FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for WHOIS, DNS, Pillow/numpy, and OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    tesseract-ocr \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy all application files (models, modules, data files) in one step
# instead of listing each one — prevents new files from being silently
# excluded from the deployed image
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]